//go:build e2e

package e2e

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bisman-Singh/zeroreads/internal/app"
	"github.com/Bisman-Singh/zeroreads/internal/emit"
	"github.com/Bisman-Singh/zeroreads/internal/gen"
)

// runtimeCase is one pipeline runtime taken through the same loop as the Collector.
type runtimeCase struct {
	name, prefix       string
	userFile, cm, key  string // the user config, and the ConfigMap and key it is deployed through
	ds                 string
	validate           func(e *loopEnv, cfgPath string)
	section            string // the runtime's zeroreads.yaml section; %s is the user config path
	actions            string
	readRaw            func(e *loopEnv, ns string) []rawRecord
	keepDigits         int // hex digits of the SHA-256 compared with the sample threshold
	threshold          func(keep int) int64
	metrics            func(e *loopEnv) map[string]float64 // "lines|id", "bytes|id"
	hasBytes, hasDedup bool
	outputs            []string // local files this runtime writes, cleared before each deploy
}

func (rc runtimeCase) keep(text string, ts int64, keep int) bool {
	sum := sha256.Sum256([]byte(text + "|" + strconv.FormatInt(ts, 10)))
	v, _ := strconv.ParseInt(hex.EncodeToString(sum[:])[:rc.keepDigits], 16, 64)
	return v < rc.threshold(keep)
}

func (rc runtimeCase) deploy(e *loopEnv, cfgPath string) {
	e.t.Helper()
	rc.validate(e, cfgPath)
	for _, f := range rc.outputs {
		os.Remove(filepath.Join(e.work, "out", f))
	}
	cm := e.kubectl("create", "configmap", rc.cm, "-n", "zeroreads-system", "--from-file="+rc.key+"="+cfgPath, "--dry-run=client", "-o", "yaml")
	f := filepath.Join(e.t.TempDir(), "cm.yaml")
	os.WriteFile(f, []byte(cm), 0o644)
	e.kubectl("apply", "-f", f)
	e.kubectl("rollout", "restart", "daemonset/"+rc.ds, "-n", "zeroreads-system")
	e.kubectl("rollout", "status", "daemonset/"+rc.ds, "-n", "zeroreads-system", "--timeout=180s")
	time.Sleep(5 * time.Second) // let it start tailing before generators run
}

func jsonLines(t *testing.T, path string, fn func(map[string]any)) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 16<<20), 16<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		fn(m)
	}
}

func msgOf(service, message string) (string, bool) {
	if service != "orders" {
		return message, false
	}
	var m map[string]any
	if json.Unmarshal([]byte(message), &m) != nil {
		return message, false
	}
	s, _ := m["msg"].(string)
	return s, true
}

var vectorCase = runtimeCase{
	name: "vector", prefix: "zeroreads-vloop", userFile: "vector.yaml", cm: "vector-config", key: "vector.yaml", ds: "vector",
	validate: func(e *loopEnv, cfgPath string) {
		dir := e.t.TempDir()
		b, _ := os.ReadFile(cfgPath)
		os.WriteFile(filepath.Join(dir, "v.yaml"), b, 0o644)
		if out, code := e.run(e.root, "docker", "run", "--rm", "-v", dir+":/w", "timberio/vector:0.58.0-debian", "validate", "--no-environment", "/w/v.yaml"); code != 0 {
			e.t.Fatalf("vector rejects %s: %s", cfgPath, out)
		}
	},
	section: `runtime: vector
vector:
  config_files: [%s]
  after: prep
  scope_path: .service
  text_path: .message
  field_paths: {orders: .body.msg}
  dedupe_group_by: [ns]
  dedupe_ms: 3000
  measure_sink: {type: file, path: /e2e/out/vloop-metrics.json, encoding: {codec: json}}
  sinks:
    loki: {loki: true}
    logs: {exempt: "e2e local copy"}
`,
	actions: "[dedupe, sample]",
	readRaw: func(e *loopEnv, ns string) []rawRecord {
		var out []rawRecord
		jsonLines(e.t, filepath.Join(e.work, "out", "vloop-raw.json"), func(m map[string]any) {
			if m["ns"] != ns {
				return
			}
			ts, err := time.Parse(time.RFC3339Nano, m["timestamp"].(string))
			if err != nil {
				e.t.Fatal(err)
			}
			text, structured := msgOf(m["service"].(string), m["message"].(string))
			out = append(out, rawRecord{service: m["service"].(string), text: text, structured: structured, ts: ts.UnixNano()})
		})
		return out
	},
	keepDigits: 15, threshold: emit.VectorSampleThreshold,
	metrics: func(e *loopEnv) map[string]float64 {
		out := map[string]float64{}
		jsonLines(e.t, filepath.Join(e.work, "out", "vloop-metrics.json"), func(m map[string]any) {
			tags, _ := m["tags"].(map[string]any)
			c, _ := m["counter"].(map[string]any)
			v, _ := c["value"].(float64)
			switch m["name"] {
			case "zeroreads_rule_lines":
				out["lines|"+tags["rule"].(string)] += v
			case "zeroreads_rule_bytes":
				out["bytes|"+tags["rule"].(string)] += v
			}
		})
		return out
	},
	hasBytes: true, hasDedup: true,
	outputs: []string{"vloop-raw.json", "vloop-logs.json", "vloop-metrics.json"},
}

var fluentBitCase = runtimeCase{
	name: "fluentbit", prefix: "zeroreads-fbloop", userFile: "fluent-bit.yaml", cm: "fluent-bit-config", key: "fluent-bit.yaml", ds: "fluent-bit",
	validate: func(e *loopEnv, cfgPath string) {
		dir := e.t.TempDir()
		b, _ := os.ReadFile(cfgPath)
		os.WriteFile(filepath.Join(dir, "f.yaml"), b, 0o644)
		if out, code := e.run(e.root, "docker", "run", "--rm", "-v", dir+":/w", "fluent/fluent-bit:5.1.2", "--dry-run", "-c", "/w/f.yaml"); code != 0 {
			e.t.Fatalf("fluent bit rejects %s: %s", cfgPath, out)
		}
	},
	section: `runtime: fluentbit
fluentbit:
  config_files: [%s]
  match: kube.*
  after: prep
  scope_key: service
  text_key: [message]
  field_keys: {orders: [msg]}
  metrics_tag: zeroreads.metrics
  sinks:
    loki: {loki: true}
    logs: {exempt: "e2e local copy"}
`,
	actions: "[sample]",
	readRaw: func(e *loopEnv, ns string) []rawRecord {
		var out []rawRecord
		jsonLines(e.t, filepath.Join(e.work, "out", "fbloop-raw.json"), func(m map[string]any) {
			if m["ns"] != ns {
				return
			}
			ts, _ := strconv.ParseInt(m["tsn"].(string), 10, 64)
			text, structured := msgOf(m["service"].(string), m["message"].(string))
			out = append(out, rawRecord{service: m["service"].(string), text: text, structured: structured, ts: ts})
		})
		return out
	},
	keepDigits: 13, threshold: emit.FluentBitSampleThreshold,
	metrics: func(e *loopEnv) map[string]float64 {
		out := map[string]float64{}
		logs := e.kubectl("logs", "daemonset/fluent-bit", "-n", "zeroreads-system")
		re := regexp.MustCompile(`log_metric_counter_zeroreads_rule_lines_([a-z0-9_]+)\S* = (\d+)`)
		for _, m := range re.FindAllStringSubmatch(logs, -1) {
			v, _ := strconv.ParseFloat(m[2], 64)
			out["lines|"+m[1]] = v // cumulative since the last restart: the last value wins
		}
		return out
	},
	outputs: []string{"fbloop-raw.json", "fbloop-logs.json"},
}

// TestRuntimeLoops takes Vector and Fluent Bit through analyse, shadow, enforce, reconcile and verify
// in the cluster, exactly as the Collector loop does, against the same Loki and ground truth.
func TestRuntimeLoops(t *testing.T) {
	for _, rc := range []runtimeCase{vectorCase, fluentBitCase} {
		t.Run(rc.name, func(t *testing.T) { runtimeLoop(t, rc) })
	}
}

func runtimeLoop(t *testing.T, rc runtimeCase) {
	e := &loopEnv{t: t, work: env(t, "E2E_WORK"), loki: env(t, "LOKI_URL"), prefix: rc.prefix}
	e.root, _ = filepath.Abs("..")
	e.kube = filepath.Join(e.work, "kubeconfig")
	grafanaURL := env(t, "GRAFANA_URL")
	os.Setenv("E2E_GRAFANA_PASSWORD", grafanaPass)
	e.bin = filepath.Join(e.work, "zeroreads")
	if out, code := e.run(e.root, "go", "build", "-o", e.bin, "./cmd/zeroreads"); code != 0 {
		t.Fatal(out)
	}
	src, _ := os.ReadFile(filepath.Join(e.root, "e2e", "runtimes", rc.userFile))
	userPath := filepath.Join(e.work, rc.name+"-user.yaml")
	os.WriteFile(userPath, src, 0o644)
	rc.deploy(e, userPath)
	pre := e.batch("pre", 41, 2000)
	e.nsLines(pre, 6000)

	cfgPath := filepath.Join(e.work, "zeroreads-"+rc.name+".yaml")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(`loki:
  url: %s
scope:
  services: [checkout, auth, orders]
  structured: {orders: msg}
discovery:
  window: 1h
  slices: 12
  sample_lines_per_service: 6000
drain:
  masking_rules:
    - {name: %s, pattern: '%s'}
evidence:
  window: 1h
  query_log: {enabled: true, selector: '{service_name="loki"}', prove_live: true}
  ruler: true
  grafana:
    - {url: %s, username: admin, password_env: E2E_GRAFANA_PASSWORD, datasources: [loki, loki2]}
`+rc.section+`policy:
  actions: %s
  sample_percent: 30
  acknowledge: ["%s", querylog-window]
`, e.loki, gen.IPMaskName, gen.IPMaskPattern, grafanaURL, userPath, rc.actions, grafanaGap("queryhistory", grafanaURL))), 0o644)

	// 1. Analyze.
	outDir := filepath.Join(e.work, rc.name+"-out")
	out, code := e.run(e.root, e.bin, "analyze", "-c", cfgPath, "-o", outDir)
	if code != 0 {
		t.Fatal(out)
	}
	rulesPath := filepath.Join(outDir, "rules.json")
	rf, err := app.LoadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(rf.Rules) == 0 {
		md, _ := os.ReadFile(filepath.Join(outDir, "report.md"))
		t.Fatalf("no acting rule:\n%s", md)
	}
	langs := map[string]*regexp.Regexp{}
	for _, r := range rf.Rules {
		langs[r.ID] = regexp.MustCompile(r.Language)
	}
	ruleFor := func(r rawRecord) *app.EnforcedRule {
		for i := range rf.Rules {
			x := &rf.Rules[i]
			if x.Service == r.service && (x.Field != "") == r.structured && langs[x.ID].MatchString(r.text) {
				return x
			}
		}
		return nil
	}
	t.Logf("analyze: %s", strings.TrimSpace(out))

	// 2. Shadow: every line still reaches Loki; per-rule measurement equals ground truth.
	shadowPath := filepath.Join(e.work, rc.name+"-shadow.yaml")
	if out, code := e.run(e.root, e.bin, "emit", "-c", cfgPath, "-rules", rulesPath, "-format", rc.name, "-mode", "shadow", "-o", shadowPath); code != 0 {
		t.Fatal(out)
	}
	rc.deploy(e, shadowPath)
	const count = 2000
	winA0 := time.Now().Add(-time.Second)
	nsA := e.batch("shadow", 42, count)
	linesA := e.nsLines(nsA, 3*count)
	winA1 := time.Now()
	rawA := waitRaw(e, rc, nsA, 3*count)
	if len(linesA) != 3*count {
		t.Fatalf("shadow: Loki has %d lines, want %d", len(linesA), 3*count)
	}
	// Shadow changes nothing: Loki holds exactly the raw records, content and timestamp.
	type line struct {
		svc, text string
		ts        int64
	}
	stored := map[line]int{}
	for _, l := range linesA {
		text, _ := msgOf(l.Labels["service_name"], l.Line)
		stored[line{l.Labels["service_name"], text, l.TS.UnixNano()}]++
	}
	for _, r := range rawA {
		k := line{r.service, r.text, r.ts}
		if stored[k] == 0 {
			t.Fatalf("shadow: raw record not stored as it was: %+v", k)
		}
		stored[k]--
	}
	wantLines, wantBytes := map[string]float64{}, map[string]float64{}
	for _, r := range rawA {
		if x := ruleFor(r); x != nil {
			wantLines[x.ID]++
			wantBytes[x.ID] += float64(len(r.text))
		}
	}
	var got map[string]float64
	for i := 0; i < 20; i++ { // metrics flush on their own interval
		got = rc.metrics(e)
		ok := true
		for _, r := range rf.Rules {
			if got["lines|"+metricID(rc, r.ID)] != wantLines[r.ID] {
				ok = false
			}
		}
		if ok {
			break
		}
		time.Sleep(2 * time.Second)
	}
	for _, r := range rf.Rules {
		if got["lines|"+metricID(rc, r.ID)] != wantLines[r.ID] || wantLines[r.ID] == 0 || (rc.hasBytes && got["bytes|"+r.ID] != wantBytes[r.ID]) {
			t.Fatalf("shadow %s: measured %v lines / %v bytes, ground truth %v / %v", r.ID, got["lines|"+metricID(rc, r.ID)], got["bytes|"+r.ID], wantLines[r.ID], wantBytes[r.ID])
		}
	}
	t.Logf("shadow: %d lines all delivered; per-rule measurement equals ground truth %v", len(linesA), wantLines)

	// 3. Enforce.
	enforcePath := filepath.Join(e.work, rc.name+"-enforce.yaml")
	if out, code := e.run(e.root, e.bin, "emit", "-c", cfgPath, "-rules", rulesPath, "-format", rc.name, "-mode", "enforce", "-o", enforcePath); code != 0 {
		t.Fatal(out)
	}
	rc.deploy(e, enforcePath)
	winB0 := time.Now().Add(-time.Second)
	nsB := e.batch("enforce", 43, count)
	rawB := waitRaw(e, rc, nsB, 3*count)
	type key struct {
		svc, text string
		ts        int64
	}
	expect := map[key]bool{}
	dedupeLines, kept := map[string]int{}, map[string]int{}
	for _, r := range rawB {
		x := ruleFor(r)
		switch {
		case x == nil:
			expect[key{r.service, r.text, r.ts}] = true
		case x.Action == "sample":
			if rc.keep(r.text, r.ts, x.Keep) {
				expect[key{r.service, r.text, r.ts}] = true
				kept[x.ID]++
			}
		case x.Action == "dedupe":
			dedupeLines[x.ID]++
		default:
			t.Fatalf("unexpected action %s", x.Action)
		}
	}
	time.Sleep(8 * time.Second) // dedupe windows expire every 3s
	linesB := e.nsLines(nsB, len(expect))
	gotSet := map[key]bool{}
	dedupeRecords := 0
	for _, l := range linesB {
		svc := l.Labels["service_name"]
		text, structured := msgOf(svc, l.Line)
		if x := ruleFor(rawRecord{service: svc, text: text, structured: structured}); x != nil && x.Action == "dedupe" {
			dedupeRecords++
			continue
		}
		gotSet[key{svc, text, l.TS.UnixNano()}] = true
	}
	for k := range expect {
		if !gotSet[k] {
			t.Fatalf("enforce: expected line missing from Loki: %+v", k)
		}
	}
	for k := range gotSet {
		if !expect[k] {
			t.Fatalf("enforce: line should have been removed but reached Loki: %+v", k)
		}
	}
	if rc.hasDedup {
		counts := map[string]int{}
		jsonLines(t, filepath.Join(e.work, "out", "vloop-logs.json"), func(m map[string]any) {
			if m["ns"] != nsB {
				return
			}
			text, structured := msgOf(m["service"].(string), m["message"].(string))
			if x := ruleFor(rawRecord{service: m["service"].(string), text: text, structured: structured}); x != nil && x.Action == "dedupe" {
				c, _ := m["zeroreads_count"].(float64)
				counts[x.ID] += int(c)
			}
		})
		total := 0
		for id, n := range dedupeLines {
			total += n
			if counts[id] != n {
				t.Fatalf("dedupe %s: counts add up to %d, %d lines seen", id, counts[id], n)
			}
		}
		if total > 0 && (dedupeRecords == 0 || dedupeRecords >= total) {
			t.Fatalf("dedupe: %d records stored for %d lines", dedupeRecords, total)
		}
	}
	winB1 := time.Now()
	t.Logf("enforce: %d lines reached Loki exactly as predicted; sampled kept %v; deduplicated %v", len(gotSet), kept, dedupeLines)

	// 4. Reconcile from Loki's own data, and verify against the deployed config.
	w := func(a, b time.Time) string {
		return a.UTC().Format(time.RFC3339Nano) + "," + b.UTC().Format(time.RFC3339Nano)
	}
	recPath := filepath.Join(e.work, rc.name+"-reconcile.json")
	out, code = e.run(e.root, e.bin, "reconcile", "-c", cfgPath, "-rules", rulesPath, "-before", w(winA0, winA1), "-after", w(winB0, winB1), "-tolerance", "1", "-o", recPath)
	if code != 0 {
		t.Fatalf("reconcile (exit %d): %s", code, out)
	}
	var rec app.Reconciliation
	rb, _ := os.ReadFile(recPath)
	json.Unmarshal(rb, &rec)
	for _, r := range rec.Rules {
		if int(r.BeforeLines) != int(wantLines[r.RuleID]) {
			t.Fatalf("reconcile %s: before %v, ground truth %v", r.RuleID, r.BeforeLines, wantLines[r.RuleID])
		}
		if r.Action == "sample" && int(r.AfterLines) != kept[r.RuleID] {
			t.Fatalf("reconcile %s: after %v, kept %d", r.RuleID, r.AfterLines, kept[r.RuleID])
		}
	}
	out, code = e.run(e.root, e.bin, "verify", "-c", cfgPath, "-rules", rulesPath, "-deployed", enforcePath)
	if code != 0 {
		t.Fatalf("verify (exit %d): %s", code, out)
	}
	t.Logf("reconcile matches the ground truth; verify passes against the deployed %s config", rc.name)
}

// metricID is how a runtime spells a rule ID inside a metric name.
func metricID(rc runtimeCase, id string) string {
	if rc.name == "fluentbit" {
		return strings.ReplaceAll(id, "-", "_")
	}
	return id
}

// waitRaw waits until the runtime's raw copy holds want records of a namespace.
func waitRaw(e *loopEnv, rc runtimeCase, ns string, want int) []rawRecord {
	e.t.Helper()
	var got []rawRecord
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		if _, err := os.Stat(filepath.Join(e.work, "out", rc.outputs[0])); err == nil {
			if got = rc.readRaw(e, ns); len(got) >= want {
				return got
			}
		}
	}
	e.t.Fatalf("%s raw copy of %s has %d records, want %d", rc.name, ns, len(got), want)
	return nil
}
