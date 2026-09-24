//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/Bisman-Singh/sievelog/internal/app"
	"github.com/Bisman-Singh/sievelog/internal/emit"
	"github.com/Bisman-Singh/sievelog/internal/gen"
	"github.com/Bisman-Singh/sievelog/internal/source/loki"
)

type loopEnv struct {
	t    *testing.T
	work string // .e2e on the host, mounted at /e2e in the node
	root string
	kube string
	loki string
	bin  string
}

func (e *loopEnv) run(dir, name string, args ...string) (string, int) {
	e.t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out), code
}

func (e *loopEnv) kubectl(args ...string) string {
	e.t.Helper()
	full := append([]string{"--kubeconfig", e.kube, "--context", "kind-sievelog"}, args...)
	out, code := e.run(e.root, "kubectl", full...)
	if code != 0 {
		e.t.Fatalf("kubectl %v: %s", args, out)
	}
	return out
}

// deployCollector replaces the collector's config and waits for the new pod.
func (e *loopEnv) deployCollector(cfgPath string) {
	e.t.Helper()
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		e.t.Fatal(err)
	}
	valDir := e.t.TempDir()
	if err := os.WriteFile(filepath.Join(valDir, "c.yaml"), b, 0o644); err != nil {
		e.t.Fatal(err)
	}
	if out, code := e.run(e.root, "docker", "run", "--rm", "-v", valDir+":/cfg", "otel/opentelemetry-collector-contrib:0.161.0", "validate", "--config=/cfg/c.yaml"); code != 0 {
		e.t.Fatalf("collector rejects %s: %s", cfgPath, out)
	}
	cm := e.kubectl("create", "configmap", "collector-config", "-n", "sievelog-system", "--from-file=config.yaml="+cfgPath, "--dry-run=client", "-o", "yaml")
	f := filepath.Join(e.t.TempDir(), "cm.yaml")
	os.WriteFile(f, []byte(cm), 0o644)
	e.kubectl("apply", "-f", f)
	e.kubectl("rollout", "restart", "daemonset/collector", "-n", "sievelog-system")
	e.kubectl("rollout", "status", "daemonset/collector", "-n", "sievelog-system", "--timeout=180s")
	time.Sleep(3 * time.Second) // let the new collector start tailing before generators run
}

// batch runs the ground-truth generators in a fresh loop namespace and returns the namespace.
func (e *loopEnv) batch(name string, seed uint64, count int) string {
	e.t.Helper()
	ns := fmt.Sprintf("sievelog-loop-%d-%s", time.Now().Unix(), name)
	e.kubectl("create", "namespace", ns)
	for _, s := range []string{"checkout", "auth", "orders"} {
		job := fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata: {name: gen-%s, namespace: %s}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: %s
          image: sievelog/loggen:e2e
          imagePullPolicy: Never
          args: ["--service=%s", "--seed=%d", "--count=%d", "--rate=2000"]
`, s, ns, s, s, seed, count)
		f := filepath.Join(e.t.TempDir(), "job.yaml")
		os.WriteFile(f, []byte(job), 0o644)
		e.kubectl("apply", "-f", f)
	}
	for _, s := range []string{"checkout", "auth", "orders"} {
		e.kubectl("wait", "--for=condition=complete", "job/gen-"+s, "-n", ns, "--timeout=120s")
	}
	return ns
}

// nsLines reads every line Loki holds for a loop namespace, waiting until the count is stable.
func (e *loopEnv) nsLines(ns string, atLeast int) []loki.Entry {
	e.t.Helper()
	c := &loki.Client{Base: e.loki}
	q := `{service_name=~"checkout|auth|orders", k8s_namespace_name="` + ns + `"}`
	var last []loki.Entry
	stable := 0
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); {
		got, err := c.QueryRange(context.Background(), q, time.Now().Add(-time.Hour), time.Now().Add(time.Minute), 5000)
		if err != nil {
			e.t.Fatal(err)
		}
		if len(got) >= atLeast && len(got) == len(last) {
			stable++
			if stable >= 3 {
				return got
			}
		} else {
			stable = 0
		}
		last = got
		time.Sleep(3 * time.Second)
	}
	e.t.Fatalf("namespace %s: Loki has %d lines, expected at least %d", ns, len(last), atLeast)
	return nil
}

// rawRecord is one record from the independent raw pipeline.
type rawRecord struct {
	service, text string
	ts            int64
	structured    bool
}

func (e *loopEnv) readRaw(ns string) []rawRecord {
	e.t.Helper()
	f, err := os.Open(filepath.Join(e.work, "out", "loop-raw.json"))
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	var out []rawRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<20), 64<<20)
	var u plog.JSONUnmarshaler
	for sc.Scan() {
		ld, err := u.UnmarshalLogs(sc.Bytes())
		if err != nil {
			e.t.Fatal(err)
		}
		for i := 0; i < ld.ResourceLogs().Len(); i++ {
			rl := ld.ResourceLogs().At(i)
			nsv, _ := rl.Resource().Attributes().Get("k8s.namespace.name")
			if nsv.Str() != ns {
				continue
			}
			svc, _ := rl.Resource().Attributes().Get("service.name")
			sls := rl.ScopeLogs()
			for j := 0; j < sls.Len(); j++ {
				lrs := sls.At(j).LogRecords()
				for k := 0; k < lrs.Len(); k++ {
					lr := lrs.At(k)
					r := rawRecord{service: svc.Str(), ts: int64(lr.Timestamp())}
					if lr.Body().Type() == pcommon.ValueTypeMap {
						v, _ := lr.Body().Map().Get("msg")
						r.text, r.structured = v.Str(), true
					} else {
						r.text = lr.Body().Str()
					}
					out = append(out, r)
				}
			}
		}
	}
	return out
}

// ruleMetrics sums the per-rule measurement metrics exported to loop-metrics.json.
func (e *loopEnv) ruleMetrics() map[string]float64 {
	e.t.Helper()
	out := map[string]float64{}
	f, err := os.Open(filepath.Join(e.work, "out", "loop-metrics.json"))
	if os.IsNotExist(err) {
		return out
	}
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<20), 64<<20)
	var u pmetric.JSONUnmarshaler
	for sc.Scan() {
		md, err := u.UnmarshalMetrics(sc.Bytes())
		if err != nil {
			e.t.Fatal(err)
		}
		for i := 0; i < md.ResourceMetrics().Len(); i++ {
			sms := md.ResourceMetrics().At(i).ScopeMetrics()
			for j := 0; j < sms.Len(); j++ {
				ms := sms.At(j).Metrics()
				for k := 0; k < ms.Len(); k++ {
					dps := ms.At(k).Sum().DataPoints()
					for d := 0; d < dps.Len(); d++ {
						v := float64(dps.At(d).IntValue())
						if dps.At(d).ValueType() == pmetric.NumberDataPointValueTypeDouble {
							v = dps.At(d).DoubleValue()
						}
						out[ms.At(k).Name()] += v
					}
				}
			}
		}
	}
	return out
}

func (e *loopEnv) resetOutputs() {
	for _, f := range []string{"loop-raw.json", "loop-logs.json", "loop-metrics.json"} {
		os.Remove(filepath.Join(e.work, "out", f))
	}
}

// installChart installs charts/sievelog in the cluster with the in-cluster addresses of the stack, and
// returns a function that runs the verify CronJob once and reports its exit code and logs.
func (e *loopEnv) installChart(rulesPath, collectorPath, grafanaURL string) func(string) (int, string) {
	e.t.Helper()
	rules, _ := os.ReadFile(rulesPath)
	collector, _ := os.ReadFile(collectorPath)
	cfg := fmt.Sprintf(`loki:
  url: http://loki.sievelog-system.svc:3100
scope:
  services: [checkout, auth, orders]
  structured: {orders: msg}
drain:
  masking_rules:
    - {name: %s, pattern: '%s'}
evidence:
  window: 5m
  query_log: {enabled: true, selector: '{service_name="loki"}', prove_live: true}
  ruler: true
  grafana:
    - {url: http://grafana.sievelog-system.svc:3000, username: admin, password_env: GRAFANA_PASSWORD, datasources: [loki]}
collector:
  config_files: [/etc/sievelog/collector.yaml]
  pipeline: logs
  after: transform/prep
  measure_exporters: [file/metrics]
  sinks:
    otlp_http/loki: {loki: true}
    file/logs: {exempt: "e2e local copy"}
policy:
  acknowledge: [grafana-queryhistory, querylog-window]
`, gen.IPMaskName, gen.IPMaskPattern)
	values := map[string]any{
		"image":  map[string]any{"repository": "sievelog/sievelog", "tag": "e2e", "pullPolicy": "Never"},
		"config": cfg, "rules": string(rules), "files": map[string]any{"collector.yaml": string(collector)},
		"env": []any{map[string]any{"name": "GRAFANA_PASSWORD", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "sievelog-grafana", "key": "password"}}}},
	}
	vb, _ := json.Marshal(values)
	vf := filepath.Join(e.t.TempDir(), "values.json")
	os.WriteFile(vf, vb, 0o644)
	sec := e.kubectl("create", "secret", "generic", "sievelog-grafana", "-n", "sievelog-system", "--from-literal=password="+grafanaPass, "--dry-run=client", "-o", "yaml")
	sf := filepath.Join(e.t.TempDir(), "secret.yaml")
	os.WriteFile(sf, []byte(sec), 0o644)
	e.kubectl("apply", "-f", sf)
	if out, code := e.run(e.root, "helm", "upgrade", "--install", "sievelog", "./charts/sievelog", "-n", "sievelog-system",
		"--kubeconfig", e.kube, "--kube-context", "kind-sievelog", "-f", vf, "--wait"); code != 0 {
		e.t.Fatalf("helm install: %s", out)
	}
	return func(name string) (int, string) {
		job := "verify-" + name + "-" + strconv.FormatInt(time.Now().Unix(), 10)
		e.kubectl("create", "job", "--from=cronjob/sievelog-verify", job, "-n", "sievelog-system")
		for deadline := time.Now().Add(4 * time.Minute); time.Now().Before(deadline); time.Sleep(3 * time.Second) {
			st := e.kubectl("get", "job", job, "-n", "sievelog-system", "-o", "jsonpath={.status.succeeded}/{.status.failed}")
			if st == "1/" || strings.HasSuffix(st, "/1") {
				logs := e.kubectl("logs", "job/"+job, "-n", "sievelog-system")
				code := 0
				if strings.HasSuffix(st, "/1") {
					term := e.kubectl("get", "pods", "-n", "sievelog-system", "-l", "job-name="+job, "-o", "jsonpath={.items[0].status.containerStatuses[0].state.terminated.exitCode}")
					code, _ = strconv.Atoi(strings.TrimSpace(term))
				}
				return code, logs
			}
		}
		e.t.Fatalf("job %s did not finish", job)
		return 0, ""
	}
}

func sampleKeep(text string, ts int64, keep int) bool {
	sum := sha256.Sum256([]byte(text + "|" + strconv.FormatInt(ts, 10)))
	return hex.EncodeToString(sum[:]) < emit.SampleThreshold(keep)
}

func TestFullLoop(t *testing.T) {
	e := &loopEnv{t: t, work: env(t, "E2E_WORK"), loki: env(t, "LOKI_URL")}
	e.root, _ = filepath.Abs("..")
	e.kube = filepath.Join(e.work, "kubeconfig")
	grafanaURL := env(t, "GRAFANA_URL")
	setupGrafanaFixtures(t, grafanaURL)

	// The "user" collector config, and the analyzer's config for this environment.
	userCfg, code := e.run(filepath.Join(e.root, "e2e"), "go", "run", "./render", "--loop")
	if code != 0 {
		t.Fatal(userCfg)
	}
	userPath := filepath.Join(e.work, "loop-user.yaml")
	os.WriteFile(userPath, []byte(userCfg), 0o644)
	cfgPath := filepath.Join(e.work, "sievelog.yaml")
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
    - {url: %s, username: admin, password_env: E2E_GRAFANA_PASSWORD, datasources: [loki]}
collector:
  config_files: [%s]
  pipeline: logs
  after: transform/prep
  measure_exporters: [file/metrics]
  dedupe_interval: 3s
  sinks:
    otlp_http/loki: {loki: true}
    file/logs: {exempt: "e2e local copy"}
policy:
  actions: [dedupe, sample]
  sample_percent: 30
  acknowledge: [grafana-queryhistory, querylog-window]
`, e.loki, gen.IPMaskName, gen.IPMaskPattern, grafanaURL, userPath)), 0o644)
	os.Setenv("E2E_GRAFANA_PASSWORD", grafanaPass)
	e.bin = filepath.Join(e.work, "sievelog")
	if out, code := e.run(e.root, "go", "build", "-o", e.bin, "./cmd/sievelog"); code != 0 {
		t.Fatal(out)
	}

	// 1. Analyze.
	outDir := filepath.Join(e.work, "loop-out")
	out, code := e.run(e.root, e.bin, "analyze", "-c", cfgPath, "-o", outDir)
	if code != 0 {
		t.Fatalf("analyze: %s", out)
	}
	t.Logf("analyze: %s", strings.TrimSpace(out))
	rf, err := app.LoadRules(filepath.Join(outDir, "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, r := range rf.Rules {
		actions[r.Service+"|"+r.Template] = r.Action
	}
	want := map[string]string{
		"checkout|INFO heartbeat ok":       "dedupe",
		"checkout|DEBUG cache <*> key <*>": "sample",
	}
	if len(actions) != len(want) {
		md, _ := os.ReadFile(filepath.Join(outDir, "report.md"))
		t.Fatalf("acting rules %v, want %v\n%s", actions, want, md)
	}
	for k, a := range want {
		if actions[k] != a {
			t.Fatalf("%s: action %q, want %q", k, actions[k], a)
		}
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

	// 2. Shadow: measure only. Every line still reaches Loki; per-rule counts equal ground truth.
	shadowPath := filepath.Join(e.work, "loop-shadow.yaml")
	if out, code := e.run(e.root, e.bin, "emit", "-c", cfgPath, "-rules", filepath.Join(outDir, "rules.json"), "-mode", "shadow", "-o", shadowPath); code != 0 {
		t.Fatal(out)
	}
	e.resetOutputs()
	e.deployCollector(shadowPath)
	const count = 2000
	winA0 := time.Now().Add(-time.Second)
	nsA := e.batch("shadow", 21, count)
	linesA := e.nsLines(nsA, 3*count)
	winA1 := time.Now()
	if len(linesA) != 3*count {
		t.Fatalf("shadow: Loki has %d lines, want %d", len(linesA), 3*count)
	}
	rawA := e.readRaw(nsA)
	if len(rawA) != 3*count {
		t.Fatalf("shadow: raw copy has %d records, want %d", len(rawA), 3*count)
	}
	wantLines := map[string]float64{}
	wantBytes := map[string]float64{}
	for _, r := range rawA {
		if x := ruleFor(r); x != nil {
			wantLines[x.ID]++
			wantBytes[x.ID] += float64(len(r.text))
		}
	}
	time.Sleep(3 * time.Second)
	got := e.ruleMetrics()
	for _, r := range rf.Rules {
		if got[emit.MeasureLines(r.ID)] != wantLines[r.ID] || got[emit.MeasureBytes(r.ID)] != wantBytes[r.ID] || wantLines[r.ID] == 0 {
			t.Fatalf("shadow %s: measured %v lines / %v bytes, ground truth %v / %v", r.ID,
				got[emit.MeasureLines(r.ID)], got[emit.MeasureBytes(r.ID)], wantLines[r.ID], wantBytes[r.ID])
		}
	}
	t.Logf("shadow: %d lines all delivered; per-rule measurement equals ground truth %v", len(linesA), wantLines)

	// 3. Enforce.
	enforcePath := filepath.Join(e.work, "loop-enforce.yaml")
	if out, code := e.run(e.root, e.bin, "emit", "-c", cfgPath, "-rules", filepath.Join(outDir, "rules.json"), "-mode", "enforce", "-o", enforcePath); code != 0 {
		t.Fatal(out)
	}
	e.resetOutputs()
	e.deployCollector(enforcePath)
	winB0 := time.Now().Add(-time.Second)
	nsB := e.batch("enforce", 22, count)
	time.Sleep(8 * time.Second) // dedupe flushes every 3s
	rawB := e.readRaw(nsB)
	if len(rawB) != 3*count {
		t.Fatalf("enforce: raw copy has %d records, want %d", len(rawB), 3*count)
	}
	type key struct {
		svc, text string
		ts        int64
	}
	expect := map[key]bool{}
	dedupeLines := 0
	for _, r := range rawB {
		x := ruleFor(r)
		switch {
		case x == nil:
			expect[key{r.service, r.text, r.ts}] = true
		case x.Action == "sample":
			if sampleKeep(r.text, r.ts, x.Keep) {
				expect[key{r.service, r.text, r.ts}] = true
			}
		case x.Action == "dedupe":
			dedupeLines++
		default:
			t.Fatalf("unexpected action %s", x.Action)
		}
	}
	linesB := e.nsLines(nsB, len(expect))
	gotSet := map[key]bool{}
	dedupeRecords := 0
	for _, l := range linesB {
		svc := l.Labels["service_name"]
		text := l.Line
		structured := false
		if svc == "orders" {
			var m map[string]any
			if err := json.Unmarshal([]byte(l.Line), &m); err == nil {
				text, _ = m["msg"].(string)
				structured = true
			}
		}
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
	// Dedupe keeps every line's content and its total count.
	lc := &loki.Client{Base: e.loki}
	sum, err := lc.Instant(context.Background(), `sum(sum_over_time({k8s_namespace_name="`+nsB+`", service_name="checkout"} |= "INFO heartbeat ok" | unwrap sievelog_dedup_count [1h]))`, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(sum) != 1 || int(sum[0].Value) != dedupeLines {
		t.Fatalf("dedupe: counts in Loki %+v, want total %d", sum, dedupeLines)
	}
	if dedupeRecords == 0 || dedupeRecords >= dedupeLines {
		t.Fatalf("dedupe: %d records stored for %d lines", dedupeRecords, dedupeLines)
	}
	t.Logf("enforce: %d lines reached Loki exactly as predicted; %d heartbeats stored as %d records with exact counts", len(gotSet), dedupeLines, dedupeRecords)
	winB1 := time.Now()

	// 3b. Reconcile from Loki's own data: exactly what was stored for each rule before and after.
	recPath := filepath.Join(e.work, "loop-reconcile.json")
	w := func(a, b time.Time) string {
		return a.UTC().Format(time.RFC3339Nano) + "," + b.UTC().Format(time.RFC3339Nano)
	}
	out, code = e.run(e.root, e.bin, "reconcile", "-c", cfgPath, "-rules", filepath.Join(outDir, "rules.json"),
		"-before", w(winA0, winA1), "-after", w(winB0, winB1), "-tolerance", "1", "-o", recPath)
	if code != 0 {
		t.Fatalf("reconcile (exit %d): %s", code, out)
	}
	var rec app.Reconciliation
	rb, _ := os.ReadFile(recPath)
	if err := json.Unmarshal(rb, &rec); err != nil {
		t.Fatal(err)
	}
	keptCache := 0
	for k := range expect {
		if x := ruleFor(rawRecord{service: k.svc, text: k.text}); x != nil && x.Action == "sample" {
			keptCache++
		}
	}
	for _, r := range rec.Rules {
		switch r.Action {
		case "sample":
			if int(r.BeforeLines) != int(wantLines[r.RuleID]) || int(r.AfterLines) != keptCache {
				t.Fatalf("reconcile %s: before %v after %v, want %v and %d", r.RuleID, r.BeforeLines, r.AfterLines, wantLines[r.RuleID], keptCache)
			}
		case "dedupe":
			if int(r.BeforeLines) != int(wantLines[r.RuleID]) || int(r.AfterLines) != dedupeRecords {
				t.Fatalf("reconcile %s: before %v after %v, want %v and %d", r.RuleID, r.BeforeLines, r.AfterLines, wantLines[r.RuleID], dedupeRecords)
			}
		}
	}
	t.Logf("reconcile: per-rule stored lines before and after match the ground truth exactly")

	// 4. Verify: nothing changed, all rules still safe.
	out, code = e.run(e.root, e.bin, "verify", "-c", cfgPath, "-rules", filepath.Join(outDir, "rules.json"))
	if code != 0 {
		t.Fatalf("verify should pass: %s", out)
	}

	// 4b. The deployed config is exactly the emitted enforce config; an edit to it fails verify.
	out, code = e.run(e.root, e.bin, "verify", "-c", cfgPath, "-rules", filepath.Join(outDir, "rules.json"), "-deployed", enforcePath)
	if code != 0 {
		t.Fatalf("verify against the deployed enforce config should pass (exit %d): %s", code, out)
	}
	eb, _ := os.ReadFile(enforcePath)
	editedPath := filepath.Join(e.work, "loop-enforce-edited.yaml")
	// Someone raises the sample rule's keep share by hand.
	edited := strings.Replace(string(eb), emit.SampleThreshold(30), emit.SampleThreshold(90), 1)
	if edited == string(eb) {
		t.Fatalf("enforce config has no sample key to edit:\n%s", eb)
	}
	os.WriteFile(editedPath, []byte(edited), 0o644)
	out, code = e.run(e.root, e.bin, "verify", "-c", cfgPath, "-rules", filepath.Join(outDir, "rules.json"), "-deployed", editedPath)
	if code != 3 || !strings.Contains(out, "deployed pipeline config is not what emit produces") {
		t.Fatalf("verify should fail on an edited deployed config (exit %d): %s", code, out)
	}
	t.Logf("verify: the deployed config matches the emitted one, and a hand edit is caught")

	// 4d. A changed masking rule invalidates every rule.
	cb, _ := os.ReadFile(cfgPath)
	changedCfg := filepath.Join(e.work, "sievelog-changed-masks.yaml")
	os.WriteFile(changedCfg, []byte(strings.Replace(string(cb), "  masking_rules:\n", "  masking_rules:\n    - {name: hex, pattern: '\\b[0-9a-f]{8}\\b'}\n", 1)), 0o644)
	out, code = e.run(e.root, e.bin, "verify", "-c", changedCfg, "-rules", filepath.Join(outDir, "rules.json"), "-drift=false")
	if code != 3 || !strings.Contains(out, "masking rules or seed templates changed") {
		t.Fatalf("verify should fail after a masking change (exit %d): %s", code, out)
	}
	t.Logf("verify: a masking-rule change invalidates the rules")

	// 6a. The same check, scheduled in the cluster by the Helm chart: it must pass now.
	helmVerify := e.installChart(filepath.Join(outDir, "rules.json"), userPath, grafanaURL)
	if code, logs := helmVerify("pass"); code != 0 || !strings.Contains(logs, "still safe") {
		t.Fatalf("scheduled verify should pass (exit %d): %s", code, logs)
	}

	// 5. Someone builds a dashboard that reads cache lines: verify must fail and revert that rule.
	s, b := grafanaCall(t, grafanaURL, "POST", "/api/dashboards/db", 1, map[string]any{"overwrite": true, "dashboard": map[string]any{
		"uid": "cache-watch", "title": "Cache watch", "schemaVersion": 41,
		"panels": []any{map[string]any{"id": 1, "type": "logs", "datasource": map[string]any{"type": "loki", "uid": "loki"},
			"targets": []any{map[string]any{"refId": "A", "expr": `{service_name="checkout"} |= "cache miss"`}}}}}})
	must(t, s, b, 200)
	defer grafanaCall(t, grafanaURL, "DELETE", "/api/dashboards/uid/cache-watch", 1, nil)
	keepPath := filepath.Join(e.work, "loop-keep.json")
	out, code = e.run(e.root, e.bin, "verify", "-c", cfgPath, "-rules", filepath.Join(outDir, "rules.json"), "-o", keepPath)
	if code != 3 || !strings.Contains(out, "cache miss") {
		t.Fatalf("verify should fail on the new dashboard (exit %d): %s", code, out)
	}
	keep, err := app.LoadRules(keepPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(keep.Rules) != 1 || keep.Rules[0].Template != "INFO heartbeat ok" {
		t.Fatalf("revert keeps %+v, want only the heartbeat rule", keep.Rules)
	}
	t.Logf("verify caught the new reader and reverted the cache rule")

	// 6b. The scheduled check fails the same way, so an operator is alerted by the failed Job.
	if code, logs := helmVerify("fail"); code != 3 || !strings.Contains(logs, "cache miss") {
		t.Fatalf("scheduled verify should fail with exit 3 (got %d): %s", code, logs)
	}
	t.Logf("the Helm-scheduled verify passed, then failed with exit 3 once the new dashboard appeared")
	_ = gen.Corpus
}

// lokiPush writes n copies of line to the e2e Loki under the given labels, a nanosecond apart.
func lokiPush(t *testing.T, base string, labels map[string]string, line string, n int) {
	t.Helper()
	now := time.Now().UnixNano()
	var values [][]string
	for i := 0; i < n; i++ {
		values = append(values, []string{strconv.FormatInt(now+int64(i), 10), line})
	}
	b, _ := json.Marshal(map[string]any{"streams": []any{map[string]any{"stream": labels, "values": values}}})
	resp, err := http.Post(base+"/loki/api/v1/push", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("loki push: %d %s", resp.StatusCode, body)
	}
}
