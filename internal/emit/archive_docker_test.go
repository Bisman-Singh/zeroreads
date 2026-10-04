//go:build docker

package emit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
)

// Real Vector archives exactly the archived rules' events, each naming its rule, and delivers every
// other event exactly as without the archive.
func TestVectorArchivesExactly(t *testing.T) {
	cfg := strings.Replace(vectorUserConfig, "sinks:\n", "sinks:\n  archive:\n    type: file\n    inputs: []\n    path: /w/archive.json\n    encoding: {codec: json}\n", 1)
	target := vectorTarget()
	target.ArchiveSinks = []string{"archive"}
	rules := withArchive("r-health", "r-route")
	out, err := Vector([][]byte{[]byte(cfg)}, target, rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "vector.yaml"), out, 0o644)
	recs := genRecords(3000)
	events, _ := runVectorInput(t, dir, vectorInput(recs))
	type key struct {
		svc, text string
		ts        float64
	}
	main := map[key]int{}
	for _, ev := range events {
		svc, text, _ := eventText(ev)
		if _, counted := ev["zeroreads_count"]; counted {
			continue // dedupe output, checked by TestVectorEnforcesExactly
		}
		ts, _ := ev["tsn"].(float64)
		main[key{svc, text, ts}]++
	}
	archived := map[key]string{}
	f, err := os.Open(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 16<<20), 16<<20)
	for sc.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		svc, text, _ := eventText(ev)
		ts, _ := ev["tsn"].(float64)
		rule, _ := ev["zeroreads_archive"].(string)
		if _, twice := archived[key{svc, text, ts}]; twice {
			t.Fatalf("archived twice: %v", ev)
		}
		archived[key{svc, text, ts}] = rule
		if _, ok := ev["zeroreads_rule"]; ok {
			t.Fatalf("internal field in the archive: %v", ev)
		}
	}
	n := 0
	for _, r := range recs {
		k := key{r.service, r.text, float64(r.ts)}
		x := matched(r)
		if x != nil && (x.ID == "r-health" || x.ID == "r-route") {
			n++
			if archived[k] != x.ID || main[k] != 0 {
				t.Fatalf("%+v: archive %q, delivered %d; want archived by %s only", k, archived[k], main[k], x.ID)
			}
			continue
		}
		if _, ok := archived[k]; ok {
			t.Fatalf("%+v archived without an archive rule", k)
		}
	}
	if n < 300 || len(archived) != n {
		t.Fatalf("%d archived events, want %d (at least 300)", len(archived), n)
	}
	t.Logf("vector: %d events archived exactly, each with its rule", n)
}

// Real Fluent Bit moves exactly the archived rules' records to the archive output, each naming its
// rule, and delivers every other record as without the archive.
func TestFluentBitArchivesExactly(t *testing.T) {
	cfg := strings.Replace(fluentBitUserConfig, "  outputs:\n", "  outputs:\n    - name: stdout\n      alias: archive\n      match: zeroreads.archive\n      format: otlp_json\n", 1)
	target := fluentBitTarget()
	target.ArchiveOutputs = []string{"archive"}
	var rules []Rule
	for _, r := range withArchive("r-health", "r-route") {
		if r.Action != "dedupe" {
			rules = append(rules, r)
		}
	}
	out, err := FluentBit([][]byte{[]byte(cfg)}, target, rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	recs := genRecords(2500)
	got, _ := runFluentBit(t, out, recs)
	type key struct {
		svc, text  string
		ts         int64
		structured bool
	}
	raw, app, archived := map[key]int{}, map[key]int{}, map[key]map[string]int{}
	for _, r := range got {
		k := key{r.service, r.text, r.ts, r.structured}
		switch {
		case r.archive != "":
			if archived[k] == nil {
				archived[k] = map[string]int{}
			}
			archived[k][r.archive]++
		case r.stream == "raw":
			raw[k]++
		case r.stream == "app":
			app[k]++
		}
	}
	match := func(k key) *Rule {
		for i := range rules {
			if r := &rules[i]; r.ScopeValue == k.svc && (r.Field != "") == k.structured && regexp.MustCompile(r.Language).MatchString(k.text) {
				return r
			}
		}
		return nil
	}
	n := 0
	for k, c := range raw {
		x := match(k)
		switch {
		case x != nil && x.Action == "archive":
			n += c
			if archived[k][x.ID] != c || app[k] != 0 {
				t.Fatalf("%+v: archived %v, delivered %d; want %d archived by %s only", k, archived[k], app[k], c, x.ID)
			}
		case len(archived[k]) > 0:
			t.Fatalf("%+v archived without an archive rule", k)
		case (x == nil || x.Action == "sample") && app[k] == 0 && (x == nil || fbKeep(k.text, k.ts, x.Keep)):
			t.Fatalf("%+v: lost", k)
		}
	}
	if n < 300 {
		t.Fatalf("only %d archived records", n)
	}
	t.Logf("fluent bit: %d records archived exactly, each with its rule", n)
}

// The real Collector (the contrib release the suites pin) archives exactly the archived rules'
// records through the emitted connectors and pipelines, each naming its rule, and exports every
// other record as it would without the archive.
func TestCollectorArchivesExactly(t *testing.T) {
	user := `
receivers:
  otlp_json_file:
    include: [/w/in.json]
    start_at: beginning
processors:
  transform/prep:
    log_statements:
      - context: log
        statements: ['set(log.attributes["prep"], "1")']
exporters:
  file/main: {path: /w/main.json}
  file/archive: {path: /w/archive.json}
  file/metrics: {path: /w/metrics.json}
service:
  pipelines:
    logs:
      receivers: [otlp_json_file]
      processors: [transform/prep]
      exporters: [file/main]
`
	rules := withArchive("r-health", "r-route")
	out, err := Collector([][]byte{[]byte(user)}, Target{Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"file/metrics"},
		AggregateExporters: []string{"file/metrics"}, ArchiveExporters: []string{"file/archive"}, DedupeInterval: "300ms"}, rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o777) // the Collector image runs as a non-root user
	os.WriteFile(filepath.Join(dir, "c.yaml"), out, 0o644)
	recs := genRecords(3000)
	in, err := (&plog.JSONMarshaler{}).MarshalLogs(toLogs(recs))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "in.json"), append(in, '\n'), 0o644)
	name := fmt.Sprintf("zeroreads-archive-%d", time.Now().UnixNano())
	if b, err := exec.Command("docker", "run", "-d", "--name", name, "-v", dir+":/w", "otel/opentelemetry-collector-contrib:0.161.0",
		"--config", "/w/c.yaml").CombinedOutput(); err != nil {
		t.Fatalf("collector: %v %s", err, b)
	}
	defer exec.Command("docker", "rm", "-f", name).Run()
	// Stop once both outputs have held still for a while: the Collector then flushes on shutdown.
	last := int64(-1)
	for stable, deadline := 0, time.Now().Add(90*time.Second); stable < 3 && time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		size := fileSize(filepath.Join(dir, "main.json")) + fileSize(filepath.Join(dir, "archive.json"))
		if size > 0 && size == last {
			stable++
		} else {
			stable = 0
		}
		last = size
	}
	if b, err := exec.Command("docker", "stop", "-t", "20", name).CombinedOutput(); err != nil {
		t.Fatalf("stop: %v %s", err, b)
	}
	if logs, _ := exec.Command("docker", "logs", name).CombinedOutput(); strings.Contains(string(logs), "Error:") {
		t.Fatalf("collector failed:\n%s", logs)
	}
	main := collectorTimes(t, filepath.Join(dir, "main.json"))
	archive := collectorTimes(t, filepath.Join(dir, "archive.json"))
	n := 0
	for _, rec := range recs {
		x := matched(rec)
		rule, archived := archive[rec.ts]
		_, delivered := main[rec.ts]
		switch {
		case x != nil && (x.ID == "r-health" || x.ID == "r-route"):
			n++
			if !archived || rule != x.ID || delivered {
				t.Fatalf("%+v: archived=%v (%q) delivered=%v; want archived by %s only", rec, archived, rule, delivered, x.ID)
			}
		case archived:
			t.Fatalf("%+v archived without an archive rule", rec)
		case x == nil && !delivered:
			t.Fatalf("%+v: no rule applies, but it was not delivered", rec)
		}
	}
	if n < 300 || len(archive) != n {
		t.Fatalf("%d archived records, want %d (at least 300)", len(archive), n)
	}
	t.Logf("collector: %d records archived exactly, each with its rule", n)
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// collectorTimes reads a file exporter's OTLP JSON lines: record timestamp -> its archive rule.
func collectorTimes(t *testing.T, path string) map[int64]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[int64]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<20), 64<<20)
	for sc.Scan() {
		ld, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs(sc.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		for ts, rule := range byTime(ld) {
			if _, twice := out[ts]; twice {
				t.Fatalf("record %d exported twice to %s", ts, path)
			}
			out[ts] = rule
		}
	}
	return out
}

// The real Collector starts with what emit writes when no rule acts. Found on the demo run: the
// empty measurement connector emit used to write made the Collector refuse its configuration.
func TestCollectorStartsWithNoRules(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []Mode{Shadow, Enforce} {
		out, err := Collector([][]byte{[]byte(archiveConfig)}, archiveTarget(), nil, mode)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "c.yaml"), out, 0o644)
		if b, err := exec.Command("docker", "run", "--rm", "-v", dir+":/w", "otel/opentelemetry-collector-contrib:0.161.0",
			"validate", "--config", "/w/c.yaml").CombinedOutput(); err != nil {
			t.Fatalf("%s: the Collector refuses the configuration: %v\n%s", mode, err, b)
		}
	}
}
