//go:build docker

package emit

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// The real Collector resolves the emitted configuration with every value from the logs intact and
// no environment variable read.
func TestCollectorResolvesValuesLiterally(t *testing.T) {
	svc := "svc${env:ZEROREADS_TEST_SECRET}$${ZEROREADS_TEST_SECRET}$HOME"
	rules := []Rule{{ID: "r-dollar", ScopeAttr: "service.name", ScopeValue: svc, Language: `\Acost ` + regexp.QuoteMeta("${ZEROREADS_TEST_SECRET}") + `\z`, Action: "drop"}}
	cfg, err := Collector([][]byte{[]byte(userConfig)}, Target{Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"file/metrics"}}, rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "c.yaml"), cfg, 0o644)
	out, err := exec.Command("docker", "run", "--rm", "-e", "ZEROREADS_TEST_SECRET=leaked", "-v", dir+":/w",
		"otel/opentelemetry-collector-contrib:0.161.0", "print-config", "--mode", "unredacted", "--config", "/w/c.yaml").CombinedOutput()
	if err != nil {
		t.Fatalf("print-config: %v\n%s", err, out)
	}
	resolved := string(out)
	if strings.Contains(resolved, "leaked") {
		t.Fatalf("the Collector expanded an environment variable in the emitted rules:\n%s", resolved)
	}
	for _, want := range []string{`resource.attributes["service.name"] == "` + svc + `"`, `\\$\\{ZEROREADS_TEST_SECRET\\}`} {
		if !strings.Contains(resolved, want) {
			t.Fatalf("resolved configuration lacks %s:\n%s", want, resolved)
		}
	}
}

// The real Collector's per-rule measurement is exact when its deltas are summed, as a delta-aware
// consumer does, however the records are spread over batches: here three chunks, seconds apart.
func TestCollectorMeasuresExactlyAcrossBatches(t *testing.T) {
	user := `
receivers:
  otlp_json_file:
    include: [/w/in-*.json]
    start_at: beginning
    poll_interval: 200ms
processors:
  transform/prep:
    log_statements:
      - context: log
        statements: ['set(log.attributes["prep"], "1")']
exporters:
  file/main: {path: /w/main.json}
  file/metrics: {path: /w/metrics.json}
service:
  pipelines:
    logs:
      receivers: [otlp_json_file]
      processors: [transform/prep]
      exporters: [file/main]
`
	out, err := Collector([][]byte{[]byte(user)}, Target{Pipeline: "logs", After: "transform/prep",
		MeasureExporters: []string{"file/metrics"}, AggregateExporters: []string{"file/metrics"}}, testRules, Shadow)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o777) // the Collector image runs as a non-root user
	os.WriteFile(filepath.Join(dir, "c.yaml"), out, 0o644)
	name := fmt.Sprintf("zeroreads-measure-%d", time.Now().UnixNano())
	if b, err := exec.Command("docker", "run", "-d", "--name", name, "-v", dir+":/w",
		"otel/opentelemetry-collector-contrib:0.161.0", "--config", "/w/c.yaml").CombinedOutput(); err != nil {
		t.Fatalf("collector: %v %s", err, b)
	}
	defer exec.Command("docker", "rm", "-f", name).Run()
	recs := genRecords(3000)
	want := map[string]float64{}
	for i := 0; i < 3; i++ { // three chunks, two seconds apart: separate, non-contiguous batches
		chunk := recs[i*1000 : (i+1)*1000]
		for _, r := range chunk {
			if x := matched(r); x != nil {
				want[x.ID]++
			}
		}
		in, err := (&plog.JSONMarshaler{}).MarshalLogs(toLogs(chunk))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("in-%d.json", i)), append(in, '\n'), 0o644)
		time.Sleep(2 * time.Second)
	}
	var got map[string]float64
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		if _, err := os.Stat(filepath.Join(dir, "metrics.json")); err == nil {
			if got = deltaTotals(t, filepath.Join(dir, "metrics.json"), "zeroreads.rule.lines."); maps.Equal(got, want) {
				break
			}
		}
	}
	exec.Command("docker", "stop", "-t", "20", name).Run()
	if got = deltaTotals(t, filepath.Join(dir, "metrics.json"), "zeroreads.rule.lines."); !maps.Equal(got, want) {
		t.Fatalf("measured %v, want %v", got, want)
	}
	t.Logf("collector: every rule's measurement exact over three separate batches: %v", want)
}

// deltaTotals sums a file exporter's delta points of the metrics named prefix+rule, per rule.
func deltaTotals(t *testing.T, path, prefix string) map[string]float64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]float64{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<20), 64<<20)
	for sc.Scan() {
		md, err := (&pmetric.JSONUnmarshaler{}).UnmarshalMetrics(sc.Bytes())
		if err != nil {
			continue // a line the exporter is still writing
		}
		for i := 0; i < md.ResourceMetrics().Len(); i++ {
			rm := md.ResourceMetrics().At(i)
			for j := 0; j < rm.ScopeMetrics().Len(); j++ {
				ms := rm.ScopeMetrics().At(j).Metrics()
				for k := 0; k < ms.Len(); k++ {
					m := ms.At(k)
					id, ok := strings.CutPrefix(m.Name(), prefix)
					if !ok {
						continue
					}
					if m.Sum().AggregationTemporality() != pmetric.AggregationTemporalityDelta {
						t.Fatalf("%s is not a delta sum", m.Name())
					}
					dps := m.Sum().DataPoints()
					for d := 0; d < dps.Len(); d++ {
						out[id] += float64(dps.At(d).IntValue()) + dps.At(d).DoubleValue()
					}
				}
			}
		}
	}
	return out
}
