//go:build e2e

// Package e2e checks the collector pipeline running in kind against the ground truth and the
// embedded drain engine. Run it through e2e/run.sh, which produces the files it reads.
package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/Bisman-Singh/zeroreads/internal/gen"
	"github.com/Bisman-Singh/zeroreads/internal/templating"
)

// observed is one record as the pipeline exported it.
type observed struct {
	service  string
	body     string // raw string body, or canonical JSON for map bodies
	template string
	bytes    int64 // zeroreads.body_bytes captured before JSON parsing
}

type key struct{ service, template string }

func env(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("%s not set; run e2e/run.sh", name)
	}
	return v
}

func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func readLogs(t *testing.T, path string) []observed {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []observed
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<20), 64<<20)
	var u plog.JSONUnmarshaler
	for sc.Scan() {
		ld, err := u.UnmarshalLogs(sc.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		rls := ld.ResourceLogs()
		for i := 0; i < rls.Len(); i++ {
			sls := rls.At(i).ScopeLogs()
			for j := 0; j < sls.Len(); j++ {
				lrs := sls.At(j).LogRecords()
				for k := 0; k < lrs.Len(); k++ {
					lr := lrs.At(k)
					o := observed{}
					if v, ok := lr.Attributes().Get("service.name"); ok {
						o.service = v.Str()
					}
					if v, ok := lr.Attributes().Get("log.record.template"); ok {
						o.template = v.Str()
					}
					if v, ok := lr.Attributes().Get("zeroreads.body_bytes"); ok {
						o.bytes = v.Int()
					}
					if lr.Body().Type() == pcommon.ValueTypeMap {
						o.body = canonicalJSON(lr.Body().Map().AsRaw())
					} else {
						o.body = lr.Body().AsString()
					}
					out = append(out, o)
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// readSums totals every exported datapoint of each sum metric by (service, template).
// signal_to_metrics keeps no state, so the sum over all payloads is the exact total.
func readSums(t *testing.T, path string) map[string]map[key]float64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]map[key]float64{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<20), 64<<20)
	var u pmetric.JSONUnmarshaler
	for sc.Scan() {
		md, err := u.UnmarshalMetrics(sc.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		rms := md.ResourceMetrics()
		for i := 0; i < rms.Len(); i++ {
			sms := rms.At(i).ScopeMetrics()
			for j := 0; j < sms.Len(); j++ {
				ms := sms.At(j).Metrics()
				for k := 0; k < ms.Len(); k++ {
					m := ms.At(k)
					if m.Type() != pmetric.MetricTypeSum {
						t.Fatalf("metric %s is %s, want sum", m.Name(), m.Type())
					}
					dps := m.Sum().DataPoints()
					for d := 0; d < dps.Len(); d++ {
						dp := dps.At(d)
						svc, _ := dp.Attributes().Get("service.name")
						tpl, _ := dp.Attributes().Get("log.record.template")
						v := dp.DoubleValue()
						if dp.ValueType() == pmetric.NumberDataPointValueTypeInt {
							v = float64(dp.IntValue())
						}
						if out[m.Name()] == nil {
							out[m.Name()] = map[key]float64{}
						}
						out[m.Name()][key{svc.Str(), tpl.Str()}] += v
					}
				}
			}
		}
	}
	return out
}

func groundTruth(t *testing.T) ([]gen.Record, gen.Manifest) {
	t.Helper()
	seed, err := strconv.ParseUint(env(t, "E2E_SEED"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	count, err := strconv.Atoi(env(t, "E2E_COUNT"))
	if err != nil {
		t.Fatal(err)
	}
	recs, m, err := gen.Run(seed, count)
	if err != nil {
		t.Fatal(err)
	}
	return recs, m
}

// expectedBody is how the pipeline should export a generated line: plain services keep the
// string, the JSON service is parsed into a map.
func expectedBody(r gen.Record, isJSON bool) string {
	if !isJSON {
		return r.Line
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Line), &m); err != nil {
		panic(err)
	}
	return canonicalJSON(m)
}

// pairRecords gives every exported record the generated record it came from, matched by content
// within its service: the file receiver can hand lines on out of order, which no total depends on.
// Identical lines pair in the order they occur. A record exported that was never generated, or
// generated and never exported, is an error.
func pairRecords(recs []gen.Record, obs []observed) ([]gen.Record, error) {
	isJSON := map[string]bool{}
	for _, s := range gen.Corpus() {
		isJSON[s.Name] = s.JSON
	}
	type line struct{ service, body string }
	pending := map[line][]gen.Record{}
	for _, r := range recs {
		k := line{r.Service, expectedBody(r, isJSON[r.Service])}
		pending[k] = append(pending[k], r)
	}
	paired := make([]gen.Record, len(obs))
	for i, o := range obs {
		k := line{o.service, o.body}
		if len(pending[k]) == 0 {
			return nil, fmt.Errorf("%s: exported %q, which was not generated, or not that often", o.service, o.body)
		}
		paired[i] = pending[k][0]
		pending[k] = pending[k][1:]
	}
	for k, left := range pending {
		if len(left) > 0 {
			return nil, fmt.Errorf("%s: %d generated records were not exported, such as %q", k.service, len(left), k.body)
		}
	}
	return paired, nil
}

// checkDelivery verifies the pipeline exported exactly the generated lines, each once, with the
// bytes of each original line.
func checkDelivery(recs []gen.Record, obs []observed) error {
	paired, err := pairRecords(recs, obs)
	if err != nil {
		return err
	}
	for i, o := range obs {
		if o.bytes != int64(len(paired[i].Line)) {
			return fmt.Errorf("%s: %q exported with bytes %d, want %d", o.service, o.body, o.bytes, len(paired[i].Line))
		}
	}
	return nil
}

// offlineTemplates runs the embedded engine with the pipeline's configuration over the same
// records, in the order the pipeline exported them since templates depend on order, and returns
// the template of each.
func offlineTemplates(t *testing.T, recs []gen.Record) []string {
	t.Helper()
	ctx := context.Background()
	cfg := templating.DefaultConfig()
	cfg.BodyField = "msg"
	cfg.MaskingRules = []templating.MaskRule{{Name: gen.IPMaskName, Pattern: gen.IPMaskPattern}}
	cfg.SeedTemplates = gen.SeedTemplates()
	e, err := templating.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)
	isJSON := map[string]bool{}
	for _, s := range gen.Corpus() {
		isJSON[s.Name] = s.JSON
	}
	in := make([]templating.Input, len(recs))
	for i, r := range recs {
		if !isJSON[r.Service] {
			in[i] = templating.Input{Body: r.Line}
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(r.Line), &m); err != nil {
			t.Fatal(err)
		}
		in[i] = templating.Input{Fields: m}
	}
	tmpl, err := e.Template(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}

// checkTemplatesEqual verifies every pipeline record carries exactly the offline template.
func checkTemplatesEqual(offline []string, obs []observed) error {
	if len(offline) != len(obs) {
		return fmt.Errorf("%d pipeline records, %d offline", len(obs), len(offline))
	}
	for i, o := range obs {
		if o.template == "" {
			return fmt.Errorf("%s[%d]: no template in pipeline", o.service, i)
		}
		if o.template != offline[i] {
			return fmt.Errorf("%s[%d]: pipeline %q, offline %q", o.service, i, o.template, offline[i])
		}
	}
	return nil
}

// checkSums verifies the per-template metric totals equal the ground truth grouped by the
// template each record received.
func checkSums(paired []gen.Record, obs []observed, sums map[string]map[key]float64) error {
	wantRecords := map[key]float64{}
	wantBytes := map[key]float64{}
	wantLen := map[key]float64{}
	isJSON := map[string]bool{}
	for _, s := range gen.Corpus() {
		isJSON[s.Name] = s.JSON
	}
	for i, o := range obs {
		r := paired[i]
		k := key{o.service, o.template}
		wantRecords[k]++
		wantBytes[k] += float64(len(r.Line))
		if isJSON[o.service] {
			wantLen[k] += 4 // Len of the parsed map: level, msg, route, status
		} else {
			wantLen[k] += float64(len(r.Line))
		}
	}
	for name, want := range map[string]map[key]float64{
		"zeroreads.template.records":         wantRecords,
		"zeroreads.template.bytes":           wantBytes,
		"zeroreads.template.len_after_parse": wantLen,
	} {
		got := sums[name]
		if len(got) != len(want) {
			return fmt.Errorf("%s: %d series, want %d", name, len(got), len(want))
		}
		for k, w := range want {
			if got[k] != w {
				return fmt.Errorf("%s %v: got %v, want %v", name, k, got[k], w)
			}
		}
	}
	return nil
}

func TestPipelineMatchesGroundTruthAndOffline(t *testing.T) {
	dir := env(t, "E2E_OUT")
	recs, _ := groundTruth(t)
	obs := readLogs(t, filepath.Join(dir, "logs.json"))
	sums := readSums(t, filepath.Join(dir, "metrics.json"))
	paired, pairErr := pairRecords(recs, obs)

	t.Run("delivery is exact", func(t *testing.T) {
		if err := checkDelivery(recs, obs); err != nil {
			t.Fatal(err)
		}
		bad := append([]observed(nil), obs[:len(obs)-1]...)
		if checkDelivery(recs, bad) == nil {
			t.Fatal("negative: a missing record was not detected")
		}
		bad = append([]observed(nil), obs...)
		bad[5].bytes++
		if checkDelivery(recs, bad) == nil {
			t.Fatal("negative: a wrong byte count was not detected")
		}
		swapped := append([]observed(nil), obs...)
		swapped[1], swapped[len(swapped)-1] = swapped[len(swapped)-1], swapped[1]
		if err := checkDelivery(recs, swapped); err != nil {
			t.Fatalf("lines handed on out of order are still each delivered once: %v", err)
		}
	})

	t.Run("pipeline templates equal offline templates", func(t *testing.T) {
		if pairErr != nil {
			t.Fatal(pairErr)
		}
		offline := offlineTemplates(t, paired)
		if err := checkTemplatesEqual(offline, obs); err != nil {
			t.Fatal(err)
		}
		bad := append([]observed(nil), obs...)
		bad[7].template = "something else"
		if checkTemplatesEqual(offline, bad) == nil {
			t.Fatal("negative: a differing template was not detected")
		}
	})

	t.Run("per-template sums equal ground truth", func(t *testing.T) {
		if pairErr != nil {
			t.Fatal(pairErr)
		}
		if err := checkSums(paired, obs, sums); err != nil {
			t.Fatal(err)
		}
		for k := range sums["zeroreads.template.bytes"] {
			sums["zeroreads.template.bytes"][k]++
			break
		}
		if checkSums(paired, obs, sums) == nil {
			t.Fatal("negative: a wrong byte sum was not detected")
		}
	})

	t.Logf("records=%d templates=%d", len(obs), len(sums["zeroreads.template.records"]))
}
