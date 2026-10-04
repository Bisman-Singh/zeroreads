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

// checkDelivery verifies the pipeline exported exactly the generated lines, per service, in
// order, with the bytes of each original line.
func checkDelivery(recs []gen.Record, obs []observed) error {
	isJSON := map[string]bool{}
	for _, s := range gen.Corpus() {
		isJSON[s.Name] = s.JSON
	}
	want := map[string][]gen.Record{}
	for _, r := range recs {
		want[r.Service] = append(want[r.Service], r)
	}
	got := map[string][]observed{}
	for _, o := range obs {
		got[o.service] = append(got[o.service], o)
	}
	if len(got) != len(want) {
		return fmt.Errorf("services: got %d, want %d", len(got), len(want))
	}
	for svc, w := range want {
		g := got[svc]
		if len(g) != len(w) {
			return fmt.Errorf("%s: got %d records, want %d", svc, len(g), len(w))
		}
		for i := range w {
			if eb := expectedBody(w[i], isJSON[svc]); g[i].body != eb {
				return fmt.Errorf("%s[%d]: body %q, want %q", svc, i, g[i].body, eb)
			}
			if g[i].bytes != int64(len(w[i].Line)) {
				return fmt.Errorf("%s[%d]: bytes %d, want %d", svc, i, g[i].bytes, len(w[i].Line))
			}
		}
	}
	return nil
}

// offlineTemplates runs the embedded engine with the pipeline's configuration over the same
// records and returns the template per record, keyed by service and position.
func offlineTemplates(t *testing.T, recs []gen.Record) map[string][]string {
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
	out := map[string][]string{}
	for i, r := range recs {
		out[r.Service] = append(out[r.Service], tmpl[i])
	}
	return out
}

// checkTemplatesEqual verifies every pipeline record carries exactly the offline template.
func checkTemplatesEqual(offline map[string][]string, obs []observed) error {
	idx := map[string]int{}
	for _, o := range obs {
		i := idx[o.service]
		idx[o.service]++
		want := offline[o.service]
		if i >= len(want) {
			return fmt.Errorf("%s: more pipeline records than offline", o.service)
		}
		if o.template == "" {
			return fmt.Errorf("%s[%d]: no template in pipeline", o.service, i)
		}
		if o.template != want[i] {
			return fmt.Errorf("%s[%d]: pipeline %q, offline %q", o.service, i, o.template, want[i])
		}
	}
	return nil
}

// checkSums verifies the per-template metric totals equal the ground truth grouped by the
// template each record received.
func checkSums(recs []gen.Record, obs []observed, sums map[string]map[key]float64) error {
	wantRecords := map[key]float64{}
	wantBytes := map[key]float64{}
	wantLen := map[key]float64{}
	isJSON := map[string]bool{}
	for _, s := range gen.Corpus() {
		isJSON[s.Name] = s.JSON
	}
	byService := map[string][]gen.Record{}
	for _, r := range recs {
		byService[r.Service] = append(byService[r.Service], r)
	}
	idx := map[string]int{}
	for _, o := range obs {
		r := byService[o.service][idx[o.service]]
		idx[o.service]++
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
	offline := offlineTemplates(t, recs)

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
	})

	t.Run("pipeline templates equal offline templates", func(t *testing.T) {
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
		if err := checkSums(recs, obs, sums); err != nil {
			t.Fatal(err)
		}
		for k := range sums["zeroreads.template.bytes"] {
			sums["zeroreads.template.bytes"][k]++
			break
		}
		if checkSums(recs, obs, sums) == nil {
			t.Fatal("negative: a wrong byte sum was not detected")
		}
	})

	t.Logf("records=%d templates=%d", len(obs), len(sums["zeroreads.template.records"]))
}
