package emit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/signaltometricsconnector"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/logdedupprocessor"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/connector/connectortest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.yaml.in/yaml/v3"
)

const userConfig = `
receivers:
  otlp: {protocols: {grpc: {}}}
processors:
  batch: {}
  transform/prep: {}
exporters:
  debug: {}
  file/metrics: {path: /tmp/m.json}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [transform/prep, batch]
      exporters: [debug]
`

// record is one input line.
type record struct {
	service string
	text    string // plain body, or the msg field of a map body
	mapBody bool
	ts      int64
}

// testRules covers every action. Languages are shaped like inferred ones.
var testRules = []Rule{
	{ID: "r-health", ScopeAttr: "service.name", ScopeValue: "checkout", Language: `\AINFO GET /healthz 200 [0-9]{1,3}ms\z`, Action: "drop"},
	{ID: "r-cache", ScopeAttr: "service.name", ScopeValue: "checkout", Language: `\ADEBUG cache (?:hit|miss) key [0-9a-f]{8}\z`, Action: "aggregate"},
	{ID: "r-request", ScopeAttr: "service.name", ScopeValue: "checkout", Language: `\AINFO request [0-9a-f]{16} status (?:200|201|404|503) took [0-9]{1,3}ms\z`, Action: "sample", Keep: 30},
	{ID: "r-heartbeat", ScopeAttr: "service.name", ScopeValue: "checkout", Language: `\AINFO heartbeat ok\z`, Action: "dedupe"},
	{ID: "r-route", ScopeAttr: "service.name", ScopeValue: "orders", Language: `\Ahandled route in [0-9]{1,3}ms\z`, Field: "msg", Action: "sample", Keep: 50},
	{ID: "r-quote", ScopeAttr: "service.name", ScopeValue: "auth", Language: `\Asays "hi" \\ bye\z`, Action: "drop"},
	// A plain-body rule in the same service as a field rule: a plain record must still be counted and
	// removed by this rule even though the field rule's expression cannot index its body.
	{ID: "r-plain-route", ScopeAttr: "service.name", ScopeValue: "orders", Language: `\Ahandled route in 5ms\z`, Action: "drop"},
}

func genRecords(n int) []record {
	r := rand.New(rand.NewPCG(8, 9))
	var out []record
	ts := int64(1790000000000000000)
	for i := 0; i < n; i++ {
		ts += int64(1 + r.IntN(1000000))
		switch r.IntN(10) {
		case 0:
			out = append(out, record{"checkout", "INFO GET /healthz 200 " + strconv.Itoa(1+r.IntN(900)) + "ms", false, ts})
		case 1:
			out = append(out, record{"checkout", "DEBUG cache " + []string{"hit", "miss"}[r.IntN(2)] + " key " + hex8(r), false, ts})
		case 2:
			out = append(out, record{"checkout", "INFO request " + hex8(r) + hex8(r) + " status 200 took 5ms", false, ts})
		case 3:
			out = append(out, record{"checkout", "INFO heartbeat ok", false, ts})
		case 4:
			out = append(out, record{"orders", "handled route in " + strconv.Itoa(1+r.IntN(900)) + "ms", true, ts})
		case 5:
			out = append(out, record{"orders", "handled route in 5ms", false, ts}) // plain body: the field rule must not apply
		case 6:
			out = append(out, record{"auth", `says "hi" \ bye`, false, ts})
		case 7:
			out = append(out, record{"auth", "INFO GET /healthz 200 5ms", false, ts}) // right text, wrong service
		case 8:
			out = append(out, record{"checkout", "INFO GET /healthz 200 5000ms", false, ts}) // outside the language
		default:
			out = append(out, record{"checkout", "ERROR payment pay_123456 declined", false, ts})
		}
	}
	return out
}

func hex8(r *rand.Rand) string { return strconv.FormatUint(uint64(r.Uint32())|1<<32, 16)[1:] }

func toLogs(recs []record) plog.Logs {
	ld := plog.NewLogs()
	for _, rec := range recs {
		rl := ld.ResourceLogs().AppendEmpty()
		rl.Resource().Attributes().PutStr("service.name", rec.service)
		lr := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
		lr.SetTimestamp(pcommon.Timestamp(rec.ts))
		if rec.mapBody {
			m := lr.Body().SetEmptyMap()
			m.PutStr("msg", rec.text)
			m.PutStr("route", "/cart")
		} else {
			lr.Body().SetStr(rec.text)
		}
	}
	return ld
}

// matched returns the rule a record falls under, if any, computed independently with Go regexp.
func matched(rec record) *Rule {
	for i := range testRules {
		r := &testRules[i]
		if r.ScopeValue != rec.service || (r.Field != "") != rec.mapBody {
			continue
		}
		if regexp.MustCompile(r.Language).MatchString(rec.text) {
			return r
		}
	}
	return nil
}

// sampleDigest mirrors SHA256(Concat([text, String(time_unix_nano)], "|")) in OTTL.
func sampleDigest(text string, ts int64) string {
	sum := sha256.Sum256([]byte(text + "|" + strconv.FormatInt(ts, 10)))
	return hex.EncodeToString(sum[:])
}

func emitted(t *testing.T, mode Mode) map[string]any {
	t.Helper()
	out, err := Collector([][]byte{[]byte(userConfig)}, Target{Pipeline: "logs", After: "transform/prep",
		MeasureExporters: []string{"file/metrics"}, AggregateExporters: []string{"file/metrics"}, DedupeInterval: "300ms"}, testRules, mode)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func componentConfig(t *testing.T, m map[string]any, section, name string, into any) {
	t.Helper()
	raw, ok := m[section].(map[string]any)[name].(map[string]any)
	if !ok {
		t.Fatalf("%s/%s missing", section, name)
	}
	if err := confmap.NewFromStringMap(raw).Unmarshal(into); err != nil {
		t.Fatalf("%s/%s: %v", section, name, err)
	}
}

func textOf(lr plog.LogRecord) (string, bool) {
	if lr.Body().Type() == pcommon.ValueTypeMap {
		v, _ := lr.Body().Map().Get("msg")
		return v.Str(), true
	}
	return lr.Body().Str(), false
}

// The real filter processor, configured by the emitted YAML, removes exactly the expected lines.
func TestFilterRemovesExactlyTheRules(t *testing.T) {
	m := emitted(t, Enforce)
	f := filterprocessor.NewFactory()
	cfg := f.CreateDefaultConfig()
	componentConfig(t, m, "processors", "filter/sievelog", cfg)
	sink := new(consumertest.LogsSink)
	proc, err := f.CreateLogs(context.Background(), processortest.NewNopSettings(f.Type()), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	defer proc.Shutdown(context.Background())
	recs := genRecords(6000)
	if err := proc.ConsumeLogs(context.Background(), toLogs(recs)); err != nil {
		t.Fatal(err)
	}
	type key struct {
		svc, text string
		ts        int64
	}
	survived := map[key]bool{}
	for _, ld := range sink.AllLogs() {
		for i := 0; i < ld.ResourceLogs().Len(); i++ {
			rl := ld.ResourceLogs().At(i)
			svc, _ := rl.Resource().Attributes().Get("service.name")
			lrs := rl.ScopeLogs().At(0).LogRecords()
			for j := 0; j < lrs.Len(); j++ {
				txt, _ := textOf(lrs.At(j))
				survived[key{svc.Str(), txt, int64(lrs.At(j).Timestamp())}] = true
			}
		}
	}
	keptSampled, totalSampled := map[string]int{}, map[string]int{}
	for _, rec := range recs {
		r := matched(rec)
		want := true
		switch {
		case r == nil, r.Action == "dedupe":
			want = true // dedupe is not the filter's job
		case r.Action == "drop" || r.Action == "aggregate":
			want = false
		case r.Action == "sample":
			want = sampleDigest(rec.text, rec.ts) < SampleThreshold(r.Keep)
			totalSampled[r.ID]++
			if want {
				keptSampled[r.ID]++
			}
		}
		if got := survived[key{rec.service, rec.text, rec.ts}]; got != want {
			rule := "none"
			if r != nil {
				rule = r.ID
			}
			t.Fatalf("record %+v (rule %s): survived=%v want %v", rec, rule, got, want)
		}
	}
	for id, n := range totalSampled {
		frac := float64(keptSampled[id]) / float64(n)
		t.Logf("%s kept %d/%d (%.1f%%)", id, keptSampled[id], n, frac*100)
	}
}

// The real signal_to_metrics connector counts exactly each rule's lines and bytes.
func TestMeasurementCountsExactly(t *testing.T) {
	m := emitted(t, Enforce)
	f := signaltometricsconnector.NewFactory()
	cfg := f.CreateDefaultConfig()
	componentConfig(t, m, "connectors", "signal_to_metrics/sievelog", cfg)
	sink := new(consumertest.MetricsSink)
	conn, err := f.CreateLogsToMetrics(context.Background(), connectortest.NewNopSettings(f.Type()), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	defer conn.Shutdown(context.Background())
	recs := genRecords(4000)
	if err := conn.ConsumeLogs(context.Background(), toLogs(recs)); err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, md := range sink.AllMetrics() {
		rms := md.ResourceMetrics()
		for i := 0; i < rms.Len(); i++ {
			sms := rms.At(i).ScopeMetrics()
			for j := 0; j < sms.Len(); j++ {
				ms := sms.At(j).Metrics()
				for k := 0; k < ms.Len(); k++ {
					dps := ms.At(k).Sum().DataPoints()
					for d := 0; d < dps.Len(); d++ {
						dp := dps.At(d)
						v := float64(dp.IntValue())
						if dp.ValueType() == pmetric.NumberDataPointValueTypeDouble {
							v = dp.DoubleValue()
						}
						got[ms.At(k).Name()] += v
					}
				}
			}
		}
	}
	want := map[string]float64{}
	for _, rec := range recs {
		if r := matched(rec); r != nil {
			want[MeasureLines(r.ID)]++
			want[MeasureBytes(r.ID)] += float64(len(rec.text))
			if r.Action == "aggregate" {
				want[AggregateLines(r.ID)]++
			}
		}
	}
	for name, w := range want {
		if got[name] != w {
			t.Fatalf("%s: got %v want %v", name, got[name], w)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok && got[name] != 0 {
			t.Fatalf("unexpected metric %s=%v", name, got[name])
		}
	}
}

// The real logdedup processor collapses only the dedupe rule's lines, keeping their total count.
func TestDedupeCollapsesOnlyItsRule(t *testing.T) {
	m := emitted(t, Enforce)
	f := logdedupprocessor.NewFactory()
	cfg := f.CreateDefaultConfig()
	componentConfig(t, m, "processors", "logdedup/sievelog", cfg)
	sink := new(consumertest.LogsSink)
	proc, err := f.CreateLogs(context.Background(), processortest.NewNopSettings(f.Type()), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	recs := genRecords(3000)
	if err := proc.ConsumeLogs(context.Background(), toLogs(recs)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(900 * time.Millisecond)
	if err := proc.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	var heartbeatCount, heartbeatRecords, others int64
	for _, ld := range sink.AllLogs() {
		for i := 0; i < ld.ResourceLogs().Len(); i++ {
			sls := ld.ResourceLogs().At(i).ScopeLogs()
			for s := 0; s < sls.Len(); s++ {
				lrs := sls.At(s).LogRecords()
				for j := 0; j < lrs.Len(); j++ {
					lr := lrs.At(j)
					if txt, _ := textOf(lr); txt == "INFO heartbeat ok" {
						heartbeatRecords++
						c, ok := lr.Attributes().Get(DedupCounter)
						if !ok {
							t.Fatalf("deduped heartbeat without %s", DedupCounter)
						}
						heartbeatCount += c.Int()
						continue
					}
					if _, ok := lr.Attributes().Get(DedupCounter); ok {
						t.Fatalf("a non-dedupe line was deduplicated: %v", lr.Body().AsRaw())
					}
					others++
				}
			}
		}
	}
	var wantHeartbeats, wantOthers int64
	for _, rec := range recs {
		if r := matched(rec); r != nil && r.Action == "dedupe" {
			wantHeartbeats++
		} else {
			wantOthers++
		}
	}
	if heartbeatCount != wantHeartbeats || others != wantOthers {
		t.Fatalf("heartbeats counted %d (want %d) in %d records; others %d (want %d)", heartbeatCount, wantHeartbeats, heartbeatRecords, others, wantOthers)
	}
	if heartbeatRecords >= wantHeartbeats {
		t.Fatalf("dedupe did not collapse: %d records for %d lines", heartbeatRecords, wantHeartbeats)
	}
}

func TestShadowAddsNoEnforcement(t *testing.T) {
	m := emitted(t, Shadow)
	procs, _ := m["processors"].(map[string]any)
	if _, ok := procs["filter/sievelog"]; ok {
		t.Fatal("shadow mode added a filter")
	}
	if _, ok := procs["logdedup/sievelog"]; ok {
		t.Fatal("shadow mode added dedupe")
	}
	pipes := m["service"].(map[string]any)["pipelines"].(map[string]any)
	logs := pipes["logs"].(map[string]any)
	if got, _ := json.Marshal(logs["processors"]); string(got) != `["transform/prep"]` {
		t.Fatalf("head processors %s", got)
	}
	out := pipes["logs/sievelog"].(map[string]any)
	if got, _ := json.Marshal(out); !strings.Contains(string(got), `"processors":["batch"]`) || !strings.Contains(string(got), `"exporters":["debug"]`) {
		t.Fatalf("out pipeline %s", got)
	}
}

func TestOverlappingRulesRejected(t *testing.T) {
	bad := []Rule{
		{ID: "a", ScopeAttr: "service.name", ScopeValue: "x", Language: `\Auser [a-z]+ logged in\z`, Action: "drop"},
		{ID: "b", ScopeAttr: "service.name", ScopeValue: "x", Language: `\Auser .* logged in\z`, Action: "drop"},
	}
	if _, err := Collector([][]byte{[]byte(userConfig)}, Target{Pipeline: "logs", MeasureExporters: []string{"file/metrics"}}, bad, Enforce); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("got %v", err)
	}
}

func TestSampleThresholdFraction(t *testing.T) {
	for _, keep := range []int{1, 10, 30, 50, 90, 99} {
		s := SampleThreshold(keep)
		kept := 0
		n := 200000
		for i := 0; i < n; i++ {
			if sampleDigest("line", int64(i)) < s {
				kept++
			}
		}
		frac := float64(kept) / float64(n) * 100
		if frac < float64(keep)-1 || frac > float64(keep)+1 {
			t.Fatalf("keep %d%%: measured %.2f%%", keep, frac)
		}
	}
}
