package emit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/signaltometricsconnector"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/logdedupprocessor"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/provider/envprovider"
	"go.opentelemetry.io/collector/confmap/provider/yamlprovider"
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
	extra   map[string]any // extra record fields for runtime tests; "body." keys go inside a map body
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
			out = append(out, record{"checkout", "INFO GET /healthz 200 " + strconv.Itoa(1+r.IntN(900)) + "ms", false, ts, nil})
		case 1:
			out = append(out, record{"checkout", "DEBUG cache " + []string{"hit", "miss"}[r.IntN(2)] + " key " + hex8(r), false, ts, nil})
		case 2:
			out = append(out, record{"checkout", "INFO request " + hex8(r) + hex8(r) + " status 200 took 5ms", false, ts, nil})
		case 3:
			out = append(out, record{"checkout", "INFO heartbeat ok", false, ts, nil})
		case 4:
			out = append(out, record{"orders", "handled route in " + strconv.Itoa(1+r.IntN(900)) + "ms", true, ts, nil})
		case 5:
			out = append(out, record{"orders", "handled route in 5ms", false, ts, nil}) // plain body: the field rule must not apply
		case 6:
			out = append(out, record{"auth", `says "hi" \ bye`, false, ts, nil})
		case 7:
			out = append(out, record{"auth", "INFO GET /healthz 200 5ms", false, ts, nil}) // right text, wrong service
		case 8:
			out = append(out, record{"checkout", "INFO GET /healthz 200 5000ms", false, ts, nil}) // outside the language
		default:
			out = append(out, record{"checkout", "ERROR payment pay_123456 declined", false, ts, nil})
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
	return emittedRules(t, testRules, mode)
}

// emittedRules emits rules and resolves the result exactly as the Collector does before building
// components: ${...} references are expanded and $$ becomes $.
func emittedRules(t *testing.T, rules []Rule, mode Mode) map[string]any {
	t.Helper()
	out, err := Collector([][]byte{[]byte(userConfig)}, Target{Pipeline: "logs", After: "transform/prep",
		MeasureExporters: []string{"file/metrics"}, AggregateExporters: []string{"file/metrics"}, DedupeInterval: "300ms"}, rules, mode)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := confmap.NewResolver(confmap.ResolverSettings{
		URIs:              []string{"yaml:" + string(out)},
		ProviderFactories: []confmap.ProviderFactory{yamlprovider.NewFactory(), envprovider.NewFactory()},
		DefaultScheme:     "env",
	})
	if err != nil {
		t.Fatal(err)
	}
	conf, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("the Collector would not resolve the emitted configuration: %v", err)
	}
	return conf.ToStringMap()
}

// runFilter runs the real filter processor configured from m and returns the records that survive,
// as service and text.
func runFilter(t *testing.T, m map[string]any, recs []record) map[[2]string]bool {
	t.Helper()
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
	if err := proc.ConsumeLogs(context.Background(), toLogs(recs)); err != nil {
		t.Fatal(err)
	}
	survived := map[[2]string]bool{}
	for _, ld := range sink.AllLogs() {
		for i := 0; i < ld.ResourceLogs().Len(); i++ {
			rl := ld.ResourceLogs().At(i)
			svc, _ := rl.Resource().Attributes().Get("service.name")
			lrs := rl.ScopeLogs().At(0).LogRecords()
			for j := 0; j < lrs.Len(); j++ {
				txt, _ := textOf(lrs.At(j))
				survived[[2]string{svc.Str(), txt}] = true
			}
		}
	}
	return survived
}

// Service names come from the logs, and the Collector expands ${...} in its configuration before
// OTTL reads it: every value must stay literal. Found by the v1 audit: a service named
// "svc${env:X}" made the emitted rule read the environment variable X.
func TestCollectorWritesDollarLiterally(t *testing.T) {
	t.Setenv("SIEVELOG_TEST_SECRET", "leaked")
	svc := "svc${env:SIEVELOG_TEST_SECRET}$${SIEVELOG_TEST_SECRET}$HOME"
	text := "cost ${SIEVELOG_TEST_SECRET} $$ ok"
	rules := []Rule{{ID: "r-dollar", ScopeAttr: "service.name", ScopeValue: svc, Language: `\A` + regexp.QuoteMeta(text) + `\z`, Action: "drop"}}
	survived := runFilter(t, emittedRules(t, rules, Enforce), []record{
		{service: svc, text: text, ts: 1},
		{service: "svcleaked$leaked$HOME", text: text, ts: 2},
		{service: svc, text: "cost leaked $$ ok", ts: 3},
		{service: svc, text: "cost leaked $ ok", ts: 4},
	})
	for k, want := range map[[2]string]bool{
		{svc, text}: false, {"svcleaked$leaked$HOME", text}: true, {svc, "cost leaked $$ ok"}: true, {svc, "cost leaked $ ok"}: true,
	} {
		if survived[k] != want {
			t.Fatalf("%q: survived %v, want %v", k, survived[k], want)
		}
	}
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
	// The user's later processors run before measurement, so shadow counts what enforce would see.
	out := pipes["logs/sievelog"].(map[string]any)
	if got, _ := json.Marshal(out); string(got) != `{"exporters":["forward/sievelog_enforce","signal_to_metrics/sievelog"],"processors":["batch"],"receivers":["forward/sievelog"]}` {
		t.Fatalf("measurement pipeline %s", got)
	}
	enf := pipes["logs/sievelog_enforce"].(map[string]any)
	if got, _ := json.Marshal(enf); string(got) != `{"exporters":["debug"],"processors":[],"receivers":["forward/sievelog_enforce"]}` {
		t.Fatalf("shadow enforcement pipeline must be empty: %s", got)
	}
}

func TestOverlappingRulesRejected(t *testing.T) {
	bad := []Rule{
		{ID: "r-a", ScopeAttr: "service.name", ScopeValue: "x", Language: `\Auser [a-z]+ logged in\z`, Action: "drop"},
		{ID: "r-b", ScopeAttr: "service.name", ScopeValue: "x", Language: `\Auser .* logged in\z`, Action: "drop"},
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

// The real transform and logdedup processors, chained as emitted, turn exactly the rollup rule's
// lines into marker records whose counts add up to the lines replaced, whatever attributes the
// lines carried, and leave every other line untouched.
func TestRollupCountsExactly(t *testing.T) {
	rules := append([]Rule(nil), testRules...)
	for i := range rules {
		if rules[i].ID == "r-cache" {
			rules[i].Action = "rollup"
		}
	}
	out, err := Collector([][]byte{[]byte(userConfig)}, Target{Pipeline: "logs", After: "transform/prep",
		MeasureExporters: []string{"file/metrics"}, DedupeInterval: "300ms"}, rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	procs := m["service"].(map[string]any)["pipelines"].(map[string]any)["logs/sievelog_enforce"].(map[string]any)["processors"].([]any)
	if strings.Join(toStrings(procs), ",") != "transform/sievelog_rollup,logdedup/sievelog,filter/sievelog" {
		t.Fatalf("processor order %v", procs)
	}
	df := logdedupprocessor.NewFactory()
	dcfg := df.CreateDefaultConfig()
	componentConfig(t, m, "processors", "logdedup/sievelog", dcfg)
	sink := new(consumertest.LogsSink)
	dedup, err := df.CreateLogs(context.Background(), processortest.NewNopSettings(df.Type()), dcfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	tf := transformprocessor.NewFactory()
	tcfg := tf.CreateDefaultConfig()
	componentConfig(t, m, "processors", "transform/sievelog_rollup", tcfg)
	transform, err := tf.CreateLogs(context.Background(), processortest.NewNopSettings(tf.Type()), tcfg, dedup)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []interface {
		Start(context.Context, component.Host) error
	}{dedup, transform} {
		if err := c.Start(context.Background(), componenttest.NewNopHost()); err != nil {
			t.Fatal(err)
		}
	}
	recs := genRecords(3000)
	ld := toLogs(recs)
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		lr := ld.ResourceLogs().At(i).ScopeLogs().At(0).LogRecords().At(0)
		lr.Attributes().PutStr("trace_id", strconv.Itoa(i)) // would split every group if kept
		lr.SetSeverityText("DEBUG")
	}
	if err := transform.ConsumeLogs(context.Background(), ld); err != nil {
		t.Fatal(err)
	}
	time.Sleep(900 * time.Millisecond)
	transform.Shutdown(context.Background())
	dedup.Shutdown(context.Background())
	var rolled, rollRecords int64
	others := map[string]int{}
	for _, ld := range sink.AllLogs() {
		for i := 0; i < ld.ResourceLogs().Len(); i++ {
			rl := ld.ResourceLogs().At(i)
			sls := rl.ScopeLogs()
			for s := 0; s < sls.Len(); s++ {
				lrs := sls.At(s).LogRecords()
				for j := 0; j < lrs.Len(); j++ {
					lr := lrs.At(j)
					txt, _ := textOf(lr)
					if txt == RollupMarker("r-cache") {
						rollRecords++
						c, _ := lr.Attributes().Get(DedupCounter)
						rule, _ := lr.Attributes().Get(RuleAttr)
						svc, _ := rl.Resource().Attributes().Get("service.name")
						if rule.Str() != "r-cache" || svc.Str() != "checkout" {
							t.Fatalf("rollup record attributes %v resource %v", lr.Attributes().AsRaw(), rl.Resource().Attributes().AsRaw())
						}
						if _, kept := lr.Attributes().Get("trace_id"); kept {
							t.Fatal("rollup kept the line's attributes")
						}
						rolled += c.Int()
						continue
					}
					if strings.HasPrefix(txt, "DEBUG cache") {
						t.Fatalf("a cache line survived rollup: %q", txt)
					}
					others[txt]++
				}
			}
		}
	}
	var want int64
	wantOthers := map[string]int{}
	for _, rec := range recs {
		if r := matched(rec); r != nil && r.ID == "r-cache" {
			want++
		} else if r == nil || r.Action != "dedupe" {
			wantOthers[rec.text]++
		}
	}
	if rolled != want || rollRecords == 0 || rollRecords >= want {
		t.Fatalf("rollup: %d records carrying %d lines, want %d lines in fewer records", rollRecords, rolled, want)
	}
	for txt, n := range wantOthers {
		if others[txt] != n {
			t.Fatalf("line %q: %d after rollup, want %d untouched", txt, others[txt], n)
		}
	}
	t.Logf("rollup: %d cache lines became %d records with exact counts; every other line untouched", want, rollRecords)
}

func toStrings(v []any) []string {
	var out []string
	for _, x := range v {
		out = append(out, x.(string))
	}
	return out
}

// The runtime severity guard, with the real filter processor and signal_to_metrics connector: a
// record in a drop rule's language is kept, and not counted, when any level says warning or worse.
func TestSeverityGuard(t *testing.T) {
	rules := []Rule{
		{ID: "r-plain", ScopeAttr: "service.name", ScopeValue: "checkout", Language: `\AINFO heartbeat ok\z`, Action: "drop"},
		{ID: "r-field", ScopeAttr: "service.name", ScopeValue: "orders", Language: `\Ahandled route in 5ms\z`, Field: "msg", Action: "drop"},
	}
	out, err := Collector([][]byte{[]byte(userConfig)}, Target{Pipeline: "logs", After: "transform/prep",
		MeasureExporters: []string{"file/metrics"}}, rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	yaml.Unmarshal(out, &m)
	type rec struct {
		name    string
		svc     string
		setup   func(lr plog.LogRecord)
		removed bool
	}
	plain := func(f func(lr plog.LogRecord)) func(lr plog.LogRecord) {
		return func(lr plog.LogRecord) { lr.Body().SetStr("INFO heartbeat ok"); f(lr) }
	}
	field := func(f func(bm pcommon.Map)) func(lr plog.LogRecord) {
		return func(lr plog.LogRecord) {
			bm := lr.Body().SetEmptyMap()
			bm.PutStr("msg", "handled route in 5ms")
			f(bm)
		}
	}
	cases := []rec{
		{"no level", "checkout", plain(func(plog.LogRecord) {}), true},
		{"info number", "checkout", plain(func(lr plog.LogRecord) { lr.SetSeverityNumber(plog.SeverityNumberInfo) }), true},
		{"warn number", "checkout", plain(func(lr plog.LogRecord) { lr.SetSeverityNumber(plog.SeverityNumberWarn) }), false},
		{"fatal number", "checkout", plain(func(lr plog.LogRecord) { lr.SetSeverityNumber(plog.SeverityNumberFatal4) }), false},
		{"error text", "checkout", plain(func(lr plog.LogRecord) { lr.SetSeverityText("Error") }), false},
		{"info text", "checkout", plain(func(lr plog.LogRecord) { lr.SetSeverityText("INFO") }), true},
		{"level attribute", "checkout", plain(func(lr plog.LogRecord) { lr.Attributes().PutStr("level", "WARNING") }), false},
		{"severity attribute", "checkout", plain(func(lr plog.LogRecord) { lr.Attributes().PutStr("severity", " critical") }), false},
		{"debug attribute", "checkout", plain(func(lr plog.LogRecord) { lr.Attributes().PutStr("level", "debug") }), true},
		{"numeric attribute", "checkout", plain(func(lr plog.LogRecord) { lr.Attributes().PutInt("level", 50) }), true},
		{"body level", "orders", field(func(bm pcommon.Map) { bm.PutStr("level", "error") }), false},
		{"body info", "orders", field(func(bm pcommon.Map) { bm.PutStr("level", "info") }), true},
		{"body without level", "orders", field(func(pcommon.Map) {}), true},
	}
	ld := plog.NewLogs()
	for i, c := range cases {
		rl := ld.ResourceLogs().AppendEmpty()
		rl.Resource().Attributes().PutStr("service.name", c.svc)
		lr := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
		lr.Attributes().PutInt("case", int64(i))
		c.setup(lr)
	}
	f := filterprocessor.NewFactory()
	cfg := f.CreateDefaultConfig()
	componentConfig(t, m, "processors", "filter/sievelog", cfg)
	sink := new(consumertest.LogsSink)
	proc, err := f.CreateLogs(context.Background(), processortest.NewNopSettings(f.Type()), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	proc.Start(context.Background(), componenttest.NewNopHost())
	defer proc.Shutdown(context.Background())
	in := plog.NewLogs()
	ld.CopyTo(in)
	if err := proc.ConsumeLogs(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	kept := map[int64]bool{}
	for _, out := range sink.AllLogs() {
		for i := 0; i < out.ResourceLogs().Len(); i++ {
			lrs := out.ResourceLogs().At(i).ScopeLogs().At(0).LogRecords()
			for j := 0; j < lrs.Len(); j++ {
				v, _ := lrs.At(j).Attributes().Get("case")
				kept[v.Int()] = true
			}
		}
	}
	measured := measureRules(t, m, ld)
	for i, c := range cases {
		if kept[int64(i)] == c.removed {
			t.Fatalf("%s: kept=%v, want removed=%v", c.name, kept[int64(i)], c.removed)
		}
	}
	var wantPlain, wantField int
	for _, c := range cases {
		if c.removed && c.svc == "checkout" {
			wantPlain++
		}
		if c.removed && c.svc == "orders" {
			wantField++
		}
	}
	if measured["r-plain"] != wantPlain || measured["r-field"] != wantField {
		t.Fatalf("measured %v, want r-plain %d, r-field %d: shadow numbers must match what enforcement removes", measured, wantPlain, wantField)
	}
}

// measureRules runs the emitted signal_to_metrics connector and returns lines counted per rule.
func measureRules(t *testing.T, m map[string]any, ld plog.Logs) map[string]int {
	t.Helper()
	f := signaltometricsconnector.NewFactory()
	cfg := f.CreateDefaultConfig()
	componentConfig(t, m, "connectors", "signal_to_metrics/sievelog", cfg)
	sink := new(consumertest.MetricsSink)
	conn, err := f.CreateLogsToMetrics(context.Background(), connectortest.NewNopSettings(f.Type()), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	conn.Start(context.Background(), componenttest.NewNopHost())
	defer conn.Shutdown(context.Background())
	in := plog.NewLogs()
	ld.CopyTo(in)
	if err := conn.ConsumeLogs(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, md := range sink.AllMetrics() {
		rms := md.ResourceMetrics()
		for i := 0; i < rms.Len(); i++ {
			sms := rms.At(i).ScopeMetrics()
			for j := 0; j < sms.Len(); j++ {
				ms := sms.At(j).Metrics()
				for k := 0; k < ms.Len(); k++ {
					mt := ms.At(k)
					if !strings.HasPrefix(mt.Name(), "sievelog.rule.lines.") {
						continue
					}
					dps := mt.Sum().DataPoints()
					for d := 0; d < dps.Len(); d++ {
						out[strings.TrimPrefix(mt.Name(), "sievelog.rule.lines.")] += int(dps.At(d).IntValue() + int64(dps.At(d).DoubleValue()))
					}
				}
			}
		}
	}
	return out
}

// A record without a timestamp is sampled by its observed time, exactly and independently.
func TestSampleUntimedRecords(t *testing.T) {
	rules := []Rule{{ID: "r-s", ScopeAttr: "service.name", ScopeValue: "checkout", Language: `\AINFO heartbeat ok\z`, Action: "sample", Keep: 30}}
	out, err := Collector([][]byte{[]byte(userConfig)}, Target{Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"file/metrics"}}, rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	yaml.Unmarshal(out, &m)
	f := filterprocessor.NewFactory()
	cfg := f.CreateDefaultConfig()
	componentConfig(t, m, "processors", "filter/sievelog", cfg)
	sink := new(consumertest.LogsSink)
	proc, err := f.CreateLogs(context.Background(), processortest.NewNopSettings(f.Type()), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	proc.Start(context.Background(), componenttest.NewNopHost())
	defer proc.Shutdown(context.Background())
	ld := plog.NewLogs()
	lrs := ld.ResourceLogs().AppendEmpty()
	lrs.Resource().Attributes().PutStr("service.name", "checkout")
	recs := lrs.ScopeLogs().AppendEmpty().LogRecords()
	const n = 4000
	for i := 0; i < n; i++ {
		lr := recs.AppendEmpty()
		lr.Body().SetStr("INFO heartbeat ok")
		lr.SetObservedTimestamp(pcommon.Timestamp(1790000000000000000 + int64(i)*997))
		lr.Attributes().PutInt("i", int64(i))
	}
	if err := proc.ConsumeLogs(context.Background(), ld); err != nil {
		t.Fatal(err)
	}
	kept := map[int64]bool{}
	for _, out := range sink.AllLogs() {
		l := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
		for j := 0; j < l.Len(); j++ {
			v, _ := l.At(j).Attributes().Get("i")
			kept[v.Int()] = true
		}
	}
	for i := 0; i < n; i++ {
		want := sampleDigest("INFO heartbeat ok", 1790000000000000000+int64(i)*997) < SampleThreshold(30)
		if kept[int64(i)] != want {
			t.Fatalf("record %d: kept=%v want %v", i, kept[int64(i)], want)
		}
	}
	if frac := float64(len(kept)) / n; frac < 0.25 || frac > 0.35 {
		t.Fatalf("untimed records kept %.3f, want about 0.30", frac)
	}
}

// Every emitter refuses a rule it cannot write safely, whoever wrote the rules file.
func TestCheckRules(t *testing.T) {
	ok := Rule{ID: "r-0123456789ab", ScopeAttr: "service.name", ScopeValue: "x", Language: `\Aa\z`, Action: "drop"}
	with := func(f func(r *Rule)) []Rule {
		r := ok
		f(&r)
		return []Rule{r}
	}
	if err := CheckRules([]Rule{ok}); err != nil {
		t.Fatal(err)
	}
	for want, rules := range map[string][]Rule{
		"rule ID":         with(func(r *Rule) { r.ID = "r-1 ${env:ARCHIVE_SECRET}" }),
		"rule ID \"R-1\"": with(func(r *Rule) { r.ID = "R-1" }),
		"rule ID \"r-\"":  with(func(r *Rule) { r.ID = "r-" }),
		"appears twice":   {ok, ok},
		"unknown action":  with(func(r *Rule) { r.Action = "teleport" }),
		"keep must be":    with(func(r *Rule) { r.Action, r.Keep = "sample", 0 }),
		"plain lines":     with(func(r *Rule) { r.Action, r.Field = "rollup", "msg" }),
		"language":        with(func(r *Rule) { r.Language = `(` }),
	} {
		if err := CheckRules(rules); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: got %v", want, err)
		}
	}
	sample := with(func(r *Rule) { r.Action, r.Keep = "sample", 100 })
	if err := CheckRules(sample); err == nil {
		t.Fatal("keep 100 accepted")
	}
}

// Configured level fields add to the defaults. Found by the v1 audit: the documented
// "severity_paths: []" decodes as an empty list, not nil, and turned the level-field guard off.
func TestSeverityGuardKeepsDefaults(t *testing.T) {
	r := Rule{ID: "r-x", ScopeAttr: "service.name", ScopeValue: "a", Language: `\Ax\z`, Field: "msg"}
	for _, configured := range [][]string{nil, {}, {"custom"}} {
		cond := r.GuardedCondition(configured)
		for _, k := range append(defaultSeverityKeys(), configured...) {
			if !strings.Contains(cond, `log.attributes["`+k+`"]`) || !strings.Contains(cond, `log.body["`+k+`"]`) {
				t.Fatalf("configured %v: %s is not guarded:\n%s", configured, k, cond)
			}
		}
	}
	for _, configured := range [][]string{nil, {}, {".custom"}} {
		paths := VectorTarget{FieldPaths: map[string]string{"orders": ".body.msg"}, SeverityPaths: configured}.severityPaths()
		for _, want := range append([]string{".level", ".body.level", ".\"log.level\""}, configured...) {
			if !slices.Contains(paths, want) {
				t.Fatalf("vector, configured %v: %s missing from %v", configured, want, paths)
			}
		}
	}
	for _, configured := range [][][]string{nil, {}, {{"custom"}}} {
		keys := FluentBitTarget{FieldKeys: map[string][]string{"orders": {"body", "msg"}}, SeverityKeys: configured}.severityKeys()
		for _, want := range append([][]string{{"level"}, {"body", "level"}}, configured...) {
			if !slices.ContainsFunc(keys, func(k []string) bool { return slices.Equal(k, want) }) {
				t.Fatalf("fluent bit, configured %v: %v missing from %v", configured, want, keys)
			}
		}
	}
}
