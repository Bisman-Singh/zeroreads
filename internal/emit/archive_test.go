package emit

import (
	"context"
	"strings"
	"testing"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.yaml.in/yaml/v3"
)

// archiveConfig is userConfig with an exporter for the archive.
var archiveConfig = strings.Replace(userConfig, "  debug: {}\n", "  debug: {}\n  file/archive: {path: /tmp/archive.json}\n", 1)

func archiveTarget() Target {
	return Target{Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"file/metrics"},
		AggregateExporters: []string{"file/metrics"}, ArchiveExporters: []string{"file/archive"}, DedupeInterval: "300ms"}
}

// withArchive is testRules with the given rules archiving instead.
func withArchive(ids ...string) []Rule {
	rules := append([]Rule(nil), testRules...)
	for i := range rules {
		for _, id := range ids {
			if rules[i].ID == id {
				rules[i].Action = "archive"
			}
		}
	}
	return rules
}

type logsFactory interface {
	Type() component.Type
	CreateDefaultConfig() component.Config
	CreateLogs(context.Context, processor.Settings, component.Config, consumer.Logs) (processor.Logs, error)
}

// processLogs runs one real processor configured from the emitted configuration m and returns what
// it passes on.
func processLogs(t *testing.T, m map[string]any, f logsFactory, name string, in plog.Logs) plog.Logs {
	t.Helper()
	cfg := f.CreateDefaultConfig()
	componentConfig(t, m, "processors", name, cfg)
	sink := new(consumertest.LogsSink)
	p, err := f.CreateLogs(context.Background(), processortest.NewNopSettings(f.Type()), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	defer p.Shutdown(context.Background())
	copied := plog.NewLogs()
	in.CopyTo(copied)
	if err := p.ConsumeLogs(context.Background(), copied); err != nil {
		t.Fatal(err)
	}
	out := plog.NewLogs()
	for _, ld := range sink.AllLogs() {
		ld.ResourceLogs().MoveAndAppendTo(out.ResourceLogs())
	}
	return out
}

// byTime maps each record's timestamp to the rule attribute it carries ("" when none).
func byTime(ld plog.Logs) map[int64]string {
	out := map[int64]string{}
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		sls := ld.ResourceLogs().At(i).ScopeLogs()
		for s := 0; s < sls.Len(); s++ {
			lrs := sls.At(s).LogRecords()
			for j := 0; j < lrs.Len(); j++ {
				rule := ""
				if v, ok := lrs.At(j).Attributes().Get(ArchiveAttr); ok {
					rule = v.AsString()
				}
				out[int64(lrs.At(j).Timestamp())] = rule
			}
		}
	}
	return out
}

// Archived rules' lines leave the enforce path and reach the archive path, each marked with its
// rule, whatever else the rules do; a record at warning or above is never archived; every other
// record meets exactly the fate it meets without the archive. Run on the real transform and filter
// processors built from the emitted configuration.
func TestArchiveSplitsExactly(t *testing.T) {
	archived := []string{"r-health", "r-route"} // a plain-body rule and a field rule
	out, err := Collector([][]byte{[]byte(archiveConfig)}, archiveTarget(), withArchive(archived...), Enforce)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	pipes := m["service"].(map[string]any)["pipelines"].(map[string]any)
	split := pipes["logs/zeroreads"].(map[string]any)
	if p := toStrings(split["processors"].([]any)); p[len(p)-1] != "transform/zeroreads_archive" {
		t.Fatalf("split processors %v: the mark must run last", p)
	}
	arch := pipes["logs/zeroreads_archive"].(map[string]any)
	if strings.Join(toStrings(arch["exporters"].([]any)), ",") != "file/archive" || strings.Join(toStrings(arch["processors"].([]any)), ",") != "filter/zeroreads_archive" {
		t.Fatalf("archive pipeline %v", arch)
	}

	recs := genRecords(3000)
	in := toLogs(recs)
	severe := map[int64]bool{}
	for i := 0; i < in.ResourceLogs().Len(); i++ {
		if i%40 == 0 {
			lr := in.ResourceLogs().At(i).ScopeLogs().At(0).LogRecords().At(0)
			lr.SetSeverityText("ERROR")
			severe[int64(lr.Timestamp())] = true
		}
	}
	marked := processLogs(t, m, transformprocessor.NewFactory(), "transform/zeroreads_archive", in)
	main := byTime(processLogs(t, m, filterprocessor.NewFactory(), "filter/zeroreads", marked))
	toArchive := byTime(processLogs(t, m, filterprocessor.NewFactory(), "filter/zeroreads_archive", marked))

	// The fate of every record without the archive: the same rules minus the archived ones.
	var others []Rule
	for _, r := range testRules {
		if r.ID != archived[0] && r.ID != archived[1] {
			others = append(others, r)
		}
	}
	plain := emittedRules(t, others, Enforce)
	withoutArchive := byTime(processLogs(t, plain, filterprocessor.NewFactory(), "filter/zeroreads", in))

	var nArchived int
	for _, rec := range recs {
		r := matched(rec)
		isArchived := r != nil && (r.ID == archived[0] || r.ID == archived[1]) && !severe[rec.ts]
		rule, inArchive := toArchive[rec.ts]
		_, inMain := main[rec.ts]
		_, keptWithout := withoutArchive[rec.ts]
		switch {
		case isArchived && (!inArchive || rule != r.ID || inMain):
			t.Fatalf("%v: archived by %s, but archive=%v (%q) main=%v", rec, r.ID, inArchive, rule, inMain)
		case !isArchived && inArchive:
			t.Fatalf("%v: archived, but no archive rule applies", rec)
		case !isArchived && inMain != keptWithout:
			t.Fatalf("%v: kept=%v with the archive, %v without", rec, inMain, keptWithout)
		}
		if isArchived {
			nArchived++
		}
	}
	if nArchived < 300 || len(severe) == 0 {
		t.Fatalf("the test has no teeth: %d archived, %d severe", nArchived, len(severe))
	}
}

// Shadow mode measures archive rules like any other and routes nothing.
func TestArchiveShadowRoutesNothing(t *testing.T) {
	out, err := Collector([][]byte{[]byte(archiveConfig)}, archiveTarget(), withArchive("r-health"), Shadow)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(out); strings.Contains(s, "zeroreads_archive") || !strings.Contains(s, MeasureLines("r-health")) {
		t.Fatalf("shadow config:\n%s", s)
	}
}

// An archive must exist, be named, and not be where the lines went anyway.
func TestArchiveRefusals(t *testing.T) {
	rules := withArchive("r-health")
	for name, target := range map[string]Target{
		"no archive exporter":       {Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"file/metrics"}, AggregateExporters: []string{"file/metrics"}},
		"unknown archive exporter":  {Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"file/metrics"}, AggregateExporters: []string{"file/metrics"}, ArchiveExporters: []string{"file/nowhere"}},
		"the pipeline's own export": {Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"file/metrics"}, AggregateExporters: []string{"file/metrics"}, ArchiveExporters: []string{"debug"}},
	} {
		if _, err := Collector([][]byte{[]byte(archiveConfig)}, target, rules, Enforce); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// Vector routes archived events to the archive sinks, besides what those sinks read already, and
// the rest of the chain no longer sees them.
func TestVectorArchive(t *testing.T) {
	// An archive sink that already keeps every raw event: it gains the archived ones.
	cfg := strings.Replace(vectorUnit, "sinks:\n", "sinks:\n  archive: {type: blackhole, inputs: [in]}\n", 1)
	target := vtarget()
	target.ArchiveSinks = []string{"archive"}
	out, err := Vector([][]byte{[]byte(cfg)}, target, withArchive("r-health", "r-route"), Enforce)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	tr, sinks := m["transforms"].(map[string]any), m["sinks"].(map[string]any)
	route := tr[vArchive].(map[string]any)["route"].(map[string]any)["archive"].(string)
	if route != `.zeroreads_rule == "r-health" || .zeroreads_rule == "r-route"` {
		t.Fatalf("route %q", route)
	}
	if in := toStrings(sinks["archive"].(map[string]any)["inputs"].([]any)); strings.Join(in, ",") != "in,"+vArchiveClean {
		t.Fatalf("archive sink inputs %v", in)
	}
	if in := toStrings(tr[vRoute].(map[string]any)["inputs"].([]any)); strings.Join(in, ",") != vArchive+"._unmatched" {
		t.Fatalf("the dedupe route must read what the archive left: %v", in)
	}
	target.ArchiveSinks = nil
	if _, err := Vector([][]byte{[]byte(cfg)}, target, withArchive("r-health"), Enforce); err == nil {
		t.Fatal("archive without a sink accepted")
	}
	target.ArchiveSinks = []string{"nowhere"}
	if _, err := Vector([][]byte{[]byte(cfg)}, target, withArchive("r-health"), Enforce); err == nil {
		t.Fatal("unknown archive sink accepted")
	}
}

// Fluent Bit moves archived records to the archive tag, which exactly the archive outputs receive.
func TestFluentBitArchive(t *testing.T) {
	var rules []Rule
	for _, r := range withArchive("r-health") {
		if r.Action != "dedupe" { // Fluent Bit cannot keep counts
			rules = append(rules, r)
		}
	}
	cfg := strings.Replace(fluentBitUnit, "  outputs:\n", "  outputs:\n    - {name: stdout, alias: archive, match: zeroreads.archive}\n", 1)
	target := fbTarget()
	target.ArchiveOutputs = []string{"archive"}
	out, err := FluentBit([][]byte{[]byte(cfg)}, target, rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(out); !strings.Contains(s, "rewrite_tag") || !strings.Contains(s, `zeroreads.archive false`) {
		t.Fatalf("no archive rewrite:\n%s", s)
	}
	target.ArchiveOutputs = nil
	if _, err := FluentBit([][]byte{[]byte(cfg)}, target, rules, Enforce); err == nil {
		t.Fatal("archive without an output accepted")
	}
	target.ArchiveOutputs = []string{"archive"}
	// The main output taking every tag would keep receiving the archived records.
	everything := strings.Replace(cfg, "{name: stdout, match: app}", "{name: stdout, match: '*'}", 1)
	if _, err := FluentBit([][]byte{[]byte(everything)}, target, rules, Enforce); err == nil {
		t.Fatal("another output receiving the archive tag accepted")
	}
	target.Match = "*"
	if _, err := FluentBit([][]byte{[]byte(cfg)}, target, rules, Enforce); err == nil {
		t.Fatal("rules whose match also takes archived records accepted")
	}
}

// With no rule to enforce, which analysis often concludes, every emitter returns the user's
// configuration unchanged. Found on a real Collector: an empty measurement connector stopped it from
// starting, taking the pipeline down.
func TestNoRulesLeaveTheConfigUnchanged(t *testing.T) {
	same := func(t *testing.T, got []byte, user string) {
		t.Helper()
		var a, b map[string]any
		if err := yaml.Unmarshal(got, &a); err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal([]byte(user), &b); err != nil {
			t.Fatal(err)
		}
		ga, _ := yaml.Marshal(a)
		gb, _ := yaml.Marshal(b)
		if string(ga) != string(gb) {
			t.Fatalf("changed:\n%s\nwant:\n%s", ga, gb)
		}
	}
	for _, mode := range []Mode{Shadow, Enforce} {
		out, err := Collector([][]byte{[]byte(userConfig)}, Target{Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"file/metrics"}}, nil, mode)
		if err != nil {
			t.Fatal(err)
		}
		same(t, out, userConfig)
		out, err = Vector([][]byte{[]byte(vectorUnit)}, vtarget(), nil, mode)
		if err != nil {
			t.Fatal(err)
		}
		same(t, out, vectorUnit)
		out, err = FluentBit([][]byte{[]byte(fluentBitUnit)}, fbTarget(), nil, mode)
		if err != nil {
			t.Fatal(err)
		}
		same(t, out, fluentBitUnit)
	}
}

// A Prometheus exporter keeps running totals of the per-batch deltas and restarts them at nearly every
// batch, so emit refuses it for measurement and for aggregate counters, whose counts it would lose.
func TestMeasurementRefusesTotalKeepingExporters(t *testing.T) {
	cfg := strings.Replace(userConfig, "  debug: {}\n", "  debug: {}\n  prometheus: {endpoint: \"0.0.0.0:8889\"}\n  prometheus/x: {endpoint: \"0.0.0.0:8890\"}\n", 1)
	for _, tg := range []Target{
		{Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"prometheus"}, AggregateExporters: []string{"file/metrics"}},
		{Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"file/metrics"}, AggregateExporters: []string{"prometheus/x"}},
	} {
		if _, err := Collector([][]byte{[]byte(cfg)}, tg, testRules, Shadow); err == nil || !strings.Contains(err.Error(), "delta temporality") {
			t.Fatalf("%+v: %v", tg, err)
		}
	}
	if _, err := Collector([][]byte{[]byte(cfg)}, Target{Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"file/metrics"},
		AggregateExporters: []string{"file/metrics"}}, testRules, Shadow); err != nil {
		t.Fatal(err)
	}
}
