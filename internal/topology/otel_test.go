package topology

import (
	"reflect"
	"sort"
	"testing"
)

const base = `
receivers:
  file_log: {}
  otlp: {}
processors:
  transform/prep: {}
  drain: {}
  batch: {}
exporters:
  otlp_http/loki: {endpoint: http://loki:3100/otlp}
  file/archive: {path: /tmp/a.json}
  kafka/siem: {}
  otlp_grpc/gateway: {endpoint: gateway:4317}
  file/metrics: {}
connectors:
  signal_to_metrics: {}
  routing: {}
service:
  pipelines:
    logs:
      receivers: [file_log, otlp]
      processors: [transform/prep, drain, batch]
      exporters: [otlp_http/loki, routing, signal_to_metrics]
    logs/archive:
      receivers: [routing]
      exporters: [file/archive, kafka/siem]
    logs/fwd:
      receivers: [routing]
      processors: [batch]
      exporters: [otlp_grpc/gateway]
    metrics:
      receivers: [signal_to_metrics]
      exporters: [file/metrics]
`

func TestDownstreamFollowsConnectors(t *testing.T) {
	c, err := Load([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Downstream("logs", 1)
	if err != nil {
		t.Fatal(err)
	}
	var exps []string
	for e := range r.Exporters {
		exps = append(exps, e)
	}
	sort.Strings(exps)
	want := []string{"file/archive", "file/metrics", "kafka/siem", "otlp_grpc/gateway", "otlp_http/loki"}
	if !reflect.DeepEqual(exps, want) {
		t.Fatalf("exporters %v, want %v", exps, want)
	}
	if !reflect.DeepEqual(r.Derived, []string{"signal_to_metrics"}) {
		t.Fatalf("derived %v", r.Derived)
	}
	if got := r.Exporters["kafka/siem"]; len(got) != 2 {
		t.Fatalf("path to kafka/siem %v", got)
	}
}

// Later files win and lists are replaced, as the collector merges repeated --config files.
func TestMerge(t *testing.T) {
	override := `
exporters:
  otlp_http/loki: {endpoint: http://other:3100/otlp}
service:
  pipelines:
    logs:
      exporters: [otlp_http/loki]
`
	c, err := Load([]byte(base), []byte(override))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Pipelines["logs"].Exporters; !reflect.DeepEqual(got, []string{"otlp_http/loki"}) {
		t.Fatalf("list not replaced: %v", got)
	}
	if got := c.Pipelines["logs"].Receivers; len(got) != 2 {
		t.Fatalf("receivers lost in merge: %v", got)
	}
	if ep := c.Exporters["otlp_http/loki"].(map[string]any)["endpoint"]; ep != "http://other:3100/otlp" {
		t.Fatalf("endpoint %v", ep)
	}
	r, _ := c.Downstream("logs", 2)
	if len(r.Exporters) != 1 {
		t.Fatalf("exporters %v", r.Exporters)
	}
}

func TestUndefinedComponentsRejected(t *testing.T) {
	bad := `
receivers: {otlp: {}}
exporters: {debug: {}}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [missing]
      exporters: [debug]
`
	if _, err := Load([]byte(bad)); err == nil {
		t.Fatal("undefined processor accepted")
	}
}

func TestCycleTerminates(t *testing.T) {
	cyc := `
receivers: {otlp: {}}
exporters: {debug: {}}
connectors: {forward/a: {}, forward/b: {}}
service:
  pipelines:
    logs/a: {receivers: [otlp, forward/b], exporters: [forward/a]}
    logs/b: {receivers: [forward/a], exporters: [forward/b, debug]}
`
	c, err := Load([]byte(cyc))
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Downstream("logs/a", -1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Exporters["debug"]; !ok || len(r.Derived) != 0 {
		t.Fatalf("%+v", r)
	}
}
