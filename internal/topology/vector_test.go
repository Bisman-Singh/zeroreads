package topology

import (
	"reflect"
	"sort"
	"testing"
)

const vbase = `
sources:
  k8s: {type: kubernetes_logs}
transforms:
  prep: {type: remap, inputs: [k8s], source: "."}
  split: {type: route, inputs: [prep], route: {errors: "true"}}
  counts: {type: log_to_metric, inputs: [prep], metrics: []}
  late_a: {type: remap, inputs: ["split.errors"], source: "."}
sinks:
  loki: {type: loki, inputs: [prep]}
  archive: {type: file, inputs: ["late_*"]}
  prom: {type: prometheus_exporter, inputs: [counts]}
  raw: {type: file, inputs: [k8s]}
`

func TestVectorDownstream(t *testing.T) {
	c, err := LoadVector([]byte(vbase))
	if err != nil {
		t.Fatal(err)
	}
	sinks, derived, err := c.VectorDownstream("prep")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for id := range sinks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if !reflect.DeepEqual(ids, []string{"archive", "loki", "prom"}) {
		t.Fatalf("sinks %v", ids)
	}
	if !reflect.DeepEqual(derived, []string{"counts"}) {
		t.Fatalf("derived %v", derived)
	}
	if _, ok := sinks["raw"]; ok {
		t.Fatal("a sink reading the source directly is not downstream of prep")
	}
}

func TestVectorUnknownComponent(t *testing.T) {
	c, _ := LoadVector([]byte(vbase))
	if _, _, err := c.VectorDownstream("nope"); err == nil {
		t.Fatal("unknown component accepted")
	}
}
