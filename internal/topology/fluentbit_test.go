package topology

import (
	"reflect"
	"sort"
	"testing"
)

const fbconf = `
pipeline:
  filters:
    - {name: kubernetes, match: "kube.*", alias: k8s}
    - {name: log_to_metrics, match: "kube.*", alias: counts}
    - {name: rewrite_tag, match: "other.*", alias: unrelated}
  outputs:
    - {name: loki, match: "kube.*", alias: loki}
    - {name: file, match: "*", alias: archive}
    - {name: stdout, match_regex: "^kube\\.app\\..*$", alias: debug}
    - {name: es, match: "audit.*", alias: audit}
`

func TestFluentBitDownstream(t *testing.T) {
	c, err := LoadFluentBit([]byte(fbconf))
	if err != nil {
		t.Fatal(err)
	}
	outs, derived, err := c.FluentBitDownstream("kube.app.*", "k8s")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for id := range outs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if !reflect.DeepEqual(ids, []string{"archive", "debug", "loki"}) {
		t.Fatalf("outputs %v", ids)
	}
	if !reflect.DeepEqual(derived, []string{"counts"}) {
		t.Fatalf("derived %v", derived)
	}
	if _, _, err := c.FluentBitDownstream("kube.*", "missing"); err == nil {
		t.Fatal("unknown alias accepted")
	}
}

// Fluent Bit reads property names case-insensitively (5.1.2 routes an output written
// "Match: app"). Found by the v1 audit: such an output was classed as receiving nothing, so it
// needed no evidence and was never a gap.
func TestFluentBitPropertyNamesIgnoreCase(t *testing.T) {
	c, err := LoadFluentBit([]byte(`
pipeline:
  filters:
    - {Name: kubernetes, Match: "kube.*", Alias: k8s}
    - {Name: Log_To_Metrics, Match: "kube.*", Alias: counts}
  outputs:
    - {Name: file, Match: "*", Alias: archive}
    - {NAME: es, MATCH_REGEX: "^kube\\..*$", ALIAS: search}
    - {name: stdout, alias: nothing}
`))
	if err != nil {
		t.Fatal(err)
	}
	outs, derived, err := c.FluentBitDownstream("kube.app.*", "k8s")
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 2 || outs["archive"] != "file" || outs["search"] != "es" || !reflect.DeepEqual(derived, []string{"counts"}) {
		t.Fatalf("outputs %v, derived %v", outs, derived)
	}
}
