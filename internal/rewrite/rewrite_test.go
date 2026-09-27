package rewrite

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
	"github.com/Bisman-Singh/sievelog/internal/logql"
	"github.com/Bisman-Singh/sievelog/internal/usage"
)

var cache = Rule{ID: "r-cache", Language: `\ADEBUG cache (?:hit|miss) key [0-9a-f]{8}\z`, Scope: map[string]string{"service_name": "checkout"}}

var streams = map[string]bool{"service_name": true, "k8s_namespace_name": true}

func TestRewritableShapes(t *testing.T) {
	for _, c := range []struct {
		expr    string
		changed bool
	}{
		{`sum(count_over_time({service_name="checkout"} |= "cache" [5m]))`, true},
		{`sum(count_over_time({service_name="checkout"} |= "cache" [5m])) > 10`, true},
		{`sum by (k8s_namespace_name) (rate({service_name="checkout"} |~ "DEBUG" [1m] offset 5m))`, true},
		{`sum(count_over_time({service_name="checkout"} [$__interval]))`, true},
		{`sum((count_over_time({service_name="checkout"}[5m])))`, true},
		{`sum(count_over_time({service_name="checkout"} |= "cache" [5m])) by (k8s_namespace_name)`, true},
		// not rewritable
		{`sum(rate({service_name="checkout"} [$__interval]))`, false},                     // rate over an unknown range
		{`sum by (trace_id) (count_over_time({service_name="checkout"} [5m]))`, false},    // not a stream label
		{`sum without (pod) (count_over_time({service_name="checkout"} [5m]))`, false},    // without
		{`count_over_time({service_name="checkout"} |= "cache" [5m])`, false},             // per-series, no sum
		{`sum(bytes_over_time({service_name="checkout"} [5m]))`, false},                   // bytes
		{`sum(count_over_time({service_name="checkout"} |= "cache miss" [5m]))`, false},   // filter keeps only part of the rule
		{`sum(count_over_time({service_name="checkout"} | json [5m]))`, false},            // parser stage
		{`sum(count_over_time({service_name="checkout"} |~ "(?i)cache" [5m]))`, false},    // not exactly modelled
		{`sum(count_over_time({service_name="checkout"} |= "cache" or "x" [5m]))`, true},  // or alternatives
		{`sum(count_over_time({service_name="checkout"} != "hit" [5m]))`, false},          // drops part of the rule
		{`sum(count_over_time({service_name="checkout"} != "ERROR" [5m]))`, true},         // drops none of it
		{`topk(3, sum(count_over_time({service_name="checkout"} [5m])))`, true},           // inner sum still rewritten
		{`sum(count_over_time({service_name="auth"} [5m]))`, false},                       // other service
		{`absent_over_time({service_name="checkout"} |= "cache" [5m])`, false},            // absence
		{`sum(sum_over_time({service_name="checkout"} | logfmt | unwrap x [5m]))`, false}, // unwrap
	} {
		res, err := Query(c.expr, []Rule{cache}, streams)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if res.Changed != c.changed {
			t.Fatalf("%s: changed %v, want %v\n%s", c.expr, res.Changed, c.changed, res.Expr)
		}
		if !res.Changed {
			continue
		}
		q, err := logql.Parse(res.Expr)
		if err != nil {
			t.Fatalf("%s: rewritten query does not parse: %v\n%s", c.expr, err, res.Expr)
		}
		// The rewritten query no longer reads the rule's lines, except the compensated raw term.
		ur := usage.Rule{ID: cache.ID, Scope: cache.Scope, Language: automaton.MustCompile(cache.Language)}
		for _, sel := range q.Selections {
			if usage.Evaluate(sel, ur).Used && !Compensated(q, sel, cache.ID, map[string]string{cache.ID: cache.Language}) {
				t.Fatalf("%s: rewritten query still reads the rule: %+v\n%s", c.expr, sel, res.Expr)
			}
		}
		if !strings.Contains(res.Expr, Marker(cache.ID)) {
			t.Fatalf("no rollup term: %s", res.Expr)
		}
	}
}

func TestCompensatedNeedsTheRollupTerm(t *testing.T) {
	q, _ := logql.Parse("sum(count_over_time({service_name=\"checkout\"} |~ `" + cache.Language + "` [5m]))")
	if Compensated(q, q.Selections[0], cache.ID, map[string]string{cache.ID: cache.Language}) {
		t.Fatal("a bare count of the rule's lines is a real reader")
	}
}

func TestSeconds(t *testing.T) {
	for in, want := range map[string]float64{"5m": 300, "1h30m": 5400, "250ms": 0.25, "1d": 86400} {
		if got, ok := seconds(in); !ok || got != want {
			t.Fatalf("%s: %v %v", in, got, ok)
		}
	}
	if _, ok := seconds("$__interval"); ok {
		t.Fatal("variable parsed")
	}
}

// Rollup records must never be counted as ordinary lines: the rewritten query excludes them from
// its first term, and a query that could select them is detected. Found by an external review.
func TestRollupRecordsNotCountedTwice(t *testing.T) {
	res, err := Query(`sum(count_over_time({service_name="checkout"} != "/healthz" [5m]))`, []Rule{cache}, streams)
	if err != nil || !res.Changed {
		t.Fatalf("%v %+v", err, res)
	}
	q, err := logql.Parse(res.Expr)
	if err != nil {
		t.Fatal(err)
	}
	for _, sel := range q.Selections {
		if ReadsRollups(sel, cache.ID, cache.Scope) {
			t.Fatalf("a term of the rewritten query counts rollup records: %+v\n%s", sel, res.Expr)
		}
	}
	for q, reads := range map[string]bool{
		`sum(count_over_time({service_name="checkout"} != "/healthz" [5m]))`: true,
		`sum(count_over_time({service_name="checkout"} !~ "DEBUG" [5m]))`:    true,
		`{service_name="checkout"} | sievelog_rule=""`:                       false,
		`sum(count_over_time({service_name="checkout"} |= "healthz" [5m]))`:  false,
		`{service_name="auth"}`: false,
	} {
		pq, _ := logql.Parse(q)
		got := false
		for _, sel := range pq.Selections {
			got = got || ReadsRollups(sel, cache.ID, cache.Scope)
		}
		if got != reads {
			t.Fatalf("%s: reads rollups %v, want %v", q, got, reads)
		}
	}
}

// A query read by many rolled-up rules is rewritten once for all of them. Found by the v1 audit:
// the text grew about fourfold per rule, to megabytes at seven rules.
func TestRewriteSizeIsLinear(t *testing.T) {
	var rules []Rule
	size := map[int]int{}
	for n := 1; n <= 12; n++ {
		rules = append(rules, Rule{ID: fmt.Sprintf("r-%012x", n), Language: fmt.Sprintf(`\Aworker %d tick [0-9]+\z`, n), Scope: map[string]string{"service_name": "checkout"}})
		res, err := Query(`sum(count_over_time({service_name="checkout"}[5m]))`, rules, streams)
		if err != nil || !res.Changed || len(res.Rules) != n {
			t.Fatalf("%d rules: %v %+v", n, err, res)
		}
		size[n] = len(res.Expr)
	}
	if per := size[2] - size[1]; size[12] > size[1]+11*per+11 {
		t.Fatalf("rewrite grows faster than linearly: 1 rule %d bytes, 2 rules %d, 12 rules %d", size[1], size[2], size[12])
	}
}

// Before enforcement every line must be counted by exactly one raw-line term (X or Z), or the
// rewritten query's numbers differ from the original. Rules in different scopes can share a
// language (two services with the same health check), and one selector can span both. Found by
// the v1 audit: each rule had its own Z, so such lines were counted once per rule.
func TestEveryLineCountedOnce(t *testing.T) {
	health := `\AGET /healthz\z`
	a := Rule{ID: "r-00000000000a", Language: health, Scope: map[string]string{"service_name": "a"}}
	b := Rule{ID: "r-00000000000b", Language: health, Scope: map[string]string{"service_name": "b"}}
	orders := Rule{ID: "r-00000000000c", Language: `\AGET /orders [0-9]+\z`, Scope: map[string]string{"service_name": "a"}}
	q, err := logql.Parse(`sum(count_over_time({k8s_namespace_name="shop"} |= "GET" [5m]))`)
	if err != nil {
		t.Fatal(err)
	}
	v := q.VectorAggs[0]
	tr, ok := termsFor(v, q.RangeAggs[v.Arg], []Rule{a, b, orders})
	if !ok {
		t.Fatal("not rewritable")
	}
	for _, c := range []struct{ service, line string }{
		{"a", "GET /healthz"}, {"b", "GET /healthz"}, {"c", "GET /healthz"},
		{"a", "GET /orders 7"}, {"b", "GET /orders 7"}, {"a", "GET /cart"},
	} {
		line := usage.Rule{Scope: map[string]string{"service_name": c.service, "k8s_namespace_name": "shop"}, Language: automaton.MustCompile(`\A` + regexp.QuoteMeta(c.line) + `\z`)}
		counted := 0
		for _, term := range []string{tr.x, tr.z} {
			tq, err := logql.Parse(term)
			if err != nil {
				t.Fatalf("%v\n%s", err, term)
			}
			if usage.Evaluate(tq.Selections[0], line).Used {
				counted++
			}
		}
		if counted != 1 {
			t.Fatalf("%q in service %s is counted by %d raw-line terms, want 1\nX: %s\nZ: %s", c.line, c.service, counted, tr.x, tr.z)
		}
	}
	yq, err := logql.Parse(tr.y)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{a.ID, b.ID, orders.ID} {
		if ReadsRollups(yq.Selections[0], id, a.Scope) {
			t.Fatalf("Y is not recognised as %s's rollup term: %s", id, tr.y)
		}
	}
}

// The combined raw-line term is recognised as compensated for each of its rules and for no other,
// and only next to a rollup term for the same rules through the same selector.
func TestCompensatedCombined(t *testing.T) {
	a := Rule{ID: "r-00000000000a", Language: `\Aa [0-9]+\z`, Scope: map[string]string{"service_name": "checkout"}}
	b := Rule{ID: "r-00000000000b", Language: `\Ab [0-9]+\z`, Scope: map[string]string{"service_name": "checkout"}}
	languages := map[string]string{a.ID: a.Language, b.ID: b.Language, "r-00000000000d": `\Ad\z`}
	res, err := Query(`sum(count_over_time({service_name="checkout"}[5m]))`, []Rule{a, b}, streams)
	if err != nil || !res.Changed {
		t.Fatalf("%v %+v", err, res)
	}
	q, err := logql.Parse(res.Expr)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{a.ID: true, b.ID: true, "r-00000000000d": false} {
		got := false
		for _, sel := range q.Selections {
			got = got || Compensated(q, sel, id, languages)
		}
		if got != want {
			t.Fatalf("%s: compensated %v, want %v\n%s", id, got, want, res.Expr)
		}
	}
	// The same raw-line count without the rollup term is a real reader.
	bare, _ := logql.Parse("sum(count_over_time({service_name=\"checkout\"} |~ `" + Alternation([]string{a.Language, b.Language}) + "` [5m]))")
	if Compensated(bare, bare.Selections[0], a.ID, languages) {
		t.Fatal("a bare count of the rules' lines is a real reader")
	}
}

func TestMarkerIDs(t *testing.T) {
	for in, want := range map[string][]string{
		`{s="x"} |= "sievelog rollup r-1"`:                          {"r-1"},
		`{s="x"} |= "sievelog rollup r-1" or "sievelog rollup r-2"`: {"r-1", "r-2"},
		`{s="x"} |= "sievelog rollup r-1" or "other"`:               nil,
		`{s="x"} |= "sievelog rollup "`:                             nil,
		`{s="x"} != "sievelog rollup r-1"`:                          nil,
		`{s="x"} |~ "sievelog rollup r-1"`:                          nil,
	} {
		q, err := logql.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := markerIDs(q.Selections[0].Stages[0]); !slices.Equal(got, want) {
			t.Fatalf("%s: %v, want %v", in, got, want)
		}
	}
}
