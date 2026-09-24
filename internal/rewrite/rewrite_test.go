package rewrite

import (
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
			if usage.Evaluate(sel, ur).Used && !Compensated(q, sel, cache.ID, cache.Language) {
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
	if Compensated(q, q.Selections[0], cache.ID, cache.Language) {
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
