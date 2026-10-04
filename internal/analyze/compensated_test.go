package analyze

import (
	"testing"
	"time"

	"github.com/Bisman-Singh/zeroreads/internal/rewrite"
)

// A panel zeroreads rewrote for a rollup, then edited to add another raw count of the same lines, reads
// those lines through the added term: a rollup may go ahead only with a new rewrite of that query.
func TestCompensatedTermDoesNotHideOtherSelections(t *testing.T) {
	c := Candidate{Service: "checkout", Scope: map[string]string{"service_name": "checkout"},
		Template: "GET /healthz 200", Language: `\AGET /healthz 200\z`, Lines: 1000, Bytes: 100000,
		Window: 24 * time.Hour, StreamLabels: map[string]bool{"service_name": true}}
	pol := DefaultPolicy()
	pol.Actions = []string{"rollup"}
	orig := `sum(count_over_time({service_name="checkout"} |= "GET" [5m]))`
	res, err := rewrite.Query(orig, []rewrite.Rule{{ID: c.ID(), Language: c.Language, Scope: c.Scope}}, c.StreamLabels)
	if err != nil || !res.Changed {
		t.Fatalf("rewrite: %v %v", err, res.Changed)
	}
	decide := func(expr string) Recommendation {
		q := UsageQuery{Source: "grafana", Origin: "dashboard:d/panel:1/A", Expr: expr, Store: "grafana", Path: "dashboard:d/panel:1/A"}
		recs, err := Decide([]Candidate{c}, []UsageQuery{q}, nil, nil, pol)
		if err != nil {
			t.Fatal(err)
		}
		return recs[0]
	}
	if r := decide(res.Expr); r.Action != "rollup" {
		t.Fatalf("the rewritten query alone should allow the rollup: %s %q", r.Action, r.Blockers)
	}
	edited := res.Expr + ` + sum(count_over_time({service_name="checkout"} |= "healthz" [5m]))`
	r := decide(edited)
	if len(r.Readers) != 1 || r.Readers[0].Compensated {
		t.Fatalf("the edited query should be one reader that is not compensated: %+v", r.Readers)
	}
	if r.Action != "rollup" {
		return
	}
	if len(r.Rewrites) != 1 || r.Rewrites[0].Old != edited || r.Rewrites[0].New == edited {
		t.Fatalf("rolls up without rewriting the added term that counts the raw lines: %+v", r.Rewrites)
	}
}
