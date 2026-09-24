package analyze

import (
	"strings"
	"testing"
	"time"
)

func cand(svc, tpl, lang string, constant bool) Candidate {
	return Candidate{Service: svc, Scope: map[string]string{"service_name": svc}, Template: tpl, Language: lang,
		Constant: constant, Samples: 100, Lines: 1000, Bytes: 48000, Window: 24 * time.Hour}
}

var (
	heartbeat = cand("checkout", "INFO heartbeat ok", `\AINFO heartbeat ok\z`, true)
	health    = cand("checkout", "INFO GET /healthz 200 <*>", `\AINFO GET /healthz 200 [0-9]{1,3}ms\z`, false)
	declined  = cand("checkout", "ERROR payment <*> declined code <*>", `\AERROR payment pay_[0-9]{6} declined code (?:card_expired|do_not_honor)\z`, false)
	cache     = cand("checkout", "DEBUG cache <*> key <*>", `\ADEBUG cache (?:hit|miss) key [0-9a-f]{8}\z`, false)
)

func byTemplate(recs []Recommendation) map[string]Recommendation {
	m := map[string]Recommendation{}
	for _, r := range recs {
		m[r.Candidate.Template] = r
	}
	return m
}

func TestDecide(t *testing.T) {
	queries := []UsageQuery{
		{Source: "grafana", Origin: "dashboard:x/panel:1", Expr: `{service_name="checkout"} |= "healthz"`},
		{Source: "loki-querylog", Origin: "query-log", Expr: `sum(count_over_time({service_name="auth"}[5m]))`, Count: 3},
	}
	recs, err := Decide([]Candidate{heartbeat, health, declined, cache}, queries, nil, nil, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	m := byTemplate(recs)
	if r := m[health.Template]; r.Action != "none" || len(r.Readers) != 1 || r.Readers[0].Witness == "" {
		t.Fatalf("health: %+v", r)
	}
	if r := m[declined.Template]; r.Action != "none" || !strings.Contains(strings.Join(r.Blockers, ";"), "error-like") {
		t.Fatalf("declined: %+v", r)
	}
	if r := m[heartbeat.Template]; r.Action != "aggregate" || r.RemovedBytesPerDay != 48000 {
		t.Fatalf("heartbeat: %+v", r)
	}
	if r := m[cache.Template]; r.Action != "aggregate" {
		t.Fatalf("cache: %+v", r)
	}
}

func TestUnparsedQueryBlocksEverything(t *testing.T) {
	recs, err := Decide([]Candidate{heartbeat, cache}, []UsageQuery{{Source: "grafana", Origin: "p", Expr: `{service_name="checkout"} | $unknown_syntax`}}, nil, nil, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Action != "none" || len(r.Readers) != 1 || !r.Readers[0].Counting {
			t.Fatalf("%+v", r)
		}
	}
}

func TestGapsBlockUntilAcknowledged(t *testing.T) {
	gaps := []Gap{{Source: "grafana", Origin: "queryhistory", Reason: "other users", Key: "grafana-query-history"}}
	recs, _ := Decide([]Candidate{heartbeat}, nil, nil, gaps, DefaultPolicy())
	if recs[0].Action != "none" || !strings.Contains(recs[0].Blockers[0], "grafana-query-history") {
		t.Fatalf("%+v", recs[0])
	}
	pol := DefaultPolicy()
	pol.Acknowledged = []string{"grafana-query-history"}
	recs, _ = Decide([]Candidate{heartbeat}, nil, nil, gaps, pol)
	if recs[0].Action != "aggregate" {
		t.Fatalf("%+v", recs[0])
	}
}

func TestActionPreferences(t *testing.T) {
	pol := DefaultPolicy()
	pol.Actions = []string{"dedupe", "sample"}
	recs, _ := Decide([]Candidate{heartbeat, cache}, nil, nil, nil, pol)
	m := byTemplate(recs)
	if r := m[heartbeat.Template]; r.Action != "dedupe" || !r.UpperBound {
		t.Fatalf("constant template: %+v", r)
	}
	if r := m[cache.Template]; r.Action != "sample" || r.Keep != 10 || r.RemovedBytesPerDay != 48000*0.9 {
		t.Fatalf("variable template: %+v", r)
	}
	pol.Actions = []string{"dedupe"}
	recs, _ = Decide([]Candidate{cache}, nil, nil, nil, pol)
	if recs[0].Action != "none" || !strings.Contains(strings.Join(recs[0].Blockers, ";"), "no allowed action") {
		t.Fatalf("%+v", recs[0])
	}
}

func TestSeverityExemptAndSize(t *testing.T) {
	warn := cache
	warn.Severities = []string{"info", "WARN"}
	pol := DefaultPolicy()
	pol.Exempt = []string{heartbeat.ID(), `^DEBUG`}
	pol.MinDailyBytes = 1
	recs, _ := Decide([]Candidate{warn, heartbeat}, nil, nil, nil, pol)
	for _, r := range recs {
		if r.Action != "none" {
			t.Fatalf("%+v", r)
		}
	}
	small := health
	small.Bytes = 10
	pol = DefaultPolicy()
	pol.MinDailyBytes = 1000
	recs, _ = Decide([]Candidate{small}, nil, nil, nil, pol)
	if recs[0].Action != "none" {
		t.Fatalf("%+v", recs[0])
	}
}

func TestBadPolicy(t *testing.T) {
	pol := DefaultPolicy()
	pol.Actions = []string{"shred"}
	if _, err := Decide(nil, nil, nil, nil, pol); err == nil {
		t.Fatal("unknown action accepted")
	}
}

func TestIDStable(t *testing.T) {
	a, b := heartbeat, heartbeat
	b.Lines = 5
	if a.ID() != b.ID() {
		t.Fatal("ID depends on volume")
	}
	b.Language = `\Ax\z`
	if a.ID() == b.ID() {
		t.Fatal("ID ignores language")
	}
}

func TestScopedReadersBlockOnlyTheirService(t *testing.T) {
	other := heartbeat
	other.Service = "auth"
	other.Scope = map[string]string{"service_name": "auth"}
	recs, err := Decide([]Candidate{heartbeat, other}, nil, []ScopedReader{{Service: heartbeat.Service, Source: "opensearch", Origin: "audit POST /logs-*/_search", Reason: "targets logs-*"}}, nil, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		blocked := r.Action == "none"
		if blocked != (r.Candidate.Service == heartbeat.Service) {
			t.Fatalf("%s: %+v", r.Candidate.Service, r)
		}
		if blocked && (len(r.Readers) != 1 || !r.Readers[0].Counting || r.Readers[0].Source != "opensearch") {
			t.Fatalf("%+v", r.Readers)
		}
	}
}

func TestRollupRewritesCountingReaders(t *testing.T) {
	pol := DefaultPolicy()
	pol.Actions = []string{"rollup"}
	streams := map[string]bool{"service_name": true}
	c1, c2 := cache, health
	c1.StreamLabels, c2.StreamLabels = streams, streams
	counting := `sum(count_over_time({service_name="checkout"} [5m])) > 100`
	stored := UsageQuery{Source: "grafana", Origin: "g org 1 alertrule:a/0", Store: "grafana", StoreURL: "http://g", Org: 1, Path: "alertrule:a/0", Expr: counting}
	executed := UsageQuery{Source: "loki-querylog", Origin: "query-log (ruler)", Expr: counting, Count: 9}
	recs, err := Decide([]Candidate{c1, c2}, []UsageQuery{stored, executed}, nil, nil, pol)
	if err != nil {
		t.Fatal(err)
	}
	var news []string
	for _, r := range recs {
		if r.Action != "rollup" || len(r.Rewrites) != 2 {
			t.Fatalf("%s: %+v", r.Candidate.Template, r)
		}
		for _, rw := range r.Rewrites {
			news = append(news, rw.New)
		}
	}
	for _, n := range news {
		if n != news[0] || !strings.Contains(n, "sievelog rollup "+recs[0].ID) || !strings.Contains(n, "sievelog rollup "+recs[1].ID) {
			t.Fatalf("one combined rewrite for both rules expected:\n%s", strings.Join(news, "\n"))
		}
	}

	// A reader that shows lines, an ad-hoc executed count, or a store that cannot be written keeps blocking.
	for _, q := range []UsageQuery{
		{Source: "grafana", Origin: "p", Store: "grafana", Path: "dashboard:d/panel:1/A", Expr: `{service_name="checkout"} |= "cache"`},
		{Source: "loki-querylog", Origin: "query-log (frontend)", Expr: `sum(count_over_time({service_name="checkout"} [1m]))`},
		{Source: "grafana", Origin: "p", Store: "grafana", Path: "shorturl:x/left/0", Expr: counting},
		{Source: "grafana", Origin: "p", Store: "grafana", Path: "alertrule:b/0", Expr: `sum(bytes_over_time({service_name="checkout"} [5m]))`},
	} {
		recs, _ := Decide([]Candidate{c1}, []UsageQuery{q}, nil, nil, pol)
		if recs[0].Action != "none" {
			t.Fatalf("%+v must block: %+v", q, recs[0])
		}
	}
	// Structured rules never roll up.
	s := c1
	s.Structured, s.Field = true, "msg"
	recs, _ = Decide([]Candidate{s}, []UsageQuery{stored}, nil, nil, pol)
	if recs[0].Action != "none" {
		t.Fatalf("structured: %+v", recs[0])
	}
	// With no reader, rollup is just the least lossy allowed action.
	recs, _ = Decide([]Candidate{c1}, nil, nil, nil, pol)
	if recs[0].Action != "rollup" || len(recs[0].Rewrites) != 0 {
		t.Fatalf("no reader: %+v", recs[0])
	}
}

func TestCompensatedQueryOnlyAllowsRollup(t *testing.T) {
	c := cache
	c.StreamLabels = map[string]bool{"service_name": true}
	id := c.ID()
	rewritten := "(sum(count_over_time({service_name=\"checkout\"} |= \"DEBUG cache\" !~ `" + c.Language + "` [5m])) + sum(sum_over_time({service_name=\"checkout\"} |= `sievelog rollup " + id +
		"` | sievelog_rule=\"" + id + "\" | unwrap sievelog_dedup_count [5m])) + sum(count_over_time({service_name=\"checkout\"} |~ `" + c.Language + "` [5m])))"
	q := UsageQuery{Source: "loki-querylog", Origin: "query-log", Expr: rewritten}
	pol := DefaultPolicy()
	pol.Actions = []string{"sample"}
	recs, _ := Decide([]Candidate{c}, []UsageQuery{q}, nil, nil, pol)
	if recs[0].Action != "none" || len(recs[0].Readers) != 1 || !recs[0].Readers[0].Compensated {
		t.Fatalf("sample must be blocked by an already rewritten query: %+v", recs[0])
	}
	pol.Actions = []string{"rollup"}
	recs, _ = Decide([]Candidate{c}, []UsageQuery{q}, nil, nil, pol)
	if recs[0].Action != "rollup" || len(recs[0].Rewrites) != 0 {
		t.Fatalf("rollup keeps it, with nothing to rewrite: %+v", recs[0])
	}
}
