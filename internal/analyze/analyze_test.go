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
	recs, err := Decide([]Candidate{heartbeat, health, declined, cache}, queries, nil, DefaultPolicy())
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
	recs, err := Decide([]Candidate{heartbeat, cache}, []UsageQuery{{Source: "grafana", Origin: "p", Expr: `{service_name="checkout"} | $unknown_syntax`}}, nil, DefaultPolicy())
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
	recs, _ := Decide([]Candidate{heartbeat}, nil, gaps, DefaultPolicy())
	if recs[0].Action != "none" || !strings.Contains(recs[0].Blockers[0], "grafana-query-history") {
		t.Fatalf("%+v", recs[0])
	}
	pol := DefaultPolicy()
	pol.Acknowledged = []string{"grafana-query-history"}
	recs, _ = Decide([]Candidate{heartbeat}, nil, gaps, pol)
	if recs[0].Action != "aggregate" {
		t.Fatalf("%+v", recs[0])
	}
}

func TestActionPreferences(t *testing.T) {
	pol := DefaultPolicy()
	pol.Actions = []string{"dedupe", "sample"}
	recs, _ := Decide([]Candidate{heartbeat, cache}, nil, nil, pol)
	m := byTemplate(recs)
	if r := m[heartbeat.Template]; r.Action != "dedupe" || !r.UpperBound {
		t.Fatalf("constant template: %+v", r)
	}
	if r := m[cache.Template]; r.Action != "sample" || r.Keep != 10 || r.RemovedBytesPerDay != 48000*0.9 {
		t.Fatalf("variable template: %+v", r)
	}
	pol.Actions = []string{"dedupe"}
	recs, _ = Decide([]Candidate{cache}, nil, nil, pol)
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
	recs, _ := Decide([]Candidate{warn, heartbeat}, nil, nil, pol)
	for _, r := range recs {
		if r.Action != "none" {
			t.Fatalf("%+v", r)
		}
	}
	small := health
	small.Bytes = 10
	pol = DefaultPolicy()
	pol.MinDailyBytes = 1000
	recs, _ = Decide([]Candidate{small}, nil, nil, pol)
	if recs[0].Action != "none" {
		t.Fatalf("%+v", recs[0])
	}
}

func TestBadPolicy(t *testing.T) {
	pol := DefaultPolicy()
	pol.Actions = []string{"shred"}
	if _, err := Decide(nil, nil, nil, pol); err == nil {
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
