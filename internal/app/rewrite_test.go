package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/analyze"
	"github.com/Bisman-Singh/sievelog/internal/emit"
)

// fakeGrafanaStore keeps objects in memory and records writes and their headers.
type fakeGrafanaStore struct {
	mu        sync.Mutex
	dashboard map[string]any
	rules     map[string]map[string]any
	library   map[string]any
	writes    []string
}

func (f *fakeGrafanaStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/dashboards/uid/d1":
		json.NewEncoder(w).Encode(map[string]any{"dashboard": f.dashboard, "meta": map[string]any{"folderUid": "f"}})
	case r.Method == http.MethodPost && r.URL.Path == "/api/dashboards/db":
		var in struct {
			Dashboard map[string]any `json:"dashboard"`
			Overwrite bool           `json:"overwrite"`
		}
		json.Unmarshal(body, &in)
		if in.Overwrite || in.Dashboard["version"] != f.dashboard["version"] {
			http.Error(w, `{"message":"version-mismatch"}`, http.StatusPreconditionFailed)
			return
		}
		in.Dashboard["version"] = in.Dashboard["version"].(float64) + 1
		f.dashboard = in.Dashboard
		f.writes = append(f.writes, "dashboard")
		w.Write([]byte(`{}`))
	case strings.HasPrefix(r.URL.Path, "/api/v1/provisioning/alert-rules/"):
		uid := strings.TrimPrefix(r.URL.Path, "/api/v1/provisioning/alert-rules/")
		rule := f.rules[uid]
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(rule)
			return
		}
		prov, _ := rule["provenance"].(string)
		sent := ""
		if r.Header.Get("X-Disable-Provenance") == "" {
			sent = "api"
		}
		if prov != sent {
			http.Error(w, `{"messageId":"alerting.provenanceMismatch"}`, http.StatusConflict)
			return
		}
		var in map[string]any
		json.Unmarshal(body, &in)
		f.rules[uid] = in
		f.writes = append(f.writes, "rule:"+uid)
		w.Write([]byte(`{}`))
	case r.URL.Path == "/api/library-elements/lib":
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{"result": f.library})
			return
		}
		var in map[string]any
		json.Unmarshal(body, &in)
		if in["version"] != f.library["version"] {
			http.Error(w, "version", http.StatusPreconditionFailed)
			return
		}
		f.library["model"] = in["model"]
		f.writes = append(f.writes, "library")
		w.Write([]byte(`{}`))
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusTeapot)
	}
}

func expr(e string) map[string]any { return map[string]any{"refId": "A", "expr": e} }

func TestRewritesApplyExactlyOnceAndSafely(t *testing.T) {
	old, nw := `sum(count_over_time({s="a"}[5m]))`, `NEW`
	store := &fakeGrafanaStore{
		dashboard: map[string]any{"uid": "d1", "version": float64(3), "panels": []any{map[string]any{"id": 1, "targets": []any{expr(old), expr("other")}}}},
		rules: map[string]map[string]any{
			"ui":   {"uid": "ui", "provenance": "", "data": []any{map[string]any{"model": expr(old)}}},
			"api":  {"uid": "api", "provenance": "api", "data": []any{map[string]any{"model": expr(old)}}},
			"file": {"uid": "file", "provenance": "file", "data": []any{map[string]any{"model": expr(old)}}},
		},
		library: map[string]any{"name": "l", "kind": float64(1), "version": float64(2), "model": map[string]any{"targets": []any{expr(old)}}},
	}
	srv := httptest.NewServer(store)
	defer srv.Close()
	os.Setenv("SIEVELOG_TEST_PW", "pw")
	c := &Config{Evidence: EvidenceConfig{Grafana: []GrafanaConfig{{URL: srv.URL, Username: "admin", PasswordEnv: "SIEVELOG_TEST_PW"}}}}
	rw := func(path string) analyze.Rewrite {
		return analyze.Rewrite{Source: "grafana", Store: "grafana", StoreURL: srv.URL, Org: 1, Path: path, Old: old, New: nw}
	}
	rf := &RulesFile{Rules: []EnforcedRule{{Rule: emit.Rule{ID: "r", Action: "rollup"}, Rewrites: []analyze.Rewrite{
		rw("dashboard:d1/panel:1/A"), rw("alertrule:ui/0"), rw("alertrule:api/0"), rw("librarypanel:lib/panel:model/A"),
	}}}}
	dir := t.TempDir()
	res, err := Rewrites(context.Background(), c, rf, dir, true, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if !r.Applied || r.Replaced != 1 || r.Err != "" {
			t.Fatalf("%+v", r)
		}
	}
	if rf.RewritesAppliedAt.IsZero() {
		t.Fatal("applied rewrites not recorded")
	}
	b, _ := json.Marshal(store.dashboard)
	if !strings.Contains(string(b), `"NEW"`) || !strings.Contains(string(b), `"other"`) || strings.Contains(string(b), `count_over_time`) {
		t.Fatalf("dashboard: %s", b)
	}
	// Running again changes nothing: every object already holds the new query.
	writes := len(store.writes)
	rf.RewritesAppliedAt = time.Time{}
	res, _ = Rewrites(context.Background(), c, rf, dir, true, time.Unix(200, 0))
	for _, r := range res {
		if !r.Applied || r.Replaced != 0 {
			t.Fatalf("second run: %+v", r)
		}
	}
	if len(store.writes) != writes || rf.RewritesAppliedAt.IsZero() {
		t.Fatalf("second run wrote %v", store.writes[writes:])
	}
	// A file-provisioned rule is refused with the reason, and completion is not recorded.
	rf = &RulesFile{Rules: []EnforcedRule{{Rule: emit.Rule{ID: "r", Action: "rollup"}, Rewrites: []analyze.Rewrite{rw("alertrule:file/0")}}}}
	res, _ = Rewrites(context.Background(), c, rf, dir, true, time.Unix(300, 0))
	if res[0].Applied || !strings.Contains(res[0].Err, "provisioned from file") || !rf.RewritesAppliedAt.IsZero() {
		t.Fatalf("file-provisioned: %+v", res[0])
	}
	// A query that is no longer there is an error, not a silent success.
	rf = &RulesFile{Rules: []EnforcedRule{{Rule: emit.Rule{ID: "r", Action: "rollup"}, Rewrites: []analyze.Rewrite{
		{Store: "grafana", StoreURL: srv.URL, Org: 1, Path: "dashboard:d1/panel:1/A", Old: "gone", New: "x"}}}}}
	res, _ = Rewrites(context.Background(), c, rf, dir, true, time.Unix(400, 0))
	if res[0].Applied || !strings.Contains(res[0].Err, "no longer") {
		t.Fatalf("missing query: %+v", res[0])
	}
	// Without -apply nothing is written.
	store.writes = nil
	store.rules["ui"]["data"] = []any{map[string]any{"model": expr(old)}}
	rf = &RulesFile{Rules: []EnforcedRule{{Rule: emit.Rule{ID: "r", Action: "rollup"}, Rewrites: []analyze.Rewrite{rw("alertrule:ui/0")}}}}
	res, _ = Rewrites(context.Background(), c, rf, dir, false, time.Unix(500, 0))
	if res[0].Applied || len(store.writes) != 0 || res[0].File == "" {
		t.Fatalf("dry run: %+v %v", res[0], store.writes)
	}
}

func TestKeepStreams(t *testing.T) {
	// Two streams; one holds only heartbeat lines.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		n := 2.0
		if strings.Contains(q, "heartbeat") {
			n = 1
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector",
			"result": []any{map[string]any{"metric": map[string]string{}, "value": []any{1, jsonFloat(n)}}}}})
	}))
	defer srv.Close()
	c := &Config{Loki: LokiConfig{URL: srv.URL}, Scope: ScopeConfig{LokiLabel: "service_name"}}
	cand := func(lang string) analyze.Candidate {
		return analyze.Candidate{Service: "svc", Language: lang, StreamLabels: map[string]bool{"service_name": true, "pod": true}}
	}
	recs := []analyze.Recommendation{
		{ID: "hb", Action: "drop", Candidate: cand(`\Aheartbeat\z`), RemovedBytesPerDay: 5},
		{ID: "ok", Action: "sample", Candidate: cand(`\Aother\z`), RemovedBytesPerDay: 5},
		{ID: "dd", Action: "dedupe", Candidate: cand(`\Aheartbeat\z`)},
	}
	if err := c.keepStreams(context.Background(), c.lokiClient(srv.URL), recs, time.Now().Add(-time.Hour), time.Now()); err != nil {
		t.Fatal(err)
	}
	if recs[0].Action != "none" || !strings.Contains(strings.Join(recs[0].Blockers, ";"), "disappear") || recs[0].RemovedBytesPerDay != 0 {
		t.Fatalf("heartbeat rule: %+v", recs[0])
	}
	if recs[1].Action != "sample" || recs[2].Action != "dedupe" {
		t.Fatalf("others must stay: %+v %+v", recs[1], recs[2])
	}
}

func TestReportFiles(t *testing.T) {
	dir := t.TempDir()
	c := &Config{Scope: ScopeConfig{OTelAttribute: "service.name", LokiLabel: "service_name"}}
	rep := &Report{GeneratedAt: time.Unix(0, 0), DrainVersion: "v", Recommendations: []analyze.Recommendation{
		{ID: "r1", Action: "rollup", Candidate: analyze.Candidate{Service: "svc", Template: "t <*>", Language: `\At x\z`},
			Rewrites: []analyze.Rewrite{{Source: "grafana", Origin: "o", Old: "A", New: "B"}}, RemovedBytesPerDay: 10},
		{ID: "r2", Action: "none", Candidate: analyze.Candidate{Service: "svc", Template: "u"}, Blockers: []string{"because"},
			Readers: []analyze.Reader{{Source: "grafana", Origin: "p", Expr: "q", Counting: true, Witness: "w"}}},
	}, Gaps: []analyze.Gap{{Key: "k", Source: "s", Origin: "o", Reason: "r"}}, Notes: []string{"a note"}}
	if err := WriteReport(dir, c, rep); err != nil {
		t.Fatal(err)
	}
	rf, err := LoadRules(dir + "/rules.json")
	if err != nil || len(rf.Rules) != 1 || rf.Rules[0].Action != "rollup" || len(rf.Rules[0].Rewrites) != 1 || rf.DrainConfigHash == "" {
		t.Fatalf("%v %+v", err, rf)
	}
	md, _ := os.ReadFile(dir + "/report.md")
	for _, want := range []string{"`k`", "Blocked: because", "counts e.g. `w`", "to `B`", "a note"} {
		if !strings.Contains(string(md), want) {
			t.Fatalf("report.md lacks %q:\n%s", want, md)
		}
	}
	if err := SaveRules(dir+"/again.json", rf); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(dir + "/missing.json"); err == nil {
		t.Fatal("missing rules file accepted")
	}
}
