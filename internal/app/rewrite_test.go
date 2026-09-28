package app

import (
	"context"
	"encoding/json"
	"github.com/Bisman-Singh/sievelog/internal/pricing"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/source/grafana"

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
	lc, err := c.lokiClient()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.keepStreams(context.Background(), lc, recs, time.Now().Add(-time.Hour), time.Now()); err != nil {
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
	rolled := analyze.Candidate{Service: "svc", Template: "t <*>", Language: `\At x\z`}
	rep := &Report{GeneratedAt: time.Unix(0, 0), DrainVersion: "v", Recommendations: []analyze.Recommendation{
		{ID: rolled.ID(), Action: "rollup", Candidate: rolled,
			Rewrites: []analyze.Rewrite{{Source: "grafana", Origin: "o", Old: `{a="b"}`, New: `{a="c"}`}}, RemovedBytesPerDay: 10},
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
	for _, want := range []string{"`k`", "Blocked: because", "counts e.g. `w`", "to `{a=\"c\"}`", "a note"} {
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

// A Grafana Loki datasource the config does not classify must never hide its queries.
func TestGrafanaDatasourcesFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/orgs":
			w.Write([]byte(`[{"id":1}]`))
		case "/api/datasources":
			w.Write([]byte(`[{"uid":"listed","type":"loki","url":"http://a"},{"uid":"same","type":"loki","url":"http://analysed/"},` +
				`{"uid":"other","type":"loki","url":"http://b"},{"uid":"forgotten","type":"loki","url":"http://c"}]`))
		case "/apis/dashboard.grafana.app/v1/namespaces/default/dashboards":
			w.Write([]byte(`{"items":[{"metadata":{"name":"d"},"spec":{"panels":[` +
				`{"id":1,"datasource":{"uid":"listed"},"targets":[{"refId":"A","expr":"{s=\"listed\"}"}]},` +
				`{"id":2,"datasource":{"uid":"same"},"targets":[{"refId":"A","expr":"{s=\"same\"}"}]},` +
				`{"id":3,"datasource":{"uid":"other"},"targets":[{"refId":"A","expr":"{s=\"other\"}"}]},` +
				`{"id":4,"datasource":{"uid":"forgotten"},"targets":[{"refId":"A","expr":"{s=\"forgotten\"}"}]}]}}]}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	c := &Config{Loki: LokiConfig{URL: "http://analysed"}, Evidence: EvidenceConfig{
		Grafana: []GrafanaConfig{{URL: srv.URL, Datasources: []string{"listed"}, OtherDatasources: []string{"other"}}}}}
	qs, _, gaps := c.evidence(context.Background(), time.Now(), nil, &Report{})
	got := map[string]bool{}
	for _, q := range qs {
		got[q.Expr] = true
	}
	if !got[`{s="listed"}`] || !got[`{s="same"}`] || !got[`{s="forgotten"}`] || got[`{s="other"}`] {
		t.Fatalf("queries %v", got)
	}
	found := false
	for _, g := range gaps {
		if g.Key == "grafana-datasource-unmapped" {
			found = strings.Contains(g.Reason, "forgotten") && !strings.Contains(g.Reason, "same") && !strings.Contains(g.Reason, "listed")
		}
	}
	if !found {
		t.Fatalf("no unmapped gap naming only the forgotten datasource: %+v", gaps)
	}
}

// rules.json is checked on load: whoever edited it, nothing the emitters or verify would act on
// differently from what analyze decided gets through. Found by the v1 audit: it was not checked.
func TestLoadRulesRefusesWhatAnalyzeWouldNotWrite(t *testing.T) {
	dir := t.TempDir()
	c := analyze.Candidate{Service: "svc", Language: `\Ax [0-9]+\z`}
	good := func() map[string]any {
		return map[string]any{"drain_version": "v", "drain_config_hash": "h", "loki_label": "service_name", "rules": []any{map[string]any{
			"ID": c.ID(), "ScopeAttr": "service.name", "ScopeValue": "svc", "Language": c.Language, "Action": "drop", "service": "svc"}}}
	}
	rule := func(m map[string]any) map[string]any { return m["rules"].([]any)[0].(map[string]any) }
	load := func(m map[string]any) error {
		b, _ := json.Marshal(m)
		os.WriteFile(dir+"/rules.json", b, 0o644)
		_, err := LoadRules(dir + "/rules.json")
		return err
	}
	if err := load(good()); err != nil {
		t.Fatal(err)
	}
	for want, edit := range map[string]func(m map[string]any){
		"unknown field":         func(m map[string]any) { m["rulez"] = 1 },
		"not a rules file":      func(m map[string]any) { delete(m, "drain_config_hash") },
		"not a label name":      func(m map[string]any) { m["loki_label"] = "service name" },
		"belong to rule":        func(m map[string]any) { rule(m)["Language"] = `\Ax.*\z` },
		"differ":                func(m map[string]any) { rule(m)["service"] = "other" },
		"keep must be":          func(m map[string]any) { rule(m)["Action"] = "sample" },
		"unknown action":        func(m map[string]any) { rule(m)["Action"] = "delete" },
		"not r- followed":       func(m map[string]any) { rule(m)["ID"] = "r-1 ${env:X}" },
		"only a rollup carries": func(m map[string]any) { rule(m)["rewrites"] = []any{map[string]any{"New": `{a="b"}`}} },
	} {
		m := good()
		edit(m)
		if err := load(m); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: got %v", want, err)
		}
	}
	m := good()
	rule(m)["Action"] = "rollup"
	rule(m)["rewrites"] = []any{map[string]any{"Store": "grafana", "New": `sum(`}}
	if err := load(m); err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Fatalf("unparseable rewrite: %v", err)
	}
	b, _ := json.Marshal(good())
	os.WriteFile(dir+"/rules.json", append(b, []byte(`{}`)...), 0o644)
	if _, err := LoadRules(dir + "/rules.json"); err == nil {
		t.Fatal("trailing data accepted")
	}
}

// A gap about one Grafana object names it, so acknowledging it never accepts another object's gap.
// Found by the v1 audit: grafana-dashboard, once acknowledged, hid every later broken dashboard.
func TestGrafanaGapKeys(t *testing.T) {
	for _, c := range []struct {
		url  string
		gap  grafana.Gap
		want string
	}{
		{"https://grafana.example:3000/", grafana.Gap{Org: 2, Origin: "dashboard:abc/panel:3"}, "grafana-dashboard:grafana.example:3000/org2/dashboard:abc/panel:3"},
		{"http://g", grafana.Gap{Org: 1, Origin: "shorturl:s4"}, "grafana-shorturl:g/org1/shorturl:s4"},
		{"http://g", grafana.Gap{Org: 1, Origin: "alertrules"}, "grafana-alertrules"},
		{"http://g", grafana.Gap{Org: 1, Origin: "dashboards/v1"}, "grafana-dashboards"},
		{"http://g", grafana.Gap{Org: 1, Origin: "queryhistory"}, "grafana-queryhistory"},
	} {
		if got := grafanaGapKey(c.url, c.gap); got != c.want {
			t.Fatalf("%+v: %s, want %s", c.gap, got, c.want)
		}
	}
}

// The ruler's own executions add nothing to its rules once those are read: a current rule is a
// stored reader, a rewritten or deleted one no longer runs. Found by the e2e: the ruler evaluated a
// rewritten rule's old query once after the rewrite was applied (it switches on its next poll), and
// that execution failed verify for the whole evidence window.
func TestRulerExecutionsCoveredByItsRules(t *testing.T) {
	now := time.Now()
	logLine := func(component, query string) []string {
		return []string{strconv.FormatInt(now.Add(-time.Minute).UnixNano(), 10),
			`level=info caller=metrics.go:237 component=` + component + ` org_id=fake query_type=metric query=` + strconv.Quote(query)}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/loki/api/v1/rules":
			w.Write([]byte("rules.yaml:\n  - name: g\n    rules:\n      - record: current\n        expr: sum(rate({service_name=\"checkout\"} |= \"new\" [1m]))\n"))
		case "/loki/api/v1/query_range":
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": []any{
				map[string]any{"stream": map[string]string{"service_name": "loki"}, "values": [][]string{
					logLine("ruler", `sum(rate({service_name="checkout"} |= "old"[1m]))`),
					logLine("ruler", `sum(rate({service_name="checkout"} |= "new"[1m]))`),
					logLine("frontend", `{service_name="checkout"} |= "user"`),
				}}}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &Config{Loki: LokiConfig{URL: srv.URL}, Scope: ScopeConfig{LokiLabel: "service_name"}, Evidence: EvidenceConfig{
		Window: Duration{time.Hour}, Ruler: true, QueryLog: QueryLogConfig{Enabled: true, URL: srv.URL, Selector: `{service_name="loki"}`}}}
	exprs := func() map[string]string {
		qs, _, _ := c.evidence(context.Background(), now, nil, &Report{})
		m := map[string]string{}
		for _, q := range qs {
			m[q.Expr] = q.Source
		}
		return m
	}
	got := exprs()
	if _, ok := got[`sum(rate({service_name="checkout"} |= "old"[1m]))`]; ok || got[`sum(rate({service_name="checkout"} |= "new" [1m]))`] != "loki-ruler" || got[`{service_name="checkout"} |= "user"`] != "loki-querylog" {
		t.Fatalf("with the ruler read: %v", got)
	}
	c.Evidence.Ruler = false
	if got = exprs(); got[`sum(rate({service_name="checkout"} |= "old"[1m]))`] != "loki-querylog" {
		t.Fatalf("without the ruler read, its executions are the only evidence of it: %v", got)
	}
}

// The report states money only at the operator's own prices, in their currency.
func TestReportMoneyAtOwnPrices(t *testing.T) {
	rep := &Report{GeneratedAt: time.Unix(0, 0), RemovedPerDay: 2e9}
	if md := Markdown(rep); strings.Contains(md, "a month at your prices") {
		t.Fatalf("money without a price:\n%s", md)
	}
	rep.Pricing = pricing.Price{PerGB: 0.67, Currency: "INR"}
	rep.MonthlyCost = rep.Pricing.Monthly(rep.RemovedPerDay, 0)
	if md := Markdown(rep); !strings.Contains(md, "about 40.20 INR a month at your prices (0.67 INR per GB") {
		t.Fatalf("report:\n%s", md)
	}
}
