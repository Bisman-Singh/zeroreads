//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/app"
	"github.com/Bisman-Singh/sievelog/internal/emit"
	"github.com/Bisman-Singh/sievelog/internal/source/opensearch"
	"github.com/Bisman-Singh/sievelog/internal/templating"
)

var osHTTP = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

// osCall performs one call on the throwaway e2e OpenSearch. Setup calls are tagged like the
// analyzer's own requests so they never count as usage; untagged calls play a user.
func osCall(t *testing.T, user, pass, method, path string, body any, tagged bool) (int, []byte) {
	t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		r = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		r = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, os.Getenv("OPENSEARCH_URL")+path, r)
	req.SetBasicAuth(user, pass)
	req.Header.Set("Content-Type", "application/json")
	if tagged {
		req.Header.Set(opensearch.Header, "1")
	}
	resp, err := osHTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func osAdmin(t *testing.T, method, path string, body any) []byte {
	t.Helper()
	code, out := osCall(t, "admin", os.Getenv("OPENSEARCH_PASSWORD"), method, path, body, true)
	if code/100 != 2 {
		t.Fatalf("%s %s: %d %s", method, path, code, out)
	}
	return out
}

func osUser(t *testing.T, method, path string, body any) {
	t.Helper()
	code, out := osCall(t, "admin", os.Getenv("OPENSEARCH_PASSWORD"), method, path, body, false)
	if code/100 != 2 {
		t.Fatalf("user %s %s: %d %s", method, path, code, out)
	}
}

func auditConfig(disabled []string, ignoreUsers []string) map[string]any {
	return map[string]any{"enabled": true, "audit": map[string]any{
		"enable_rest": true, "disabled_rest_categories": disabled, "enable_transport": false, "disabled_transport_categories": []string{},
		"resolve_indices": true, "log_request_body": true, "resolve_bulk_requests": false, "exclude_sensitive_headers": true,
		"ignore_users": ignoreUsers, "ignore_requests": []string{}, "ignore_headers": []string{}, "ignore_url_params": []string{},
	}, "compliance": map[string]any{"enabled": false, "internal_config": false, "external_config": false, "read_metadata_only": true,
		"write_metadata_only": true, "write_log_diffs": false, "read_watched_fields": map[string]any{}, "read_ignore_users": []string{},
		"write_watched_indices": []string{}, "write_ignore_users": []string{}}}
}

func gapSet(gs []opensearch.Gap) map[string]string {
	m := map[string]string{}
	for _, g := range gs {
		m[g.Key] = g.Reason
	}
	return m
}

func TestOpenSearchEvidence(t *testing.T) {
	if os.Getenv("OPENSEARCH_URL") == "" {
		t.Fatal("OPENSEARCH_URL is not set")
	}
	ctx := context.Background()
	var left []struct {
		Index string `json:"index"`
	}
	json.Unmarshal(osAdmin(t, "GET", "/_cat/indices/e2e-*,.kibana_e2e-*?format=json&expand_wildcards=all", nil), &left)
	for _, l := range left {
		osAdmin(t, "DELETE", "/"+l.Index, nil) // left behind by an interrupted run
	}
	n := fmt.Sprintf("e2e-%d", time.Now().UnixNano())
	logs, alias, text, missing, multi, extra := n+"-logs", n+"-alias", n+"-text", n+"-missing", n+"-multi", n+"-extra"
	kw := map[string]any{"mappings": map[string]any{"properties": map[string]any{"service": map[string]any{"properties": map[string]any{"name": map[string]any{"type": "keyword"}}}}}}
	for _, i := range []string{logs, missing, multi, extra} {
		osAdmin(t, "PUT", "/"+i, kw)
	}
	osAdmin(t, "PUT", "/"+text, map[string]any{"mappings": map[string]any{"properties": map[string]any{"service": map[string]any{"properties": map[string]any{"name": map[string]any{"type": "text"}}}}}})
	// logs holds checkout and auth; extra holds more auth. The other indices hold only billing, so
	// they exercise the unsound-term cases without putting checkout or auth outside their scopes.
	doc := func(index, svc string) string {
		if svc == "" {
			return fmt.Sprintf("{\"index\":{\"_index\":%q}}\n{\"body\":\"no service\"}\n", index)
		}
		return fmt.Sprintf("{\"index\":{\"_index\":%q}}\n{\"service\":{\"name\":%s},\"body\":\"line 1\"}\n", index, svc)
	}
	bulk := ""
	for i := 0; i < 5; i++ {
		bulk += doc(logs, `"checkout"`) + doc(logs, `"auth"`) + doc(text, `"billing"`)
	}
	bulk += doc(missing, `"billing"`) + doc(missing, "") + doc(multi, `["billing","payments"]`) + doc(extra, `"auth"`)
	osAdmin(t, "POST", "/_bulk?refresh=true", bulk)
	osAdmin(t, "POST", "/_aliases", map[string]any{"actions": []any{map[string]any{"add": map[string]any{"index": logs, "alias": alias}}}})
	defer osAdmin(t, "DELETE", "/"+strings.Join([]string{logs, text, missing, multi, extra}, ","), nil)

	cl := &opensearch.Client{Base: os.Getenv("OPENSEARCH_URL"), Username: "admin", Password: os.Getenv("OPENSEARCH_PASSWORD"), InsecureSkipVerify: true}
	reader := func(prove bool, timeout time.Duration) *opensearch.Reader {
		return &opensearch.Reader{C: cl, AuditIndex: "security-auditlog-*", DashboardsIndex: ".kibana_" + n, ProveLive: prove, ProveTimeout: timeout}
	}
	defer osAdmin(t, "PUT", "/_plugins/_security/api/audit/config", auditConfig([]string{"GRANTED_PRIVILEGES"}, []string{"kibanaserver"}))

	t.Run("audit off is detected", func(t *testing.T) {
		// The security plugin's shipped default: successful REST requests are not logged.
		osAdmin(t, "PUT", "/_plugins/_security/api/audit/config", auditConfig([]string{"AUTHENTICATED", "GRANTED_PRIVILEGES"}, []string{"kibanaserver"}))
		res := reader(true, 20*time.Second).Read(ctx, time.Now().Add(-time.Hour), time.Now())
		g := gapSet(res.Gaps)
		for _, k := range []string{"opensearch-audit-disabled", "opensearch-audit-not-live", "opensearch-audit-ignored-users"} {
			if _, ok := g[k]; !ok {
				t.Fatalf("missing gap %s: %v", k, g)
			}
		}
	})

	osAdmin(t, "PUT", "/_plugins/_security/api/audit/config", auditConfig([]string{"GRANTED_PRIVILEGES"}, []string{}))
	t.Run("audit on is proven live", func(t *testing.T) {
		res := reader(true, 60*time.Second).Read(ctx, time.Now().Add(-time.Hour), time.Now())
		g := gapSet(res.Gaps)
		for _, k := range []string{"opensearch-audit-disabled", "opensearch-audit-not-live", "opensearch-audit-ignored-users", "opensearch-audit-config-unreadable", "opensearch-audit-unreadable"} {
			if r, ok := g[k]; ok {
				t.Fatalf("unexpected gap %s: %s", k, r)
			}
		}
	})

	// A user without privileges.
	osAdmin(t, "PUT", "/_plugins/_security/api/internalusers/"+n, map[string]any{"password": "E2e-only-Noperm-1!", "backend_roles": []string{}})
	defer osAdmin(t, "DELETE", "/_plugins/_security/api/internalusers/"+n, nil)

	start := time.Now().Add(-time.Second)
	search := func(path string, q any) {
		osUser(t, "POST", path, map[string]any{"query": q})
	}
	term := func(v string) any { return map[string]any{"term": map[string]any{"service.name": v}} }
	search("/"+logs+"/_search", term("auth"))                                                                           // reads auth only
	search("/"+n+"-*/_search", map[string]any{"bool": map[string]any{"must_not": []any{term("checkout")}}})             // reads auth, and docs without a service
	search("/"+alias+"/_search", map[string]any{"match": map[string]any{"service.name": "checkout"}})                   // full text: reads both
	osUser(t, "POST", "/"+logs+"/_search?q=service.name:auth", map[string]any{"query": term("auth")})                   // the q parameter wins: opaque
	osUser(t, "POST", "/_plugins/_ppl", map[string]any{"query": "source=" + logs + " | where `service.name` = 'auth'"}) // not interpreted
	osUser(t, "POST", "/"+n+"-nothing/_search?ignore_unavailable=true", map[string]any{"query": map[string]any{"match_all": map[string]any{}}})
	// A global aggregation ignores the query: OpenSearch returns checkout's count under a term on auth.
	globalBody := map[string]any{"size": 0, "query": term("auth"), "aggs": map[string]any{"all": map[string]any{"global": map[string]any{},
		"aggs": map[string]any{"svc": map[string]any{"terms": map[string]any{"field": "service.name"}}}}}}
	if out := osAdmin(t, "POST", "/"+logs+"/_search", globalBody); !strings.Contains(string(out), `"key":"checkout"`) {
		t.Fatalf("global aggregation did not reach checkout: %s", out)
	}
	osUser(t, "POST", "/"+logs+"/_search", globalBody)
	osUser(t, "POST", "/_msearch", fmt.Sprintf("{\"index\":%q}\n{\"query\":{\"term\":{\"service.name\":\"auth\"}}}\n", logs))
	osAdmin(t, "POST", "/"+logs+"/_search", map[string]any{"query": map[string]any{"match_all": map[string]any{}}}) // the analyzer's own tag
	if code, _ := osCall(t, n, "E2e-only-Noperm-1!", "POST", "/"+logs+"/_search", map[string]any{}, false); code != http.StatusForbidden {
		t.Fatalf("unprivileged search returned %d", code)
	}

	// Stored queries: monitors, and saved objects in a dashboards index.
	mk := func(body map[string]any) string {
		var out struct {
			ID string `json:"_id"`
		}
		json.Unmarshal(osAdmin(t, "POST", "/_plugins/_alerting/monitors", body), &out)
		return out.ID
	}
	sched := map[string]any{"period": map[string]any{"interval": 1, "unit": "MINUTES"}}
	qm := mk(map[string]any{"type": "monitor", "monitor_type": "query_level_monitor", "name": n + "-query", "enabled": false, "schedule": sched,
		"inputs": []any{map[string]any{"search": map[string]any{"indices": []string{logs}, "query": map[string]any{"size": 0, "query": term("auth")}}}}, "triggers": []any{}})
	dm := mk(map[string]any{"type": "monitor", "monitor_type": "doc_level_monitor", "name": n + "-doc", "enabled": false, "schedule": sched,
		"inputs": []any{map[string]any{"doc_level_input": map[string]any{"description": "", "indices": []string{logs},
			"queries": []any{map[string]any{"id": "q1", "name": "q1", "query": "service.name:\"auth\"", "tags": []string{}}}}}}, "triggers": []any{}})
	defer osAdmin(t, "DELETE", "/_plugins/_alerting/monitors/"+qm, nil)
	defer osAdmin(t, "DELETE", "/_plugins/_alerting/monitors/"+dm, nil)
	so := ".kibana_" + n
	osAdmin(t, "POST", "/_bulk?refresh=true", fmt.Sprintf(
		"{\"index\":{\"_index\":%q,\"_id\":\"index-pattern:p1\"}}\n{\"type\":\"index-pattern\",\"index-pattern\":{\"title\":%q}}\n"+
			"{\"index\":{\"_index\":%q,\"_id\":\"index-pattern:p2\"}}\n{\"type\":\"index-pattern\",\"index-pattern\":{\"title\":%q}}\n"+
			"{\"index\":{\"_index\":%q,\"_id\":\"search:s1\"}}\n{\"type\":\"search\",\"references\":[{\"type\":\"index-pattern\",\"id\":\"p1\"}]}\n"+
			"{\"index\":{\"_index\":%q,\"_id\":\"visualization:v1\"}}\n{\"type\":\"visualization\",\"references\":[{\"type\":\"index-pattern\",\"id\":\"p2\"}]}\n",
		so, n+"-nothing*", so, alias, so, so))
	defer osAdmin(t, "DELETE", "/"+so, nil)

	// Wait until the audit log has the unprivileged search, the last user request sent.
	var res opensearch.Result
	deadline := time.Now().Add(2 * time.Minute)
	for {
		res = reader(false, 0).Read(ctx, start, time.Now().Add(time.Minute))
		code, out := osCall(t, "admin", os.Getenv("OPENSEARCH_PASSWORD"), "POST", "/security-auditlog-*/_count", map[string]any{"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"match_phrase": map[string]any{"audit_request_effective_user": n}}}}}}, true)
		if code == 200 && !strings.Contains(string(out), `"count":0`) {
			res = reader(false, 0).Read(ctx, start, time.Now().Add(time.Minute))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the unprivileged search never reached the audit log: %s", out)
		}
		time.Sleep(2 * time.Second)
	}
	g := gapSet(res.Gaps)
	for _, k := range []string{"opensearch-audit-unreadable", "opensearch-monitors-unreadable", "opensearch-dashboards-unreadable", "opensearch-audit-unparsed"} {
		if r, ok := g[k]; ok {
			t.Fatalf("unexpected gap %s: %s", k, r)
		}
	}

	cat, err := cl.Catalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope := func(svc string, idx ...string) opensearch.Scope {
		s, gaps, notes := cl.VerifyScope(ctx, opensearch.Scope{Indices: idx, ServiceField: "service.name", Service: svc}.Expand(cat))
		if len(gaps) > 0 || len(notes) > 0 || s.ServiceField == "" {
			t.Fatalf("scope %s %v: gaps %v notes %v", svc, idx, gaps, notes)
		}
		return s
	}
	checkout, auth := scope("checkout", logs), scope("auth", logs, extra)
	readers := func(s opensearch.Scope) []string {
		var out []string
		for _, u := range res.Uses {
			if u.When.Before(start) && u.Source == "audit" {
				continue
			}
			if !strings.Contains(u.Origin, n) && u.Origin != "POST /_plugins/_ppl" && u.Origin != "POST /_msearch" {
				continue // another test's request
			}
			if !u.CannotRead(s) {
				out = append(out, u.Source+" "+u.Origin)
			}
		}
		sort.Strings(out)
		return out
	}
	wantCheckout := []string{
		"audit POST /" + alias + "/_search",
		"audit POST /" + logs + "/_search", // the global aggregation
		"audit POST /" + logs + "/_search", // the q parameter
		// The denied search: authentication succeeds at the REST layer, where it is logged as
		// AUTHENTICATED; the denial happens later. Counting it as a read is the sound side.
		"audit POST /" + logs + "/_search",
		"audit POST /_msearch",
		"audit POST /_plugins/_ppl",
		"monitor monitor " + n + "-doc (" + dm + ")",
		"savedobject visualization:v1 in " + so,
	}
	wantAuth := append([]string{"audit POST /" + logs + "/_search", "audit POST /" + n + "-*/_search", "monitor monitor " + n + "-query (" + qm + ")"}, wantCheckout...)
	sort.Strings(wantCheckout)
	sort.Strings(wantAuth)
	if got := readers(checkout); strings.Join(got, "\n") != strings.Join(wantCheckout, "\n") {
		t.Fatalf("checkout readers:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantCheckout, "\n"))
	}
	if got := readers(auth); strings.Join(got, "\n") != strings.Join(wantAuth, "\n") {
		t.Fatalf("auth readers:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantAuth, "\n"))
	}

	t.Run("random queries are sound against OpenSearch", func(t *testing.T) {
		rng := rand.New(rand.NewSource(7))
		vals := []string{"checkout", "auth", "billing", "Checkout", "checkout ", "check*"}
		var leaf func(d int) any
		leaf = func(d int) any {
			v := vals[rng.Intn(len(vals))]
			switch k := rng.Intn(9); {
			case k == 0:
				return map[string]any{"term": map[string]any{"service.name": v}}
			case k == 1:
				return map[string]any{"term": map[string]any{"service.name": map[string]any{"value": v, "case_insensitive": rng.Intn(2) == 0}}}
			case k == 2:
				return map[string]any{"terms": map[string]any{"service.name": []string{v, vals[rng.Intn(len(vals))]}}}
			case k == 3:
				return map[string]any{"match": map[string]any{"service.name": v}}
			case k == 4:
				return map[string]any{"wildcard": map[string]any{"service.name": v}}
			case k == 5:
				return map[string]any{"match_all": map[string]any{}}
			case k == 6 && d < 3:
				return map[string]any{"constant_score": map[string]any{"filter": leaf(d + 1)}}
			default:
				b := map[string]any{}
				for _, occ := range []string{"filter", "must", "must_not", "should"} {
					if d < 3 && rng.Intn(2) == 0 {
						var cs []any
						for i := rng.Intn(3); i >= 0; i-- {
							cs = append(cs, leaf(d+1))
						}
						b[occ] = cs
					}
				}
				return map[string]any{"bool": b}
			}
		}
		proven, total := 0, 400
		for i := 0; i < total; i++ {
			q := leaf(0)
			qb, _ := json.Marshal(q)
			u := opensearch.Use{Indices: []string{logs, extra}, Query: qb}
			var out struct {
				Hits struct {
					Hits []struct {
						Source struct {
							Service struct {
								Name any `json:"name"`
							} `json:"service"`
						} `json:"_source"`
					} `json:"hits"`
				} `json:"hits"`
			}
			json.Unmarshal(osAdmin(t, "POST", "/"+logs+","+extra+"/_search?size=100", map[string]any{"query": q}), &out)
			readsCheckout := false
			for _, h := range out.Hits.Hits {
				if h.Source.Service.Name == "checkout" {
					readsCheckout = true
				}
			}
			if u.CannotRead(checkout) {
				proven++
				if readsCheckout {
					t.Fatalf("unsound: %s returns checkout documents", qb)
				}
			}
		}
		t.Logf("%d of %d random queries proven not to read checkout, all confirmed by OpenSearch", proven, total)
		if proven == 0 {
			t.Fatalf("no query was ever proven: the check has no teeth")
		}
	})

	t.Run("search pipelines are a gap", func(t *testing.T) {
		if g := gapSet(reader(false, 0).Read(ctx, start, time.Now()).Gaps); g["opensearch-search-pipelines"] != "" {
			t.Fatalf("gap without pipelines: %s", g["opensearch-search-pipelines"])
		}
		osAdmin(t, "PUT", "/_search/pipeline/"+n, map[string]any{"request_processors": []any{map[string]any{"filter_query": map[string]any{"query": map[string]any{"match_all": map[string]any{}}}}}})
		g := gapSet(reader(false, 0).Read(ctx, start, time.Now()).Gaps)
		osAdmin(t, "DELETE", "/_search/pipeline/"+n, nil)
		if !strings.Contains(g["opensearch-search-pipelines"], n) {
			t.Fatalf("pipeline not reported: %v", g)
		}
	})

	t.Run("scope checks", func(t *testing.T) {
		for _, c := range []struct {
			svc   string
			idx   []string
			field bool
			gap   string
		}{
			{"billing", []string{text}, false, "opensearch-scope-outside"},
			{"billing", []string{missing}, false, "opensearch-scope-outside"},
			{"billing", []string{multi}, false, "opensearch-scope-outside"},
			{"billing", []string{text, missing, multi}, false, ""},
			{"auth", []string{logs}, true, "opensearch-scope-outside"},
			{"nobody", []string{logs}, true, "opensearch-scope-empty"},
			{"checkout", []string{alias}, true, ""},
			{"checkout", []string{"e2e-*"}, false, ""}, // the text-mapped index is in scope
		} {
			s, gaps, notes := cl.VerifyScope(ctx, opensearch.Scope{Indices: c.idx, ServiceField: "service.name", Service: c.svc}.Expand(cat))
			gs := gapSet(gaps)
			if (s.ServiceField != "") != c.field || (c.gap == "") != (len(gs) == 0) || (c.gap != "" && gs[c.gap] == "") || (!c.field && len(notes) == 0) {
				t.Fatalf("%s %v: field %q gaps %v notes %v", c.svc, c.idx, s.ServiceField, gs, notes)
			}
		}
	})

	t.Run("verify blocks rules per service", func(t *testing.T) {
		dir := t.TempDir()
		col := filepath.Join(dir, "collector.yaml")
		os.WriteFile(col, []byte("receivers: {otlp: {protocols: {grpc: {}}}}\nexporters: {opensearch/logs: {}}\nservice: {pipelines: {logs: {receivers: [otlp], exporters: [opensearch/logs]}}}\n"), 0o644)
		cfgPath := filepath.Join(dir, "sievelog.yaml")
		os.WriteFile(cfgPath, []byte(fmt.Sprintf(`loki: {url: %s}
evidence:
  window: 1h
  query_log: {enabled: false}
  ruler: false
  opensearch:
    - name: e2e
      url: %s
      username: admin
      password_env: OPENSEARCH_PASSWORD
      insecure_skip_verify: true
      dashboards_index: %s
      prove_live: true
      indices: ["%s", "%s"]
      service_field: service.name
collector:
  config_files: [%s]
  pipeline: logs
  sinks: {opensearch/logs: {opensearch: e2e}}
policy:
  acknowledge: [querylog-disabled, ruler-not-checked, grafana-not-configured, opensearch-plugins, opensearch-audit-window]
`, os.Getenv("LOKI_URL"), os.Getenv("OPENSEARCH_URL"), so, logs, extra, col)), 0o644)
		cfg, err := app.LoadConfig(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		dv, _ := templating.DrainVersion()
		rule := func(id, svc string) app.EnforcedRule {
			return app.EnforcedRule{Rule: emit.Rule{ID: id, ScopeAttr: "service.name", ScopeValue: svc, Language: `\Aline [0-9]\z`, Action: "aggregate"}, Service: svc}
		}
		rf := &app.RulesFile{DrainVersion: dv, DrainConfigHash: cfg.DrainConfigHash(), LokiLabel: "service_name", Rules: []app.EnforcedRule{rule("r-checkout", "checkout"), rule("r-auth", "auth"), rule("r-orders", "orders")}}
		vr, err := app.Verify(ctx, cfg, rf, time.Now(), app.VerifyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		reasons := map[string]string{}
		for _, v := range vr.Violations {
			reasons[v.RuleID] = strings.Join(v.Reasons, "\n")
		}
		// orders has no document in OpenSearch: that is a gap, and gaps block every rule.
		if !strings.Contains(reasons["r-orders"], "opensearch-scope-empty") || !strings.Contains(reasons["r-checkout"], "opensearch-scope-empty") {
			t.Fatalf("scope-empty gap missing: %v", reasons)
		}
		if !strings.Contains(reasons["r-auth"], "monitor "+n+"-query") || strings.Contains(reasons["r-checkout"], "monitor "+n+"-query") {
			t.Fatalf("per-service readers wrong:\ncheckout: %s\nauth: %s", reasons["r-checkout"], reasons["r-auth"])
		}
	})
}

// dashCall performs one OpenSearch Dashboards API call as the e2e admin in a tenant.
func dashCall(t *testing.T, method, path, tenant string, body any) []byte {
	t.Helper()
	var r io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		r = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, os.Getenv("DASHBOARDS_URL")+path, r)
	req.SetBasicAuth("admin", os.Getenv("OPENSEARCH_PASSWORD"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("osd-xsrf", "true")
	req.Header.Set("securitytenant", tenant)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("dashboards %s %s (%s): %d %s", method, path, tenant, resp.StatusCode, out)
	}
	return out
}

// TestOpenSearchDashboardsSavedObjects creates saved objects through a real OpenSearch Dashboards in
// the global, private and a custom tenant, and checks the reader finds every one, resolves each
// index pattern within its own tenant, and decides reads exactly.
func TestOpenSearchDashboardsSavedObjects(t *testing.T) {
	if os.Getenv("DASHBOARDS_URL") == "" {
		t.Fatal("DASHBOARDS_URL is not set")
	}
	n := fmt.Sprintf("d%d", time.Now().UnixNano())
	osAdmin(t, "PUT", "/_plugins/_security/api/tenants/"+n, map[string]any{"description": "e2e"})
	defer osAdmin(t, "DELETE", "/_plugins/_security/api/tenants/"+n, nil)
	search := func(tenant, id, pattern string) {
		dashCall(t, "POST", "/api/saved_objects/search/"+id, tenant, map[string]any{
			"attributes": map[string]any{"title": id, "columns": []string{"_source"},
				"kibanaSavedObjectMeta": map[string]any{"searchSourceJSON": `{"query":{"query":"service.name:auth","language":"kuery"},"indexRefName":"kibanaSavedObjectMeta.searchSourceJSON.index"}`}},
			"references": []any{map[string]any{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": pattern}}})
	}
	vis := func(tenant, id, pattern string) {
		dashCall(t, "POST", "/api/saved_objects/visualization/"+id, tenant, map[string]any{
			"attributes": map[string]any{"title": id, "visState": `{"type":"table","aggs":[]}`, "uiStateJSON": "{}",
				"kibanaSavedObjectMeta": map[string]any{"searchSourceJSON": `{"indexRefName":"kibanaSavedObjectMeta.searchSourceJSON.index"}`}},
			"references": []any{map[string]any{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": pattern}}})
	}
	pattern := func(tenant, id, title string) {
		dashCall(t, "POST", "/api/saved_objects/index-pattern/"+id, tenant, map[string]any{"attributes": map[string]any{"title": title}})
	}
	// The same pattern id means different titles in different tenants.
	pattern("global", n+"-p", n+"-logs*")
	pattern(n, n+"-p", n+"-metrics*")
	pattern("__user__", n+"-p", n+"-audit*,"+n+"-logs-checkout")
	search("global", n+"-s-global", n+"-p")      // reads the logs
	vis(n, n+"-v-custom", n+"-p")                // reads metrics only
	vis("__user__", n+"-v-private", n+"-p")      // reads checkout's own index
	vis("global", n+"-v-dangling", n+"-missing") // an unknown pattern: every index
	dashCall(t, "POST", "/api/saved_objects/query/"+n+"-q", n, map[string]any{"attributes": map[string]any{"title": n, "query": map[string]any{"query": "x", "language": "kuery"}}})
	defer func() {
		for _, o := range [][3]string{{"search", n + "-s-global", "global"}, {"visualization", n + "-v-custom", n}, {"visualization", n + "-v-private", "__user__"},
			{"visualization", n + "-v-dangling", "global"}, {"query", n + "-q", n}, {"index-pattern", n + "-p", "global"}, {"index-pattern", n + "-p", n}, {"index-pattern", n + "-p", "__user__"}} {
			dashCall(t, "DELETE", "/api/saved_objects/"+o[0]+"/"+o[1], o[2], nil)
		}
	}()

	cl := &opensearch.Client{Base: os.Getenv("OPENSEARCH_URL"), Username: "admin", Password: os.Getenv("OPENSEARCH_PASSWORD"), InsecureSkipVerify: true}
	r := &opensearch.Reader{C: cl, AuditIndex: "security-auditlog-*", DashboardsIndex: ".kibana*"}
	res := r.Read(context.Background(), time.Now().Add(-time.Minute), time.Now())
	if g := gapSet(res.Gaps); !strings.Contains(g["opensearch-saved-queries"], n+"-q") || g["opensearch-dashboards-unreadable"] != "" {
		t.Fatalf("gaps: %v", g)
	}
	checkout := opensearch.Scope{Indices: []string{n + "-logs-checkout"}}
	auth := opensearch.Scope{Indices: []string{n + "-logs-auth"}}
	want := map[string][2]bool{ // object -> CannotRead for checkout, auth
		n + "-s-global":   {false, false},
		n + "-v-custom":   {true, true},
		n + "-v-private":  {false, true},
		n + "-v-dangling": {false, false},
	}
	seen := map[string]bool{}
	for _, u := range res.Uses {
		if u.Source != "savedobject" || !strings.Contains(u.Origin, n) {
			continue
		}
		for id, w := range want {
			if strings.Contains(u.Origin, ":"+id+" in ") {
				seen[id] = true
				if u.CannotRead(checkout) != w[0] || u.CannotRead(auth) != w[1] {
					t.Fatalf("%s: indices %v, CannotRead checkout %v auth %v, want %v", u.Origin, u.Indices, u.CannotRead(checkout), u.CannotRead(auth), w)
				}
			}
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("found %v of %v in %+v", seen, want, res.Uses)
	}
	t.Logf("dashboards: saved objects in the global, private and a custom tenant read and decided exactly")
}
