package opensearch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fake struct {
	audit     []map[string]any
	auditCfg  string
	firstTS   *float64
	monitors  string
	saved     []map[string]any
	requests  []string
	probeSeen bool
	pipelines string
}

func hitsJSON(docs []map[string]any, idx string) map[string]any {
	var hs []map[string]any
	for i, d := range docs {
		id, _ := d["_id"].(string)
		if id == "" {
			id = "doc" + string(rune('a'+i))
		}
		index, _ := d["_index"].(string)
		if index == "" {
			index = idx
		}
		src := map[string]any{}
		for k, v := range d {
			if k != "_id" && k != "_index" {
				src[k] = v
			}
		}
		hs = append(hs, map[string]any{"_id": id, "_index": index, "_source": src})
	}
	return map[string]any{"_scroll_id": "end", "hits": map[string]any{"hits": hs}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.requests = append(f.requests, r.Method+" "+r.URL.Path+" tagged="+r.Header.Get(Header))
	switch {
	case r.URL.Path == "/_search/pipeline":
		if f.pipelines == "" {
			http.Error(w, `{"error":{"type":"resource_not_found_exception"}}`, http.StatusNotFound)
			return
		}
		io.WriteString(w, f.pipelines)
	case r.URL.Path == "/_search/scroll":
		if r.Method == http.MethodDelete {
			io.WriteString(w, `{}`)
			return
		}
		io.WriteString(w, `{"_scroll_id":"end","hits":{"hits":[]}}`)
	case r.URL.Path == "/_plugins/_security/api/audit":
		if f.auditCfg == "" {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		io.WriteString(w, f.auditCfg)
	case strings.HasPrefix(r.URL.Path, "/"+probePrefix):
		if r.Header.Get(Header) == "" {
			f.probeSeen = true
		}
		io.WriteString(w, `{"hits":{"hits":[]}}`)
	case r.URL.Path == "/security-auditlog-*/_search":
		switch {
		case strings.Contains(string(body), `"aggs"`):
			json.NewEncoder(w).Encode(map[string]any{"aggregations": map[string]any{"first": map[string]any{"value": f.firstTS}}})
		case strings.Contains(string(body), probePrefix):
			if f.probeSeen {
				var q struct {
					Query struct {
						MatchPhrase map[string]string `json:"match_phrase"`
					} `json:"query"`
				}
				json.Unmarshal(body, &q)
				json.NewEncoder(w).Encode(hitsJSON([]map[string]any{
					{"audit_rest_request_path": q.Query.MatchPhrase["audit_rest_request_path"] + "x", "audit_category": "AUTHENTICATED"},
					{"audit_rest_request_path": q.Query.MatchPhrase["audit_rest_request_path"], "audit_category": "AUTHENTICATED"},
				}, "security-auditlog-x"))
			} else {
				io.WriteString(w, `{"hits":{"hits":[]}}`)
			}
		default:
			json.NewEncoder(w).Encode(hitsJSON(f.audit, "security-auditlog-x"))
		}
	case r.URL.Path == "/_plugins/_alerting/monitors/_search":
		if f.monitors == "" {
			http.Error(w, `{"error":{"type":"index_not_found_exception","reason":"no such index [.opendistro-alerting-config]"}}`, http.StatusNotFound)
			return
		}
		io.WriteString(w, f.monitors)
	case r.URL.Path == "/.kibana*/_search":
		json.NewEncoder(w).Encode(hitsJSON(f.saved, ".kibana_1"))
	default:
		http.Error(w, "unexpected "+r.URL.Path, http.StatusTeapot)
	}
}

const fullAudit = `{"config":{"enabled":true,"audit":{"enable_rest":true,"disabled_rest_categories":["GRANTED_PRIVILEGES"],"ignore_users":[],"ignore_requests":[],"log_request_body":true}}}`

func gapKeys(res Result) map[string]string {
	m := map[string]string{}
	for _, g := range res.Gaps {
		m[g.Key] = g.Reason
	}
	return m
}

func TestReadAudit(t *testing.T) {
	ts := float64(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	f := &fake{auditCfg: fullAudit, firstTS: &ts, audit: []map[string]any{
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/logs-*/_search",
			"audit_request_body": `{"query":{"term":{"service.name":"auth"}}}`},
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/logs-*/_search",
			"audit_request_body": `{"query":{"term":{"service.name":"auth"}}}`, "audit_rest_request_params": map[string]any{"q": "service.name:checkout"}},
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/logs-auth/_msearch", "audit_request_body": "{}\n{}\n"},
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/logs-a/_search", "audit_request_body": `{not json`},
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/%3Clogs-%7Bnow%2Fd%7D%3E/_search"},
		{"audit_request_layer": "REST", "audit_category": "MISSING_PRIVILEGES", "audit_rest_request_method": "POST", "audit_rest_request_path": "/logs-*/_search"},
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/logs-*/_search",
			"audit_rest_request_headers": map[string]any{"x-zeroreads": []string{"1"}}},
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/" + probePrefix + "ab/_search"},
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/_bulk"},
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/logs-*/_search",
			"audit_request_body": `{"query":{"term":{"service.name":"auth"}},"aggs":{"all":{"global":{},"aggs":{"n":{"terms":{"field":"body"}}}}}}`},
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/logs-*/_search",
			"audit_request_body": `{"query":{"term":{"service.name":"auth"}},"size":0,"aggs":{"by":{"terms":{"field":"level"},"aggs":{"c":{"cardinality":{"field":"x"}}}}}}`},
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/logs-*/_search",
			"audit_request_body": `{"query":{"term":{"service.name":"auth"}}}`, "audit_rest_request_params": map[string]any{"search_pipeline": "p"}},
		{"audit_request_layer": "TRANSPORT", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/logs-*/_search"},
		{"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST", "audit_rest_request_path": "/_plugins/_ppl", "audit_request_body": `{"query":"source=logs-checkout"}`},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	r := &Reader{Client: &Client{Base: srv.URL}, AuditIndex: "security-auditlog-*", DashboardsIndex: ".kibana*", ProveLive: true, ProveTimeout: 5 * time.Second}
	res := r.Read(context.Background(), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Now())
	keys := gapKeys(res)
	for _, k := range []string{"opensearch-audit-not-live", "opensearch-audit-window", "opensearch-audit-config-unreadable", "opensearch-audit-unreadable", "opensearch-monitors-unreadable"} {
		if _, ok := keys[k]; ok {
			t.Fatalf("unexpected gap %s: %s", k, keys[k])
		}
	}
	if _, ok := keys["opensearch-plugins"]; !ok {
		t.Fatalf("missing plugins gap")
	}
	if res.Lines != len(f.audit) || len(res.Uses) != 6 {
		t.Fatalf("lines %d uses %d: %+v", res.Lines, len(res.Uses), res.Uses)
	}
	chk := Scope{Indices: []string{"logs-checkout"}, ServiceField: "service.name", Service: "checkout"}.Expand(Catalog{Indices: []string{"logs-checkout", "logs-a"}})
	// Identical requests fold into one use: the bounded aggregation into the plain term search, the
	// global aggregation and the search pipeline into the q-parameter search (all opaque on logs-*).
	counts := []int{2, 3, 1, 1, 1, 1}
	for i, u := range res.Uses {
		if u.Count != counts[i] {
			t.Fatalf("use %d (%s) count %d, want %d", i, u.Origin, u.Count, counts[i])
		}
	}
	want := []bool{true, false, false, true, false, false}
	for i, u := range res.Uses {
		if got := u.CannotRead(chk); got != want[i] {
			t.Fatalf("use %d (%s): CannotRead %v", i, u.Origin, got)
		}
	}
	if !res.Uses[1].Opaque || res.Uses[2].Indices != nil || !res.Uses[3].Opaque || res.Uses[3].Indices[0] != "logs-a" || res.Uses[4].Indices != nil {
		t.Fatalf("uses: %+v", res.Uses)
	}
	for _, req := range f.requests {
		probe := strings.HasPrefix(req, "POST /"+probePrefix)
		if probe != strings.HasSuffix(req, "tagged=") {
			t.Fatalf("only the probe may be untagged: %s", req)
		}
	}
}

func TestAuditGaps(t *testing.T) {
	late := float64(time.Now().Add(-time.Hour).UnixMilli())
	for _, c := range []struct {
		cfg  string
		ts   *float64
		want []string
	}{
		{"", &late, []string{"opensearch-audit-config-unreadable", "opensearch-audit-window"}},
		{`{"config":{"enabled":false,"audit":{"enable_rest":true}}}`, nil, []string{"opensearch-audit-disabled", "opensearch-audit-window"}},
		{`{"config":{"enabled":true,"audit":{"enable_rest":false}}}`, nil, []string{"opensearch-audit-disabled"}},
		{`{"config":{"enabled":true,"audit":{"enable_rest":true,"disabled_rest_categories":["AUTHENTICATED","GRANTED_PRIVILEGES"]}}}`, nil, []string{"opensearch-audit-disabled"}},
		{`{"config":{"enabled":true,"audit":{"enable_rest":true,"ignore_users":["kibanaserver"],"ignore_requests":["SearchRequest"],"ignore_headers":["x-a"]}}}`, nil,
			[]string{"opensearch-audit-ignored-users", "opensearch-audit-ignored-requests", "opensearch-audit-ignored-headers"}},
		{fullAudit + "PIPELINES", nil, []string{"opensearch-search-pipelines"}},
	} {
		f := &fake{auditCfg: strings.TrimSuffix(c.cfg, "PIPELINES"), firstTS: c.ts}
		if strings.HasSuffix(c.cfg, "PIPELINES") {
			f.pipelines = `{"rewrite":{"request_processors":[]}}`
		}
		srv := httptest.NewServer(f)
		r := &Reader{Client: &Client{Base: srv.URL}, AuditIndex: "security-auditlog-*", DashboardsIndex: ".kibana*"}
		res := r.Read(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
		srv.Close()
		keys := gapKeys(res)
		for _, k := range c.want {
			if _, ok := keys[k]; !ok {
				t.Fatalf("cfg %s: missing gap %s in %v", c.cfg, k, keys)
			}
		}
	}
}

func TestProbeNotLive(t *testing.T) {
	// A server that never records the probe.
	f := &fake{auditCfg: fullAudit}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/"+probePrefix) {
			io.WriteString(w, `{}`)
			return
		}
		f.ServeHTTP(w, r)
	}))
	defer srv.Close()
	r := &Reader{Client: &Client{Base: srv.URL}, AuditIndex: "security-auditlog-*", DashboardsIndex: ".kibana*", ProveLive: true, ProveTimeout: 10 * time.Millisecond}
	if err := r.proveLive(context.Background()); err == nil {
		t.Fatalf("probe proven without being recorded")
	}
}

func TestMonitors(t *testing.T) {
	f := &fake{auditCfg: fullAudit, monitors: `{"hits":{"total":{"value":7},"hits":[
	 {"_id":"m1","_source":{"monitor":{"name":"auth errors","inputs":[{"search":{"indices":["logs-*"],"query":{"size":0,"query":{"bool":{"filter":[{"term":{"service.name":"auth"}},{"range":{"@timestamp":{"gte":"{{period_end}}||-1h"}}}]}}}}}]}}},
	 {"_id":"m2","_source":{"type":"monitor","name":"doc level","inputs":[{"doc_level_input":{"indices":["logs-checkout"],"queries":[{"query":"level:error"}]}}]}},
	 {"_id":"m3","_source":{"monitor":{"name":"health","inputs":[{"uri":{"path":"/_cluster/health"}}]}}},
	 {"_id":"m4","_source":{"monitor":{"name":"future","inputs":[{"remote_input":{}}]}}},
	 {"_id":"w1","_source":{"type":"workflow","name":"chain"}},
	 {"_id":"m5","_source":{"monitor":{"name":"empty","inputs":[{"search":{"indices":[],"query":{"query":{"match_all":{}}}}}]}}},
	 {"_id":"x1","_source":{"type":"remote_monitor","name":"new kind"}}
	]}}`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	r := &Reader{Client: &Client{Base: srv.URL}, AuditIndex: "security-auditlog-*", DashboardsIndex: ".kibana*"}
	var res Result
	if err := r.readMonitors(context.Background(), &res); err != nil {
		t.Fatal(err)
	}
	chk := Scope{Indices: []string{"logs-checkout"}, ServiceField: "service.name", Service: "checkout"}.Expand(Catalog{Indices: []string{"logs-checkout", "logs-a"}})
	if len(res.Uses) != 5 {
		t.Fatalf("uses: %+v", res.Uses)
	}
	want := []bool{true, false, false, false, false}
	for i, u := range res.Uses {
		if got := u.CannotRead(chk); got != want[i] {
			t.Fatalf("%s: CannotRead %v", u.Origin, got)
		}
	}
	f.monitors = strings.Replace(f.monitors, `"value":7`, `"value":8`, 1)
	res = Result{}
	_ = r.readMonitors(context.Background(), &res)
	if _, ok := gapKeys(res)["opensearch-monitors-unreadable"]; !ok {
		t.Fatalf("truncated monitor listing not flagged")
	}
	f.monitors = ""
	res = Result{}
	if err := r.readMonitors(context.Background(), &res); err != nil || len(res.Uses) != 0 {
		t.Fatalf("no monitor index: %v %+v", err, res)
	}
}

func TestSavedObjects(t *testing.T) {
	f := &fake{auditCfg: fullAudit, saved: []map[string]any{
		{"_id": "index-pattern:p1", "type": "index-pattern", "index-pattern": map[string]any{"title": "logs-auth*"}},
		{"_id": "index-pattern:p1", "_index": ".kibana_tenant", "type": "index-pattern", "index-pattern": map[string]any{"title": "logs-*"}},
		{"_id": "search:s1", "type": "search", "references": []map[string]any{{"type": "index-pattern", "id": "p1"}}},
		{"_id": "search:s2", "_index": ".kibana_tenant", "type": "search", "references": []map[string]any{{"type": "index-pattern", "id": "p1"}}},
		{"_id": "visualization:v1", "type": "visualization", "references": []map[string]any{{"type": "index-pattern", "id": "gone"}}},
		{"_id": "visualization:vega", "type": "visualization"},
		{"_id": "query:q1", "type": "query"},
		{"_id": "dashboard:d1", "type": "dashboard"},
		{"_id": "config:3.8.0", "type": "config"},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	r := &Reader{Client: &Client{Base: srv.URL}, AuditIndex: "security-auditlog-*", DashboardsIndex: ".kibana*"}
	var res Result
	if err := r.readSavedObjects(context.Background(), &res); err != nil {
		t.Fatal(err)
	}
	chk := Scope{Indices: []string{"logs-checkout"}, ServiceField: "service.name", Service: "checkout"}.Expand(Catalog{Indices: []string{"logs-checkout", "logs-a"}})
	want := map[string]bool{"search:s1 in .kibana_1": true, "search:s2 in .kibana_tenant": false, "visualization:v1 in .kibana_1": false, "visualization:vega in .kibana_1": false}
	if len(res.Uses) != len(want) {
		t.Fatalf("uses: %+v", res.Uses)
	}
	for _, u := range res.Uses {
		if got := u.CannotRead(chk); got != want[u.Origin] {
			t.Fatalf("%s: CannotRead %v", u.Origin, got)
		}
	}
	if _, ok := gapKeys(res)["opensearch-saved-queries"]; !ok {
		t.Fatalf("saved query not flagged")
	}
}

// A cluster that keeps returning hits cannot keep a scroll going.
func TestScrollStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			return
		}
		_, _ = w.Write([]byte(`{"_scroll_id":"s","hits":{"hits":[{"_index":"i","_source":{}}]}}`))
	}))
	defer srv.Close()
	r := &Reader{Client: &Client{Base: srv.URL}, maxPages: 3}
	pages := 0
	err := r.scan(context.Background(), "i", map[string]any{"match_all": map[string]any{}}, func(hit) error { pages++; return nil })
	if err == nil || !strings.Contains(err.Error(), "after 3 pages") || pages != 3 {
		t.Fatalf("a scroll without end was read: %d pages, %v", pages, err)
	}
}
