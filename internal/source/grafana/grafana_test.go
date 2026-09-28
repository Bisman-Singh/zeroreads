package grafana

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// fakeGrafana serves the APIs the reader uses, per org, from fixed documents.
func fakeGrafana(t *testing.T, org2Broken bool) *httptest.Server {
	t.Helper()
	panes, _ := json.Marshal(map[string]any{"a": map[string]any{"datasource": "loki", "queries": []any{
		map[string]any{"refId": "A", "expr": `{service_name="checkout"} |= "short"`}}}})
	left, _ := json.Marshal(map[string]any{"datasource": "Loki", "queries": []any{map[string]any{"expr": `{service_name="auth"} |= "legacy"`}}})
	docs := map[string]any{
		"/api/orgs": []any{map[string]any{"id": 2}, map[string]any{"id": 1}},
		"1 /api/datasources": []any{
			map[string]any{"uid": "loki", "name": "Loki", "type": "loki", "url": "http://loki:3100", "isDefault": true},
			map[string]any{"uid": "prom", "name": "Prom", "type": "prometheus"},
		},
		"1 /apis/dashboard.grafana.app/v1/namespaces/default/dashboards": map[string]any{"items": []any{
			map[string]any{"metadata": map[string]any{"name": "d1"}, "spec": map[string]any{
				"annotations": map[string]any{"list": []any{
					map[string]any{"datasource": map[string]any{"uid": "loki"}, "expr": `{service_name="checkout"} |= "deploy"`, "enable": false},
				}},
				"panels": []any{
					map[string]any{"id": 1, "datasource": map[string]any{"uid": "loki", "type": "loki"}, "targets": []any{
						map[string]any{"refId": "A", "expr": `{service_name="checkout"} |= "a"`},
						map[string]any{"refId": "B", "expr": `{service_name="checkout"} |= "hidden"`, "hide": true},
					}},
					map[string]any{"id": 2, "targets": []any{map[string]any{"refId": "A", "expr": `{service_name="checkout"} |= "default"`}}},
					map[string]any{"id": 3, "datasource": map[string]any{"uid": "prom", "type": "prometheus"}, "targets": []any{
						map[string]any{"refId": "A", "expr": `up`}}},
					map[string]any{"id": 4, "datasource": "$ds", "targets": []any{map[string]any{"refId": "A", "expr": `{service_name="checkout"} |= "variable"`}}},
					map[string]any{"id": 5, "datasource": map[string]any{"uid": "-- Mixed --"}, "targets": []any{
						map[string]any{"refId": "A", "datasource": map[string]any{"uid": "loki"}, "expr": `{service_name="checkout"} |= "mixed"`},
						map[string]any{"refId": "B", "datasource": map[string]any{"uid": "prom"}, "expr": `up`}}},
					map[string]any{"id": 6, "type": "row", "panels": []any{
						map[string]any{"id": 7, "datasource": map[string]any{"type": "loki", "uid": "other-org-loki"}, "targets": []any{
							map[string]any{"refId": "A", "expr": `{service_name="checkout"} |= "collapsed"`}}}}},
					map[string]any{"id": 8, "libraryPanel": map[string]any{"uid": "lib-ok"}},
					map[string]any{"id": 9, "libraryPanel": map[string]any{"uid": "lib-missing"}},
				},
			}},
			map[string]any{"metadata": map[string]any{"name": "broken"}, "status": map[string]any{"conversion": map[string]any{"failed": true, "error": "boom"}}},
		}},
		"1 /apis/dashboard.grafana.app/v2/namespaces/default/dashboards": map[string]any{"items": []any{
			// The same dashboard in v2: its queries must not be counted twice.
			map[string]any{"metadata": map[string]any{"name": "d1"}, "spec": map[string]any{"elements": map[string]any{
				"panel-1": map[string]any{"kind": "Panel", "spec": map[string]any{"data": map[string]any{"spec": map[string]any{"queries": []any{
					map[string]any{"spec": map[string]any{"query": map[string]any{"group": "loki", "datasource": map[string]any{"name": "loki"},
						"spec": map[string]any{"expr": `{service_name="checkout"} |= "a"`}}}}}}}}},
			}}},
			map[string]any{"metadata": map[string]any{"name": "v2only"}, "spec": map[string]any{
				"annotations": []any{map[string]any{"spec": map[string]any{"enable": true, "query": map[string]any{"group": "loki", "datasource": map[string]any{"name": "loki"},
					"spec": map[string]any{"expr": `{service_name="auth"} |= "v2 annotation"`}}}}},
				"elements": map[string]any{
					"lib": map[string]any{"kind": "LibraryPanel", "spec": map[string]any{"libraryPanel": map[string]any{"uid": "lib-gone"}}},
					"odd": map[string]any{"kind": "Unknown"},
				}}},
			map[string]any{"metadata": map[string]any{"name": "broken"}, "status": map[string]any{"conversion": map[string]any{"failed": true, "error": "boom v2"}}},
		}},
		"1 /api/library-elements": map[string]any{"result": map[string]any{"totalCount": 1, "elements": []any{
			map[string]any{"uid": "lib-ok", "model": map[string]any{"datasource": map[string]any{"uid": "loki"}, "targets": []any{
				map[string]any{"refId": "A", "expr": `{service_name="checkout"} |= "library"`}}}},
		}}},
		"1 /api/v1/provisioning/alert-rules": []any{
			map[string]any{"uid": "al", "data": []any{
				map[string]any{"datasourceUid": "loki", "model": map[string]any{"expr": `sum(count_over_time({service_name="auth"} |= "alert" [5m]))`}},
				map[string]any{"datasourceUid": "__expr__", "model": map[string]any{"expression": "A"}}}},
			map[string]any{"uid": "rec", "record": map[string]any{"metric": "m"}, "data": []any{
				map[string]any{"datasourceUid": "loki", "model": map[string]any{"expr": `sum(rate({service_name="auth"}[1m]))`}}}},
		},
		"1 /apis/shorturl.grafana.app/v1beta1/namespaces/default/shorturls": map[string]any{"items": []any{
			map[string]any{"metadata": map[string]any{"name": "s1"}, "spec": map[string]any{"path": "explore?panes=" + url.QueryEscape(string(panes))}},
			map[string]any{"metadata": map[string]any{"name": "s2"}, "spec": map[string]any{"path": "/explore?left=" + url.QueryEscape(string(left))}},
			map[string]any{"metadata": map[string]any{"name": "s3"}, "spec": map[string]any{"path": "d/d1/dash"}},
			map[string]any{"metadata": map[string]any{"name": "s4"}, "spec": map[string]any{"path": "explore?orgId=1"}},
		}},
		"1 /api/query-history": map[string]any{"result": map[string]any{"totalCount": 1, "queryHistory": []any{
			map[string]any{"uid": "h1", "datasourceUid": "loki", "queries": []any{map[string]any{"expr": `{service_name="orders"} |= "history"`}}}}}},
		"1 /api/datasources/correlations": map[string]any{"totalCount": 2, "correlations": []any{
			map[string]any{"uid": "c1", "targetUID": "loki", "type": "query", "config": map[string]any{"target": map[string]any{"expr": `{service_name="${service}"}`}}},
			map[string]any{"uid": "c2", "targetUID": "loki", "type": "external", "config": map[string]any{"target": map[string]any{"url": "https://x"}}}}},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path
		if org := r.Header.Get("X-Grafana-Org-Id"); org != "" {
			key = org + " " + r.URL.Path
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no auth", http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(key, "2 ") && org2Broken {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		doc, ok := docs[key]
		if !ok {
			if strings.HasPrefix(key, "2 ") {
				doc = []any{} // an empty org
				if strings.Contains(key, "/apis/") {
					doc = map[string]any{"items": []any{}}
				} else if strings.Contains(key, "library") || strings.Contains(key, "history") {
					doc = map[string]any{"result": map[string]any{}}
				} else if strings.Contains(key, "correlations") {
					doc = map[string]any{}
				}
			} else {
				http.Error(w, "not found "+key, http.StatusNotFound)
				return
			}
		}
		json.NewEncoder(w).Encode(doc)
	}))
}

func TestReadEveryStoredQuery(t *testing.T) {
	srv := fakeGrafana(t, true)
	defer srv.Close()
	res, err := (&Client{Base: srv.URL, Token: "tok"}).Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, q := range res.Queries {
		got[q.Origin] = strings.Join(q.Datasources, ",") + " " + q.Expr
		if q.Hidden != (q.Origin == "dashboard:d1/panel:1/B" || q.Origin == "dashboard:d1/annotation:0") {
			t.Fatalf("%s hidden=%v", q.Origin, q.Hidden)
		}
	}
	want := map[string]string{
		"dashboard:d1/annotation:0":         `loki {service_name="checkout"} |= "deploy"`,
		"dashboard:d1/panel:1/A":            `loki {service_name="checkout"} |= "a"`,
		"dashboard:d1/panel:1/B":            `loki {service_name="checkout"} |= "hidden"`,
		"dashboard:d1/panel:2/A":            `loki {service_name="checkout"} |= "default"`,
		"dashboard:d1/panel:4/A":            `* {service_name="checkout"} |= "variable"`,
		"dashboard:d1/panel:5/A":            `loki {service_name="checkout"} |= "mixed"`,
		"dashboard:d1/panel:7/A":            `* {service_name="checkout"} |= "collapsed"`,
		"dashboard:v2only/annotation:0":     `loki {service_name="auth"} |= "v2 annotation"`,
		"librarypanel:lib-ok/panel:model/A": `loki {service_name="checkout"} |= "library"`,
		"alertrule:al/0":                    `loki sum(count_over_time({service_name="auth"} |= "alert" [5m]))`,
		"recordingrule:rec/0":               `loki sum(rate({service_name="auth"}[1m]))`,
		"shorturl:s1/a/0":                   `loki {service_name="checkout"} |= "short"`,
		"shorturl:s2/left/0":                `loki {service_name="auth"} |= "legacy"`,
		"queryhistory:h1/0":                 `loki {service_name="orders"} |= "history"`,
		"correlation:c1":                    `loki {service_name="${service}"}`,
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: got %q, want %q\nall: %v", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		var extra []string
		for k := range got {
			if _, ok := want[k]; !ok {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		t.Fatalf("unexpected queries %v (the v2 copy of d1 must not repeat it)", extra)
	}
	gaps := map[string]string{}
	for _, g := range res.Gaps {
		gaps[g.Origin] = g.Reason
	}
	for origin, part := range map[string]string{
		"dashboard:v2only/odd": "unknown element", "dashboard:broken": "conversion failed", "shorturl:s4": "without readable queries",
		"queryhistory": "only the history", "datasources": "forbidden",
	} {
		if !strings.Contains(gaps[origin], part) {
			t.Fatalf("gap %s: %q, want it to mention %q\nall: %v", origin, gaps[origin], part, gaps)
		}
	}
	// A panel whose library panel does not exist reads nothing: a note, never a gap.
	notes := map[string]string{}
	for _, n := range res.Notes {
		notes[n.Origin] = n.Reason
	}
	for origin, part := range map[string]string{"dashboard:d1/panel:9": "lib-missing", "dashboard:v2only/lib": "lib-gone"} {
		if !strings.Contains(notes[origin], part) || gaps[origin] != "" {
			t.Fatalf("%s: note %q, gap %q", origin, notes[origin], gaps[origin])
		}
	}
	if res.LokiDatasources[1]["loki"] != "http://loki:3100" || len(res.Orgs) != 2 || res.Orgs[0] != 1 {
		t.Fatalf("orgs %v, loki datasources %v", res.Orgs, res.LokiDatasources)
	}
}

func TestOrgFallbackAndAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/orgs":
			http.Error(w, "not an admin", http.StatusForbidden)
		case "/api/org":
			if u, p, ok := r.BasicAuth(); !ok || u != "viewer" || p != "pw" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			w.Write([]byte(`{"id":7}`))
		default:
			http.Error(w, "stop", http.StatusTeapot)
		}
	}))
	defer srv.Close()
	res, err := (&Client{Base: srv.URL, Username: "viewer", Password: "pw"}).Read(context.Background())
	if err != nil || len(res.Orgs) != 1 || res.Orgs[0] != 7 || len(res.Gaps) != 2 || res.Gaps[0].Origin != "orgs" || res.Gaps[1].Origin != "datasources" {
		t.Fatalf("%v %+v", err, res)
	}
	if namespace(1) != "default" || namespace(7) != "org-7" {
		t.Fatal("namespaces")
	}
	if _, err := (&Client{Base: srv.URL, Username: "viewer", Password: "bad"}).Read(context.Background()); err == nil {
		t.Fatal("bad credentials must fail")
	}
}

// Credentials that cannot list orgs (Grafana 13.2.2 answers a service account token 403, "orgs:read")
// read their own org and leave a gap for the others. Found by the v1 audit: the fallback was silent.
// Any other failure is an error, and every page of orgs is read, whether pages are numbered from 0
// (Grafana 13.2.2) or from 1.
func TestOrgsListing(t *testing.T) {
	status := http.StatusInternalServerError
	firstPage := 0
	total := 0
	ignorePage := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/orgs":
			if total == 0 {
				http.Error(w, "refused", status)
				return
			}
			per, _ := strconv.Atoi(r.URL.Query().Get("perpage"))
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			page = max(page-firstPage, 0)
			if ignorePage {
				page = 0
			}
			var out []any
			for id := page*per + 1; id <= min((page+1)*per, total); id++ {
				out = append(out, map[string]any{"id": id})
			}
			json.NewEncoder(w).Encode(append([]any{}, out...))
		case "/api/org":
			w.Write([]byte(`{"id":3}`))
		}
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL}
	if _, _, err := c.orgs(context.Background()); err == nil {
		t.Fatal("a server error on /api/orgs fell back to one org")
	}
	status = http.StatusForbidden
	orgs, gaps, err := c.orgs(context.Background())
	if err != nil || len(orgs) != 1 || orgs[0] != 3 || len(gaps) != 1 || gaps[0].Origin != "orgs" {
		t.Fatalf("%v %v %+v", orgs, err, gaps)
	}
	for _, c2 := range []struct{ first, total int }{{0, 2}, {1, 2}, {0, orgsPerPage}, {1, orgsPerPage}, {0, 2*orgsPerPage + 5}, {1, 2*orgsPerPage + 5}} {
		firstPage, total = c2.first, c2.total
		orgs, gaps, err := c.orgs(context.Background())
		if err != nil || len(gaps) != 0 || len(orgs) != total || orgs[len(orgs)-1] != int64(total) {
			t.Fatalf("pages from %d, %d orgs: got %d, %v %+v", c2.first, c2.total, len(orgs), err, gaps)
		}
	}
	ignorePage, total = true, orgsPerPage
	if _, _, err := c.orgs(context.Background()); err == nil {
		t.Fatal("a server that ignores the page number was read as having one page")
	}
}

// A datasource reference's uid can hold the datasource's name. Found by the v1 audit: a map
// reference {"uid": "<Loki name>"} resolved to nothing and its query was dropped.
func TestResolveMapReferenceByName(t *testing.T) {
	r := &orgReader{lokiByUID: map[string]bool{"l1": true}, lokiByName: map[string]string{"Loki": "l1"}}
	for _, c := range []struct {
		ref  map[string]any
		want []string
	}{
		{map[string]any{"uid": "Loki"}, []string{"l1"}},
		{map[string]any{"uid": "Loki", "type": "loki"}, []string{"l1"}},
		{map[string]any{"uid": "l1"}, []string{"l1"}},
		{map[string]any{"uid": "Loki", "type": "prometheus"}, nil},
		{map[string]any{"uid": "Prometheus"}, nil},
	} {
		if got, _ := r.resolve(c.ref); !slices.Equal(got, c.want) {
			t.Fatalf("%v: %v, want %v", c.ref, got, c.want)
		}
	}
}

// A datasource variable lists only datasources of its plugin type, so a panel on a Prometheus one
// never runs against Loki; any other variable may name any datasource. Found by measuring the public
// dashboard corpus: every Prometheus panel on a $datasource variable was read as a Loki query that
// does not parse, which blocks every rule.
func TestResolveDatasourceVariables(t *testing.T) {
	r := &orgReader{lokiByUID: map[string]bool{"l1": true}, lokiByName: map[string]string{},
		dsVars: map[string]string{"datasource": "prometheus", "logs": "loki", "templated": "$plugin"}}
	for _, c := range []struct {
		ref  any
		want []string
	}{
		{map[string]any{"uid": "${datasource}", "type": "prometheus"}, nil},
		{map[string]any{"uid": "$datasource"}, nil},
		{"$datasource", nil},
		{"${datasource:raw}", nil},
		{"[[datasource]]", nil},
		{map[string]any{"uid": "${logs}", "type": "loki"}, []string{AnyLoki}},
		{"$logs", []string{AnyLoki}},
		{"$undeclared", []string{AnyLoki}},                               // a custom or constant variable can hold a Loki UID
		{"$templated", []string{AnyLoki}},                                // the plugin type itself is templated
		{"loki-$datasource", []string{AnyLoki}},                          // built from several parts
		{map[string]any{"uid": "l1", "type": "${t}"}, []string{AnyLoki}}, // the type is a variable
	} {
		if got, _ := r.resolve(c.ref); !slices.Equal(got, c.want) {
			t.Fatalf("%v: %v, want %v", c.ref, got, c.want)
		}
	}
}

// Both schemas declare datasource variables; the reader takes each dashboard's own.
func TestDashboardDatasourceVariables(t *testing.T) {
	r := &orgReader{res: &Result{}, lokiByUID: map[string]bool{"l1": true}, lokiByName: map[string]string{}, libraries: map[string]bool{}}
	r.classicDashboard("c", map[string]any{
		"templating": map[string]any{"list": []any{map[string]any{"name": "ds", "type": "datasource", "query": "prometheus"}}},
		"panels": []any{
			map[string]any{"id": 1, "datasource": map[string]any{"uid": "${ds}", "type": "prometheus"}, "targets": []any{map[string]any{"refId": "A", "expr": `up`}}},
			map[string]any{"id": 2, "datasource": map[string]any{"uid": "l1", "type": "loki"}, "targets": []any{map[string]any{"refId": "A", "expr": `{a="b"}`}}},
		}})
	r.v2Dashboard("v", map[string]any{
		"variables": []any{map[string]any{"kind": "DatasourceVariable", "spec": map[string]any{"name": "ds", "pluginId": "loki"}}},
		"elements": map[string]any{"panel-1": map[string]any{"kind": "Panel", "spec": map[string]any{"data": map[string]any{"spec": map[string]any{"queries": []any{
			map[string]any{"spec": map[string]any{"query": map[string]any{"group": "loki", "datasource": map[string]any{"name": "${ds}"},
				"spec": map[string]any{"expr": `{c="d"}`}}}}}}}}}},
	})
	var got []string
	for _, q := range r.res.Queries {
		got = append(got, q.Origin+"="+strings.Join(q.Datasources, ","))
	}
	sort.Strings(got)
	if want := []string{"dashboard:c/panel:2/A=l1", "dashboard:v/panel-1/0=*"}; !slices.Equal(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
}
