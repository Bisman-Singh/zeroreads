//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/source/grafana"
)

const grafanaUser, grafanaPass = "admin", "e2e-only-password"

// grafanaCall performs one admin API call on the local e2e Grafana. It is only used to set up
// fixtures in the throwaway kind cluster.
func grafanaCall(t *testing.T, base, method, path string, org int64, body any) (int, []byte) {
	t.Helper()
	s, out, err := grafanaDo(base, method, path, org, body)
	if err != nil {
		t.Fatal(err)
	}
	return s, out
}

// grafanaDo is grafanaCall for goroutines, which must not stop the test themselves.
func grafanaDo(base, method, path string, org int64, body any) (int, []byte, error) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, r)
	req.SetBasicAuth(grafanaUser, grafanaPass)
	req.Header.Set("Content-Type", "application/json")
	if org > 0 {
		req.Header.Set("X-Grafana-Org-Id", fmt.Sprint(org))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, nil
}

// dropOrg empties an organisation the test created and deletes it. Grafana 13.2.2 refuses to delete
// an org at all ("failed to delete dashboards ... does not allow this method", even when it has
// none), so everything in it goes first; when the org itself is refused, it stays behind empty and
// renamed. Tests that create orgs run last (zz*_test.go), and every full run starts a new Grafana.
func dropOrg(t *testing.T, base string, org int64) {
	t.Helper()
	for {
		s, b := grafanaCall(t, base, "GET", "/api/search?type=dash-db&limit=1000", org, nil)
		must(t, s, b, http.StatusOK)
		var hits []struct {
			UID string `json:"uid"`
		}
		json.Unmarshal(b, &hits)
		if len(hits) == 0 {
			break
		}
		uids := make(chan string)
		var wg sync.WaitGroup
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for uid := range uids {
					for attempt := 0; attempt < 5; attempt++ {
						if s, _, err := grafanaDo(base, "DELETE", "/api/dashboards/uid/"+uid, org, nil); err == nil && (s == http.StatusOK || s == http.StatusNotFound) {
							break
						}
						time.Sleep(time.Duration(attempt+1) * time.Second) // SQLite can be briefly locked
					}
				}
			}()
		}
		for _, h := range hits {
			uids <- h.UID
		}
		close(uids)
		wg.Wait()
	}
	s, b := grafanaCall(t, base, "GET", "/api/library-elements?perPage=1000", org, nil)
	must(t, s, b, http.StatusOK)
	var libs struct {
		Result struct {
			Elements []struct {
				UID string `json:"uid"`
			} `json:"elements"`
		} `json:"result"`
	}
	json.Unmarshal(b, &libs)
	for _, l := range libs.Result.Elements {
		grafanaCall(t, base, "DELETE", "/api/library-elements/"+l.UID, org, nil)
	}
	s, b = grafanaCall(t, base, "GET", "/api/datasources", org, nil)
	must(t, s, b, http.StatusOK)
	var dss []struct {
		UID string `json:"uid"`
	}
	json.Unmarshal(b, &dss)
	for _, d := range dss {
		grafanaCall(t, base, "DELETE", "/api/datasources/uid/"+d.UID, org, nil)
	}
	s, b = grafanaCall(t, base, "GET", "/api/serviceaccounts/search?perpage=100", org, nil)
	must(t, s, b, http.StatusOK)
	var sas struct {
		ServiceAccounts []struct {
			ID int64 `json:"id"`
		} `json:"serviceAccounts"`
	}
	json.Unmarshal(b, &sas)
	for _, sa := range sas.ServiceAccounts {
		grafanaCall(t, base, "DELETE", fmt.Sprintf("/api/serviceaccounts/%d", sa.ID), org, nil)
	}
	s, b = grafanaCall(t, base, "DELETE", fmt.Sprintf("/api/orgs/%d", org), 0, nil)
	switch {
	case s == http.StatusOK:
	case s == http.StatusInternalServerError && strings.Contains(string(b), "Failed to delete organization"):
		s, b = grafanaCall(t, base, "PUT", fmt.Sprintf("/api/orgs/%d", org), 0, map[string]any{"name": fmt.Sprintf("sievelog-emptied-%d", org)})
		must(t, s, b, http.StatusOK)
		t.Logf("grafana refused to delete org %d; it is empty and renamed", org)
	default:
		t.Fatalf("delete org %d: %d %s", org, s, b)
	}
}

func must(t *testing.T, status int, body []byte, ok ...int) {
	t.Helper()
	for _, s := range ok {
		if status == s {
			return
		}
	}
	t.Fatalf("status %d: %s", status, body)
}

func setupGrafanaFixtures(t *testing.T, base string) {
	t.Helper()
	// Library panel referenced by the provisioned dashboard.
	s, b := grafanaCall(t, base, "POST", "/api/library-elements", 1, map[string]any{
		"uid": "lib-login", "name": "Logins (library)", "kind": 1,
		"model": map[string]any{"type": "logs", "title": "Logins", "datasource": map[string]any{"type": "loki", "uid": "loki"},
			"targets": []any{map[string]any{"refId": "A", "expr": `{service_name="auth"} |= "logged in"`}}},
	})
	must(t, s, b, 200, 400, 409) // 400/409: already exists from an earlier run
	// Explore short link.
	panes, _ := json.Marshal(map[string]any{"x1": map[string]any{"datasource": "loki", "queries": []any{
		map[string]any{"refId": "A", "expr": `{service_name="checkout"} |= "declined"`, "datasource": map[string]any{"type": "loki", "uid": "loki"}}}}})
	s, b = grafanaCall(t, base, "POST", "/api/short-urls", 1, map[string]any{"path": "explore?schemaVersion=1&orgId=1&panes=" + url.QueryEscape(string(panes))})
	must(t, s, b, 200)
	// Legacy-format Explore short link.
	left, _ := json.Marshal(map[string]any{"datasource": "loki", "queries": []any{map[string]any{"refId": "A", "expr": `{service_name="auth"} |= "failed MFA"`}}})
	s, b = grafanaCall(t, base, "POST", "/api/short-urls", 1, map[string]any{"path": "explore?orgId=1&left=" + url.QueryEscape(string(left))})
	must(t, s, b, 200)
	// Query history.
	s, b = grafanaCall(t, base, "POST", "/api/query-history", 1, map[string]any{"datasourceUid": "loki",
		"queries": []any{map[string]any{"refId": "A", "expr": `{service_name="orders"} |= "failed at step"`, "datasource": map[string]any{"type": "loki", "uid": "loki"}}}})
	must(t, s, b, 200)
	// Correlation.
	s, b = grafanaCall(t, base, "POST", "/api/datasources/uid/loki/correlations", 1, map[string]any{"targetUID": "loki", "label": "same service", "type": "query",
		"config": map[string]any{"field": "service_name", "target": map[string]any{"expr": `{service_name="${service_name}"} |= "retrying"`}}})
	must(t, s, b, 200)
	// A dashboard stored natively in the v2 schema.
	v2 := map[string]any{
		"apiVersion": "dashboard.grafana.app/v2", "kind": "Dashboard", "metadata": map[string]any{"name": "v2-native"},
		"spec": map[string]any{
			"title": "V2 native", "annotations": []any{}, "cursorSync": "Off", "editable": true, "links": []any{},
			"liveNow": false, "preload": false, "tags": []any{}, "variables": []any{},
			"timeSettings": map[string]any{"from": "now-1h", "to": "now", "autoRefresh": "", "autoRefreshIntervals": []any{}, "hideTimepicker": false, "fiscalYearStartMonth": 0},
			"elements": map[string]any{"panel-1": map[string]any{"kind": "Panel", "spec": map[string]any{
				"id": 1, "title": "Heartbeats", "description": "", "links": []any{},
				"data": map[string]any{"kind": "QueryGroup", "spec": map[string]any{"transformations": []any{}, "queryOptions": map[string]any{},
					"queries": []any{map[string]any{"kind": "PanelQuery", "spec": map[string]any{"refId": "A", "hidden": false,
						"query": map[string]any{"kind": "DataQuery", "group": "loki", "version": "v0", "datasource": map[string]any{"name": "loki"},
							"spec": map[string]any{"expr": `{service_name="checkout"} |= "healthz 200"`}}}}}}},
				"vizConfig": map[string]any{"kind": "VizConfig", "group": "logs", "version": "", "spec": map[string]any{"options": map[string]any{}, "fieldConfig": map[string]any{"defaults": map[string]any{}, "overrides": []any{}}}},
			}}},
			"layout": map[string]any{"kind": "GridLayout", "spec": map[string]any{"items": []any{map[string]any{"kind": "GridLayoutItem",
				"spec": map[string]any{"x": 0, "y": 0, "width": 12, "height": 8, "element": map[string]any{"kind": "ElementReference", "name": "panel-1"}}}}}},
		},
	}
	s, b = grafanaCall(t, base, "POST", "/apis/dashboard.grafana.app/v2/namespaces/default/dashboards", 1, v2)
	must(t, s, b, 200, 201, 409)
	// A second org with its own Loki datasource and dashboard.
	s, b = grafanaCall(t, base, "POST", "/api/orgs", 0, map[string]any{"name": "Second"})
	must(t, s, b, 200, 409)
	// Its ID depends on how many orgs other tests created before it, so look it up by name.
	s, b = grafanaCall(t, base, "GET", "/api/orgs/name/Second", 0, nil)
	must(t, s, b, 200)
	var second struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(b, &second)
	s, b = grafanaCall(t, base, "POST", "/api/datasources", second.ID, map[string]any{"name": "Loki2", "uid": "loki2", "type": "loki", "access": "proxy", "url": "http://loki.sievelog-system.svc:3100", "isDefault": true})
	must(t, s, b, 200, 409)
	s, b = grafanaCall(t, base, "POST", "/api/dashboards/db", second.ID, map[string]any{"overwrite": true, "dashboard": map[string]any{
		"uid": "org2-dash", "title": "Org 2", "schemaVersion": 41,
		"panels": []any{map[string]any{"id": 1, "type": "logs", "datasource": map[string]any{"type": "loki", "uid": "loki2"},
			"targets": []any{map[string]any{"refId": "A", "expr": `{service_name="orders"} |= "handled route"`}}}}}})
	must(t, s, b, 200)
}

func TestGrafanaReadsEveryStoredQuery(t *testing.T) {
	base := env(t, "GRAFANA_URL")
	setupGrafanaFixtures(t, base)
	c := &grafana.Client{Base: base, Username: grafanaUser, Password: grafanaPass}
	res, err := c.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := map[string][]string{}
	for _, q := range res.Queries {
		found[q.Expr] = append(found[q.Expr], fmt.Sprintf("org%d %s %v hidden=%v", q.Org, q.Origin, q.Datasources, q.Hidden))
	}
	want := []string{
		`{service_name="orders"} |= "created"`,                                 // disabled annotation
		`{service_name="checkout"} |= "healthz"`,                               // panel
		`sum(count_over_time({service_name=~"$svc"} |= "declined" [$__auto]))`, // variables
		`{service_name="checkout"} |= "retrying"`,                              // collapsed row
		`sum(rate({service_name="orders"}[1m]))`,                               // mixed panel
		`{service_name="auth"} |= "config placeholder"`,                        // hidden target, default datasource
		`{service_name="auth"} |= "logged in"`,                                 // library panel
		`sum(count_over_time({service_name="auth"} |= "failed MFA" [5m]))`,     // alert rule
		`{service_name="checkout"} |= "declined"`,                              // short URL, panes format
		`{service_name="auth"} |= "failed MFA"`,                                // short URL, legacy left format
		`{service_name="orders"} |= "failed at step"`,                          // query history
		`{service_name="${service_name}"} |= "retrying"`,                       // correlation
		`{service_name="checkout"} |= "healthz 200"`,                           // v2-native dashboard
		`{service_name="orders"} |= "handled route"`,                           // second org
	}
	for _, w := range want {
		if len(found[w]) == 0 {
			t.Errorf("not found: %s", w)
		}
	}
	if len(found["up"]) != 0 {
		t.Errorf("a Prometheus query was attributed to Loki: %v", found["up"])
	}
	gaps := map[string]bool{}
	for _, g := range res.Gaps {
		gaps[g.Reason] = true
		t.Logf("gap: org%d %s: %s", g.Org, g.Origin, g.Reason)
	}
	// A panel whose library panel was deleted reads nothing: a note, never a gap that blocks rules.
	notes := map[string]bool{}
	for _, n := range res.Notes {
		notes[n.Reason] = true
	}
	if !anyContains(notes, `library panel "lib-missing" does not exist`) || anyContains(gaps, "lib-missing") {
		t.Errorf("the deleted library panel must be a note, not a gap: notes %v", notes)
	}
	if !anyContains(gaps, "only the history of the user") {
		t.Error("the query-history limitation was not reported")
	}
	if len(res.Orgs) != 2 {
		t.Errorf("orgs %v, want 2", res.Orgs)
	}
	if t.Failed() {
		for e, o := range found {
			t.Logf("found %s <- %v", e, o)
		}
	}
	t.Logf("%d stored queries across %d orgs, %d gaps", len(res.Queries), len(res.Orgs), len(res.Gaps))
}

func anyContains(m map[string]bool, sub string) bool {
	for k := range m {
		if strings.Contains(k, sub) {
			return true
		}
	}
	return false
}

// grafanaGap is the key the report gives a gap that holds for a whole Grafana, such as other users'
// query history: the kind and the Grafana's host.
func grafanaGap(kind, url string) string {
	return "grafana-" + kind + ":" + strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://"), "/")
}
