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
	"testing"

	"github.com/Bisman-Singh/sievelog/internal/source/grafana"
)

const grafanaUser, grafanaPass = "admin", "e2e-only-password"

// grafanaCall performs one admin API call on the local e2e Grafana. It is only used to set up
// fixtures in the throwaway kind cluster.
func grafanaCall(t *testing.T, base, method, path string, org int64, body any) (int, []byte) {
	t.Helper()
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
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
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
	s, b = grafanaCall(t, base, "POST", "/api/datasources", 2, map[string]any{"name": "Loki2", "uid": "loki2", "type": "loki", "access": "proxy", "url": "http://loki.sievelog-system.svc:3100", "isDefault": true})
	must(t, s, b, 200, 409)
	s, b = grafanaCall(t, base, "POST", "/api/dashboards/db", 2, map[string]any{"overwrite": true, "dashboard": map[string]any{
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
	if !anyContains(gaps, `library panel "lib-missing" does not exist`) {
		t.Error("the deleted library panel was not reported")
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
