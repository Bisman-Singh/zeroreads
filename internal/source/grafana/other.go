package grafana

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func (r *orgReader) loadLibraries(ctx context.Context) {
	if r.libraries != nil {
		return
	}
	r.libraries = map[string]bool{}
	for page := 1; ; page++ {
		var resp struct {
			Result struct {
				TotalCount int `json:"totalCount"`
				Elements   []struct {
					UID   string         `json:"uid"`
					Model map[string]any `json:"model"`
				} `json:"elements"`
			} `json:"result"`
		}
		if err := r.c.do(ctx, r.org, fmt.Sprintf("/api/library-elements?kind=1&perPage=100&page=%d", page), &resp); err != nil {
			r.gap("librarypanels", "list: %v", err)
			return
		}
		for _, e := range resp.Result.Elements {
			r.libraries[e.UID] = true
			r.classicPanels("librarypanel:"+e.UID, []any{withoutLibraryRef(e.Model)})
		}
		if len(resp.Result.Elements) == 0 || page*100 >= resp.Result.TotalCount {
			return
		}
	}
}

// libraryPanels is read together with dashboards (loadLibraries) so references can be checked.
func (r *orgReader) libraryPanels(ctx context.Context) { r.loadLibraries(ctx) }

func withoutLibraryRef(m map[string]any) map[string]any {
	c := map[string]any{}
	for k, v := range m {
		if k != "libraryPanel" {
			c[k] = v
		}
	}
	if _, ok := c["id"]; !ok {
		c["id"] = "model"
	}
	return c
}

// alertRules reads Grafana-managed alert and recording rules.
func (r *orgReader) alertRules(ctx context.Context) {
	var rules []struct {
		UID    string `json:"uid"`
		Title  string `json:"title"`
		Record *struct {
			Metric string `json:"metric"`
		} `json:"record"`
		Data []struct {
			DatasourceUID string         `json:"datasourceUid"`
			Model         map[string]any `json:"model"`
		} `json:"data"`
	}
	if err := r.c.do(ctx, r.org, "/api/v1/provisioning/alert-rules", &rules); err != nil {
		r.gap("alertrules", "list: %v", err)
		return
	}
	for _, rule := range rules {
		kind := "alertrule"
		if rule.Record != nil {
			kind = "recordingrule"
		}
		for i, d := range rule.Data {
			if d.DatasourceUID == "__expr__" || d.DatasourceUID == "-100" {
				continue // server-side expressions do not read logs
			}
			uids, _ := r.resolve(map[string]any{"uid": d.DatasourceUID})
			expr, _ := d.Model["expr"].(string)
			r.add(fmt.Sprintf("%s:%s/%d", kind, rule.UID, i), uids, expr, false)
		}
	}
}

// shortURLs reads stored short links. Explore links carry their queries in the path, in the
// current "panes" format or the legacy "left"/"right" format.
func (r *orgReader) shortURLs(ctx context.Context) {
	items, err := r.listK8s(ctx, "shorturl.grafana.app", "v1beta1", "shorturls")
	if err != nil {
		r.gap("shorturls", "list: %v", err)
		return
	}
	for _, raw := range items {
		var s struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Path string `json:"path"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			r.gap("shorturls", "decode: %v", err)
			continue
		}
		origin := "shorturl:" + s.Metadata.Name
		path := s.Spec.Path
		if !strings.HasPrefix(strings.TrimPrefix(path, "/"), "explore") {
			continue // links to dashboards are covered by the dashboards themselves
		}
		u, err := url.Parse("/" + strings.TrimPrefix(path, "/"))
		if err != nil {
			r.gap(origin, "bad path: %v", err)
			continue
		}
		q := u.Query()
		found := false
		if panes := q.Get("panes"); panes != "" {
			var m map[string]explorePane
			if err := json.Unmarshal([]byte(panes), &m); err != nil {
				r.gap(origin, "panes: %v", err)
				continue
			}
			for name, pane := range m {
				found = r.explorePane(origin+"/"+name, pane) || found
			}
		}
		for _, side := range []string{"left", "right"} {
			if v := q.Get(side); v != "" {
				var pane explorePane
				if err := json.Unmarshal([]byte(v), &pane); err != nil {
					r.gap(origin, "%s: %v", side, err)
					continue
				}
				found = r.explorePane(origin+"/"+side, pane) || found
			}
		}
		if !found {
			r.gap(origin, "explore link without readable queries")
		}
	}
}

// explorePane is one pane of an Explore link: its datasource and its queries.
type explorePane struct {
	Datasource any              `json:"datasource"`
	Queries    []map[string]any `json:"queries"`
}

// explorePane adds a pane's queries and reports whether it had any.
func (r *orgReader) explorePane(origin string, pane explorePane) bool {
	paneDS, _ := r.resolve(pane.Datasource)
	for i, q := range pane.Queries {
		r.exploreQuery(fmt.Sprintf("%s/%d", origin, i), paneDS, q)
	}
	return len(pane.Queries) > 0
}

func (r *orgReader) exploreQuery(origin string, paneDS []string, q map[string]any) {
	ds, inherit := r.resolve(q["datasource"])
	if inherit {
		ds = paneDS
	}
	expr, _ := q["expr"].(string)
	r.add(origin, ds, expr, false)
}

// queryHistory reads the Explore history visible to the credentials' user. Other users' history is
// not readable through the API; that is reported as a gap.
func (r *orgReader) queryHistory(ctx context.Context) {
	for page := 1; ; page++ {
		var resp struct {
			Result struct {
				TotalCount   int `json:"totalCount"`
				QueryHistory []struct {
					UID           string           `json:"uid"`
					DatasourceUID string           `json:"datasourceUid"`
					Queries       []map[string]any `json:"queries"`
				} `json:"queryHistory"`
			} `json:"result"`
		}
		if err := r.c.do(ctx, r.org, fmt.Sprintf("/api/query-history?limit=100&page=%d", page), &resp); err != nil {
			r.gap("queryhistory", "list: %v", err)
			return
		}
		for _, h := range resp.Result.QueryHistory {
			paneDS, _ := r.resolve(h.DatasourceUID)
			for i, q := range h.Queries {
				r.exploreQuery(fmt.Sprintf("queryhistory:%s/%d", h.UID, i), paneDS, q)
			}
		}
		if len(resp.Result.QueryHistory) == 0 || page*100 >= resp.Result.TotalCount {
			break
		}
	}
	r.gap("queryhistory", "only the history of the user these credentials belong to is readable")
}

// correlations reads query correlations that target a Loki datasource.
func (r *orgReader) correlations(ctx context.Context) {
	for page := 1; ; page++ {
		var resp struct {
			Correlations []struct {
				UID       string `json:"uid"`
				TargetUID string `json:"targetUID"`
				Type      string `json:"type"`
				Config    struct {
					Target map[string]any `json:"target"`
				} `json:"config"`
			} `json:"correlations"`
			TotalCount int `json:"totalCount"`
		}
		if err := r.c.do(ctx, r.org, fmt.Sprintf("/api/datasources/correlations?limit=100&page=%d", page), &resp); err != nil {
			r.gap("correlations", "list: %v", err)
			return
		}
		for _, c := range resp.Correlations {
			if c.Type != "" && c.Type != "query" {
				continue // external links do not run queries
			}
			ds, _ := r.resolve(c.TargetUID)
			expr, _ := c.Config.Target["expr"].(string)
			r.add("correlation:"+c.UID, ds, expr, false)
		}
		if len(resp.Correlations) == 0 || page*100 >= resp.TotalCount {
			return
		}
	}
}
