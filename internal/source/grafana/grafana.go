// Package grafana reads every stored place a Loki query can live in Grafana: dashboards (classic
// and v2 schema, panels, collapsed rows, annotations), library panels, alert and recording rules,
// short URLs (Explore links), query history and correlations. It only reads.
package grafana

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Client reads one Grafana.
type Client struct {
	Base     string
	Token    string // service account token; or basic auth below
	Username string
	Password string
	HTTP     *http.Client
}

// Query is one stored Loki query.
type Query struct {
	Org         int64
	Origin      string   // e.g. dashboard:checkout-e2e/panel:4, librarypanel:lib-login, alertrule:mfa-failures
	Datasources []string // Loki datasource UIDs the query can run against; AnyLoki when unresolvable
	Expr        string
	Hidden      bool // stored but disabled; it can be re-enabled at any time, so it still counts
}

// AnyLoki marks a query whose datasource is a variable or otherwise unresolved: it may run
// against any Loki datasource.
const AnyLoki = "*"

// Gap is something that could not be read; it makes the evidence incomplete.
type Gap struct {
	Org    int64
	Origin string
	Reason string
}

// Result is everything read from Grafana.
type Result struct {
	Queries []Query
	Gaps    []Gap
	Orgs    []int64
	// LokiDatasources maps Loki datasource UID to its URL, per org.
	LokiDatasources map[int64]map[string]string
}

func (c *Client) do(ctx context.Context, org int64, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.Base, "/")+path, nil)
	if err != nil {
		return err
	}
	if org > 0 {
		req.Header.Set("X-Grafana-Org-Id", strconv.FormatInt(org, 10))
	}
	switch {
	case c.Token != "":
		req.Header.Set("Authorization", "Bearer "+c.Token)
	case c.Username != "":
		req.SetBasicAuth(c.Username, c.Password)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("grafana: %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("grafana: %s: decode: %w", path, err)
	}
	return nil
}

// namespace is the Kubernetes-style namespace Grafana uses for an org.
func namespace(org int64) string {
	if org == 1 {
		return "default"
	}
	return "org-" + strconv.FormatInt(org, 10)
}

// Read collects every stored Loki query from every org the credentials can see.
func (c *Client) Read(ctx context.Context) (Result, error) {
	res := Result{LokiDatasources: map[int64]map[string]string{}}
	orgs, err := c.orgs(ctx)
	if err != nil {
		return res, err
	}
	res.Orgs = orgs
	for _, org := range orgs {
		r := &orgReader{c: c, org: org, res: &res}
		if err := r.datasources(ctx); err != nil {
			res.Gaps = append(res.Gaps, Gap{Org: org, Origin: "datasources", Reason: err.Error()})
			continue // without datasources no query can be attributed; everything in this org is a gap
		}
		r.dashboards(ctx)
		r.libraryPanels(ctx)
		r.alertRules(ctx)
		r.shortURLs(ctx)
		r.queryHistory(ctx)
		r.correlations(ctx)
	}
	sort.SliceStable(res.Queries, func(i, j int) bool {
		if res.Queries[i].Org != res.Queries[j].Org {
			return res.Queries[i].Org < res.Queries[j].Org
		}
		return res.Queries[i].Origin < res.Queries[j].Origin
	})
	return res, nil
}

// orgs lists orgs visible to a server admin; a non-admin token sees only its own org.
func (c *Client) orgs(ctx context.Context) ([]int64, error) {
	var all []struct {
		ID int64 `json:"id"`
	}
	if err := c.do(ctx, 0, "/api/orgs?perpage=1000", &all); err == nil && len(all) > 0 {
		var out []int64
		for _, o := range all {
			out = append(out, o.ID)
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out, nil
	}
	var cur struct {
		ID int64 `json:"id"`
	}
	if err := c.do(ctx, 0, "/api/org", &cur); err != nil {
		return nil, err
	}
	return []int64{cur.ID}, nil
}

type orgReader struct {
	c   *Client
	org int64
	res *Result

	lokiByUID  map[string]bool
	lokiByName map[string]string // name -> uid
	defaultDS  struct{ uid, typ string }
	libraries  map[string]bool // library panel UIDs that exist
}

func (r *orgReader) gap(origin, format string, a ...any) {
	r.res.Gaps = append(r.res.Gaps, Gap{Org: r.org, Origin: origin, Reason: fmt.Sprintf(format, a...)})
}

func (r *orgReader) add(origin string, ds []string, expr string, hidden bool) {
	if strings.TrimSpace(expr) == "" || len(ds) == 0 {
		return
	}
	r.res.Queries = append(r.res.Queries, Query{Org: r.org, Origin: origin, Datasources: ds, Expr: expr, Hidden: hidden})
}

func (r *orgReader) datasources(ctx context.Context) error {
	var list []struct {
		UID       string `json:"uid"`
		Name      string `json:"name"`
		Type      string `json:"type"`
		URL       string `json:"url"`
		IsDefault bool   `json:"isDefault"`
	}
	if err := r.c.do(ctx, r.org, "/api/datasources", &list); err != nil {
		return err
	}
	r.lokiByUID = map[string]bool{}
	r.lokiByName = map[string]string{}
	r.res.LokiDatasources[r.org] = map[string]string{}
	for _, d := range list {
		if d.IsDefault {
			r.defaultDS.uid, r.defaultDS.typ = d.UID, d.Type
		}
		if d.Type == "loki" {
			r.lokiByUID[d.UID] = true
			r.lokiByName[d.Name] = d.UID
			r.res.LokiDatasources[r.org][d.UID] = d.URL
		}
	}
	return nil
}

func isVariable(s string) bool { return strings.Contains(s, "$") || strings.Contains(s, "[[") }

// resolve maps a datasource reference to the Loki UIDs it can run against. It returns nil for a
// non-Loki datasource, and inherit=true when the query inherits the panel's datasource.
func (r *orgReader) resolve(ref any) (uids []string, inherit bool) {
	switch v := ref.(type) {
	case nil:
		return nil, true
	case string:
		if v == "" {
			return nil, true
		}
		if isVariable(v) {
			return []string{AnyLoki}, false
		}
		if r.lokiByUID[v] {
			return []string{v}, false
		}
		if uid, ok := r.lokiByName[v]; ok {
			return []string{uid}, false
		}
		return nil, false
	case map[string]any:
		uid, _ := v["uid"].(string)
		typ, _ := v["type"].(string)
		if uid == "" && typ == "" {
			return nil, true
		}
		if isVariable(uid) || isVariable(typ) {
			return []string{AnyLoki}, false
		}
		if uid == "" {
			if typ == "loki" {
				if r.defaultDS.typ == "loki" {
					return []string{r.defaultDS.uid}, false
				}
				return []string{AnyLoki}, false
			}
			return nil, typ == "datasource"
		}
		if r.lokiByUID[uid] {
			return []string{uid}, false
		}
		if typ == "loki" {
			return []string{AnyLoki}, false // a Loki datasource this org cannot see: may be any Loki
		}
		return nil, uid == "-- Mixed --"
	}
	return []string{AnyLoki}, false
}

func (r *orgReader) defaultLoki() []string {
	if r.defaultDS.typ == "loki" {
		return []string{r.defaultDS.uid}
	}
	return nil
}

// listK8s pages through a Kubernetes-style list and returns raw items.
func (r *orgReader) listK8s(ctx context.Context, group, version, resource string) ([]json.RawMessage, error) {
	var out []json.RawMessage
	cont := ""
	for {
		path := fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s?limit=100", group, version, namespace(r.org), resource)
		if cont != "" {
			path += "&continue=" + url.QueryEscape(cont)
		}
		var page struct {
			Items    []json.RawMessage `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := r.c.do(ctx, r.org, path, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if page.Metadata.Continue == "" {
			return out, nil
		}
		cont = page.Metadata.Continue
	}
}
