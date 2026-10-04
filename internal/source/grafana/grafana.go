// Package grafana reads every stored place a Loki query can live in Grafana: dashboards (classic
// and v2 schema, panels, collapsed rows, annotations), library panels, alert and recording rules,
// short URLs (Explore links), query history and correlations. It only reads.
package grafana

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/fetch"
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
	// Notes are findings that hide no reader, such as a panel whose library panel does not exist.
	Notes []Gap
	Orgs  []int64
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
	res, err := fetch.Do(ctx, hc, req)
	if err != nil {
		return err
	}
	if res.Status != http.StatusOK {
		return &HTTPError{Path: path, Status: res.Status, Body: fetch.Excerpt(res.Body)}
	}
	body := res.Body
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("grafana: %s: decode: %w", path, err)
	}
	return nil
}

// HTTPError is a non-200 answer from Grafana.
type HTTPError struct {
	Path   string
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("grafana: %s: HTTP %d: %s", e.Path, e.Status, e.Body)
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
	orgs, gaps, err := c.orgs(ctx)
	if err != nil {
		return res, err
	}
	res.Orgs, res.Gaps = orgs, gaps
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
	res.Queries = dedupeViews(res.Queries)
	sort.SliceStable(res.Queries, func(i, j int) bool {
		if res.Queries[i].Org != res.Queries[j].Org {
			return res.Queries[i].Org < res.Queries[j].Org
		}
		return res.Queries[i].Origin < res.Queries[j].Origin
	})
	return res, nil
}

// orgsPerPage is the page size for listing orgs.
const orgsPerPage = 1000

// orgs lists every org. Only a server admin can list them: other credentials (every service account
// token, which belongs to one org) are refused, read their own org only, and the other orgs stay
// unknown, which is a gap.
func (c *Client) orgs(ctx context.Context) ([]int64, []Gap, error) {
	seen := map[int64]bool{}
	var out []int64
	stalled := 0
	// Grafana 13 numbers pages from 0 (page=1 is the second page); versions that number them from 1
	// return the first page twice. Reading from 0 and skipping repeats is right for both.
	for page := 0; ; page++ {
		var batch []struct {
			ID int64 `json:"id"`
		}
		err := c.do(ctx, 0, fmt.Sprintf("/api/orgs?perpage=%d&page=%d", orgsPerPage, page), &batch)
		var he *HTTPError
		if page == 0 && errors.As(err, &he) && (he.Status == http.StatusUnauthorized || he.Status == http.StatusForbidden) {
			return c.ownOrg(ctx, he)
		}
		if err != nil {
			return nil, nil, err
		}
		added := 0
		for _, o := range batch {
			if !seen[o.ID] {
				seen[o.ID] = true
				out = append(out, o.ID)
				added++
			}
		}
		if len(batch) < orgsPerPage {
			break
		}
		if added == 0 {
			if stalled++; stalled == 2 {
				return nil, nil, fmt.Errorf("grafana: /api/orgs returns the same page whatever the page number, so orgs beyond the first %d are unknown", len(out))
			}
		} else {
			stalled = 0
		}
	}
	if len(out) == 0 {
		return nil, nil, fmt.Errorf("grafana: /api/orgs listed no org")
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil, nil
}

// ownOrg reads the credentials' own org when they cannot list orgs, with a gap for the rest.
func (c *Client) ownOrg(ctx context.Context, refused *HTTPError) ([]int64, []Gap, error) {
	var cur struct {
		ID int64 `json:"id"`
	}
	if err := c.do(ctx, 0, "/api/org", &cur); err != nil {
		return nil, nil, err
	}
	gap := Gap{Org: cur.ID, Origin: "orgs", Reason: fmt.Sprintf("these credentials cannot list organisations (HTTP %d), so only org %d was read; "+
		"dashboards, alerts and links in any other org are unseen. Use a server admin's credentials, or acknowledge if this Grafana has one org", refused.Status, cur.ID)}
	return []int64{cur.ID}, []Gap{gap}, nil
}

type orgReader struct {
	c   *Client
	org int64
	res *Result

	lokiByUID  map[string]bool
	lokiByName map[string]string // name -> uid
	defaultDS  struct{ uid, typ string }
	libraries  map[string]bool // library panel UIDs that exist
	// dsVars are the datasource variables of the dashboard being read: name -> the plugin type whose
	// datasources it lists. Such a variable only ever holds a datasource of that type.
	dsVars map[string]string
}

func (r *orgReader) gap(origin, format string, a ...any) {
	r.res.Gaps = append(r.res.Gaps, Gap{Org: r.org, Origin: origin, Reason: fmt.Sprintf(format, a...)})
}

func (r *orgReader) note(origin, format string, a ...any) {
	r.res.Notes = append(r.res.Notes, Gap{Org: r.org, Origin: origin, Reason: fmt.Sprintf(format, a...)})
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
			r.res.LokiDatasources[r.org][d.UID] = withoutUserinfo(d.URL)
		}
	}
	return nil
}

// withoutUserinfo is a datasource URL without a user name or password in it: the URL is compared with
// loki.url and shown in reports, verify's output and a job's step summary.
func withoutUserinfo(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "(a URL that does not parse)"
	}
	u.User = nil
	return u.String()
}

func isVariable(s string) bool { return strings.Contains(s, "$") || strings.Contains(s, "[[") }

// variableRef matches a reference that is exactly one variable: $name, ${name}, ${name:format} or
// [[name]].
var variableRef = regexp.MustCompile(`\A(?:\$([A-Za-z0-9_]+)|\$\{([A-Za-z0-9_]+)(?::[^}]*)?\}|\[\[([A-Za-z0-9_]+)(?::[^\]]*)?\]\])\z`)

// variableDatasource resolves a datasource reference that is a variable. A datasource variable of
// the dashboard lists only datasources of its plugin type, so one of another type never runs
// against Loki. Anything else (another kind of variable, a reference built from several parts, a
// variable this dashboard does not declare) may name any datasource, so it may be any Loki.
func (r *orgReader) variableDatasource(ref string) []string {
	m := variableRef.FindStringSubmatch(ref)
	if m == nil {
		return []string{AnyLoki}
	}
	plugin, declared := r.dsVars[m[1]+m[2]+m[3]]
	if declared && plugin != "" && plugin != "loki" && !isVariable(plugin) {
		return nil
	}
	return []string{AnyLoki}
}

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
			return r.variableDatasource(v), false
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
		if isVariable(typ) {
			return []string{AnyLoki}, false
		}
		if isVariable(uid) {
			return r.variableDatasource(uid), false
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
		if id, ok := r.lokiByName[uid]; ok && (typ == "" || typ == "loki") {
			return []string{id}, false // Grafana also looks a reference's uid up as a datasource name
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

// listK8sStable lists a resource until two consecutive lists name the same objects (at most four
// lists) and returns every object any of them named, by name. Grafana 13.2.2 sometimes answers a
// list with no items and a success status right after writes; for a resource with no second API to
// check against, two agreeing lists are the evidence that nothing was left out.
func (r *orgReader) listK8sStable(ctx context.Context, group, version, resource string) ([]json.RawMessage, error) {
	union := map[string]json.RawMessage{}
	var prev map[string]bool
	var undecodable []json.RawMessage
	for attempt := 0; attempt < 4; attempt++ {
		items, err := r.listK8s(ctx, group, version, resource)
		if err != nil {
			return nil, err
		}
		names := map[string]bool{}
		undecodable = nil
		for _, raw := range items {
			var m struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			}
			if err := json.Unmarshal(raw, &m); err != nil {
				undecodable = append(undecodable, raw) // the caller decodes it again and reports it
				continue
			}
			names[m.Metadata.Name] = true
			union[m.Metadata.Name] = raw
		}
		if prev != nil && maps.Equal(prev, names) || !sleepCtx(ctx, 300*time.Millisecond) {
			break
		}
		prev = names
	}
	out := undecodable
	for _, name := range slices.Sorted(maps.Keys(union)) {
		out = append(out, union[name])
	}
	return out, nil
}

// dedupeViews drops a dashboard query already seen in another schema view of the same dashboard:
// Grafana serves every dashboard as v1 and v2, and both views carry the same queries.
func dedupeViews(qs []Query) []Query {
	seen := map[string]bool{}
	var out []Query
	for _, q := range qs {
		k := ""
		if strings.HasPrefix(q.Origin, "dashboard:") {
			dash := strings.SplitN(strings.TrimPrefix(q.Origin, "dashboard:"), "/", 2)[0]
			k = fmt.Sprintf("%d|%s|%s|%v|%v", q.Org, dash, q.Expr, q.Datasources, q.Hidden)
			if seen[k] {
				continue
			}
			seen[k] = true
		}
		out = append(out, q)
	}
	return out
}
