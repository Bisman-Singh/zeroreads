// Package opensearch reads usage evidence from OpenSearch: every search request recorded by the
// security plugin's audit log, alerting monitors, and OpenSearch Dashboards saved objects. It only
// reads.
//
// The model is deliberately coarse and sound. A request or stored query is assumed to read every line
// of every service in the indices it targets, unless its target indices provably do not overlap the
// indices holding the logs, or an exact term/terms filter on the service field provably selects other
// services. Full-text queries, KQL, Lucene strings, SQL and PPL are never interpreted.
package opensearch

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
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

// Header marks the analyzer's own requests; audit entries carrying it are not usage.
const Header = "X-Sievelog"

// Client talks to one OpenSearch cluster.
type Client struct {
	Base               string
	Username, Password string
	InsecureSkipVerify bool // for self-signed clusters
	HTTP               *http.Client
	untagged           bool // probe requests are sent like any client's, so the audit log records them
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if !c.untagged {
		req.Header.Set(Header, "1")
	}
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	hc := c.HTTP
	if hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if c.InsecureSkipVerify {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit operator choice
		}
		hc = &http.Client{Timeout: 60 * time.Second, Transport: tr}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("opensearch: %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

// Use is one reading request or stored query.
type Use struct {
	Source  string   // audit | monitor | savedobject
	Origin  string   // path or object id
	Indices []string // index expressions it targets; empty means all indices
	Query   json.RawMessage
	// Opaque is true when the query language is not the DSL (SQL, PPL, KQL, Lucene): nothing is
	// interpreted and it reads everything in its indices.
	Opaque bool
	When   time.Time // last seen
	Count  int       // audited executions folded into this use; 0 for stored queries
}

// Gap is evidence that could not be read.
type Gap struct{ Key, Origin, Reason string }

// Result is everything read.
type Result struct {
	Uses  []Use
	Gaps  []Gap
	Notes []string
	Lines int // audit entries read
}

// Reader reads one cluster's evidence.
type Reader struct {
	C *Client
	// AuditIndex is the audit log index pattern, e.g. security-auditlog-*.
	AuditIndex string
	// DashboardsIndex is the saved objects index pattern, e.g. .kibana*.
	DashboardsIndex string
	// ProveLive sends a marker search and waits until the audit log records it.
	ProveLive    bool
	ProveTimeout time.Duration
}

// probePrefix names the marker index a liveness probe searches; it never exists.
const probePrefix = "sievelog-probe-"

// Read collects uses in [start, end).
func (r *Reader) Read(ctx context.Context, start, end time.Time) Result {
	var res Result
	r.checkAuditConfig(ctx, &res)
	if r.ProveLive {
		if err := r.proveLive(ctx); err != nil {
			res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-not-live", Origin: r.AuditIndex, Reason: err.Error()})
		}
	}
	if err := r.readAudit(ctx, start, end, &res); err != nil {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-unreadable", Origin: r.AuditIndex, Reason: err.Error()})
	} else if err := r.checkAuditWindow(ctx, start, &res); err != nil {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-unreadable", Origin: r.AuditIndex, Reason: err.Error()})
	}
	if err := r.readMonitors(ctx, &res); err != nil {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-monitors-unreadable", Origin: "alerting", Reason: err.Error()})
	}
	if err := r.readSavedObjects(ctx, &res); err != nil {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-dashboards-unreadable", Origin: r.DashboardsIndex, Reason: err.Error()})
	}
	r.checkSearchPipelines(ctx, &res)
	res.Gaps = append(res.Gaps, Gap{Key: "opensearch-plugins", Origin: "notebooks, reporting, anomaly detection, observability, query workbench",
		Reason: "queries stored by these OpenSearch plugins are not read; the ones they run are in the audit log only while they run"})
	return res
}

// checkSearchPipelines records a gap when search pipelines exist: a request processor can rewrite a
// query after it is audited, so a filter in the audited body proves nothing.
func (r *Reader) checkSearchPipelines(ctx context.Context, res *Result) {
	var out map[string]json.RawMessage
	err := r.C.do(ctx, http.MethodGet, "/_search/pipeline", nil, &out)
	switch {
	case err != nil && strings.Contains(err.Error(), "HTTP 404"):
		return // none defined
	case err != nil:
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-search-pipelines", Origin: "search pipelines", Reason: "search pipelines could not be listed: " + err.Error()})
	case len(out) > 0:
		var names []string
		for n := range out {
			names = append(names, n)
		}
		sort.Strings(names)
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-search-pipelines", Origin: "search pipelines",
			Reason: "these search pipelines can rewrite queries after they are audited: " + strings.Join(names, ", ")})
	}
}

// checkAuditConfig records every audit setting that hides reading requests from the audit log.
func (r *Reader) checkAuditConfig(ctx context.Context, res *Result) {
	var out struct {
		Config struct {
			Enabled bool `json:"enabled"`
			Audit   struct {
				EnableREST       bool     `json:"enable_rest"`
				DisabledREST     []string `json:"disabled_rest_categories"`
				IgnoreUsers      []string `json:"ignore_users"`
				IgnoreRequests   []string `json:"ignore_requests"`
				IgnoreHeaders    []string `json:"ignore_headers"`
				IgnoreURLParams  []string `json:"ignore_url_params"`
				LogRequestBody   *bool    `json:"log_request_body"`
				ExcludeSensitive bool     `json:"exclude_sensitive_headers"`
			} `json:"audit"`
		} `json:"config"`
	}
	if err := r.C.do(ctx, http.MethodGet, "/_plugins/_security/api/audit", nil, &out); err != nil {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-config-unreadable", Origin: "security plugin",
			Reason: "the audit configuration could not be read, so it is unknown which requests are logged: " + err.Error()})
		return
	}
	a := out.Config.Audit
	switch {
	case !out.Config.Enabled:
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-disabled", Origin: "security plugin", Reason: "audit logging is disabled"})
	case !a.EnableREST:
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-disabled", Origin: "security plugin", Reason: "REST audit logging is disabled"})
	}
	for _, c := range a.DisabledREST {
		if strings.EqualFold(c, "AUTHENTICATED") {
			res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-disabled", Origin: "security plugin",
				Reason: "the AUTHENTICATED REST category is disabled, so successful requests are not logged (it is disabled by default)"})
		}
	}
	if len(a.IgnoreUsers) > 0 {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-ignored-users", Origin: "security plugin",
			Reason: "requests by these users are not logged: " + strings.Join(a.IgnoreUsers, ", ")})
	}
	if len(a.IgnoreRequests) > 0 {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-ignored-requests", Origin: "security plugin",
			Reason: "these requests are not logged: " + strings.Join(a.IgnoreRequests, ", ")})
	}
	if len(a.IgnoreHeaders) > 0 {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-ignored-headers", Origin: "security plugin",
			Reason: "requests carrying these headers are not logged: " + strings.Join(a.IgnoreHeaders, ", ")})
	}
	if a.LogRequestBody != nil && !*a.LogRequestBody {
		res.Notes = append(res.Notes, "the audit log does not record request bodies, so every logged search is taken to read all of its indices")
	}
}

// proveLive sends an untagged search for a unique index that does not exist and waits until the
// audit log records it. It proves, end to end, that searches are audited and the audit index is
// readable with these credentials.
func (r *Reader) proveLive(ctx context.Context) error {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	marker := probePrefix + hex.EncodeToString(nonce)
	probe := *r.C
	probe.untagged = true
	if err := probe.do(ctx, http.MethodPost, "/"+marker+"/_search?ignore_unavailable=true&allow_no_indices=true", map[string]any{"size": 0}, nil); err != nil {
		return fmt.Errorf("sending marker search: %w", err)
	}
	timeout := r.ProveTimeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	deadline := time.Now().Add(timeout)
	for {
		var out struct {
			Hits struct {
				Hits []hit `json:"hits"`
			} `json:"hits"`
		}
		path := "/" + marker + "/_search"
		err := r.C.do(ctx, http.MethodPost, "/"+r.AuditIndex+"/_search?ignore_unavailable=true&allow_no_indices=true",
			map[string]any{"size": 10, "query": map[string]any{"match_phrase": map[string]any{"audit_rest_request_path": path}}}, &out)
		if err != nil {
			return fmt.Errorf("reading the audit log: %w", err)
		}
		for _, h := range out.Hits.Hits {
			var e struct {
				Path     string `json:"audit_rest_request_path"`
				Category string `json:"audit_category"`
			}
			if json.Unmarshal(h.Source, &e) == nil && e.Path == path && e.Category == "AUTHENTICATED" {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("marker search %s never appeared in %s within %s: audit logging is off, does not log AUTHENTICATED REST requests, is not stored in that index, or ignores this user", marker, r.AuditIndex, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// checkAuditWindow records a gap when the audit log starts after the evidence window does.
func (r *Reader) checkAuditWindow(ctx context.Context, start time.Time, res *Result) error {
	var out struct {
		Aggs struct {
			First struct {
				Value *float64 `json:"value"`
			} `json:"first"`
		} `json:"aggregations"`
	}
	err := r.C.do(ctx, http.MethodPost, "/"+r.AuditIndex+"/_search?ignore_unavailable=true&allow_no_indices=true",
		map[string]any{"size": 0, "aggs": map[string]any{"first": map[string]any{"min": map[string]any{"field": "@timestamp"}}}}, &out)
	if err != nil {
		return err
	}
	if out.Aggs.First.Value == nil {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-window", Origin: r.AuditIndex, Reason: "the audit log is empty"})
		return nil
	}
	first := time.UnixMilli(int64(*out.Aggs.First.Value)).UTC()
	if first.After(start) {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-window", Origin: r.AuditIndex,
			Reason: fmt.Sprintf("the audit log starts at %s, after the evidence window starts at %s", first.Format(time.RFC3339), start.UTC().Format(time.RFC3339))})
	}
	return nil
}

type hit struct {
	ID     string          `json:"_id"`
	Index  string          `json:"_index"`
	Source json.RawMessage `json:"_source"`
}

// scan reads every hit of a query with the scroll API.
func (r *Reader) scan(ctx context.Context, index string, query any, fn func(hit) error) error {
	var page struct {
		ScrollID string `json:"_scroll_id"`
		Hits     struct {
			Hits []hit `json:"hits"`
		} `json:"hits"`
	}
	if err := r.C.do(ctx, http.MethodPost, "/"+index+"/_search?scroll=2m&size=1000&ignore_unavailable=true&allow_no_indices=true&expand_wildcards=all", map[string]any{"query": query, "sort": []any{"_doc"}}, &page); err != nil {
		return err
	}
	defer func() {
		if page.ScrollID != "" {
			_ = r.C.do(context.Background(), http.MethodDelete, "/_search/scroll", map[string]any{"scroll_id": page.ScrollID}, nil)
		}
	}()
	for len(page.Hits.Hits) > 0 {
		for _, h := range page.Hits.Hits {
			if err := fn(h); err != nil {
				return err
			}
		}
		if page.ScrollID == "" {
			return fmt.Errorf("opensearch: search on %s returned no scroll id", index)
		}
		next := page
		next.Hits.Hits = nil
		if err := r.C.do(ctx, http.MethodPost, "/_search/scroll", map[string]any{"scroll": "2m", "scroll_id": page.ScrollID}, &next); err != nil {
			return err
		}
		page = next
	}
	return nil
}

func has(p string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

// readingEndpoint reports whether a REST path can return or count document content, and whether its
// body is a query the DSL model understands.
func readingEndpoint(method, path string) (reads, dsl bool) {
	p := strings.ToLower(path)
	switch {
	case has(p, "/_plugins/_sql", "/_plugins/_ppl", "/_opendistro/_sql", "/_opendistro/_ppl"):
		return true, false
	case has(p, "/_plugins/_alerting", "/_opendistro/_alerting"):
		// Monitors are read as stored queries; only running one on demand returns search results.
		return has(p, "/_execute"), false
	case has(p, "/_search/scroll", "/_search/point_in_time"):
		return false, false // continuations of an already audited search, or a snapshot handle
	case has(p, "/_msearch", "/_search/template", "/_render/template", "/_mget", "/_termvectors", "/_mtermvectors", "/_explain",
		"/_async_search", "/_plugins/_asynchronous_search", "/_source", "/_field_caps", "/_validate", "/_knn",
		"/_delete_by_query", "/_update_by_query", "/_reindex"):
		return true, false
	case has(p, "/_search", "/_count"):
		return true, true
	case strings.Contains(p, "/_doc/") && (method == http.MethodGet || method == http.MethodHead):
		return true, false
	case has(p, "/_bulk", "/_refresh", "/_flush", "/_mapping", "/_settings", "/_stats", "/_cat/", "/_cluster/", "/_nodes",
		"/_plugins/_security", "/_alias", "/_template", "/_index_template", "/_component_template", "/_ingest", "/_create/",
		"/_update/", "/_resolve/", "/_tasks", "/_snapshot", "/_plugins/_ism", "/_forcemerge", "/_open", "/_close",
		"/_rollover", "/_data_stream"),
		strings.Contains(p, "/_doc") && method != http.MethodGet && method != http.MethodHead:
		return false, false
	case p == "/" || p == "":
		return false, false
	}
	return true, false // unknown endpoints may read: assume they do
}

// multiTarget endpoints name their indices per sub-request in the body, so the path does not bound them.
func multiTarget(path string) bool {
	return has(strings.ToLower(path), "/_msearch", "/_mget", "/_mtermvectors", "/_reindex")
}

// indicesOf returns the index expressions a request path names; nil means every index.
func indicesOf(path string) []string {
	seg := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)[0]
	if u, err := url.PathUnescape(seg); err == nil {
		seg = u
	}
	if seg == "" || strings.HasPrefix(seg, "_") {
		return nil
	}
	var out []string
	for _, e := range strings.Split(seg, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if e == "_all" || strings.HasPrefix(e, "<") {
			return nil // every index, or date math not resolved here
		}
		out = append(out, e)
	}
	return out
}

func (r *Reader) readAudit(ctx context.Context, start, end time.Time, res *Result) error {
	q := map[string]any{"bool": map[string]any{"filter": []any{
		// The security plugin's audit index is dynamically mapped: string fields are text with a
		// keyword subfield, or keyword when an index template says so. match works on both; the exact
		// values are checked again on every hit.
		map[string]any{"match": map[string]any{"audit_request_layer": "REST"}},
		map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": start.UTC().Format(time.RFC3339Nano), "lt": end.UTC().Format(time.RFC3339Nano)}}},
	}}}
	seen := map[string]int{}
	return r.scan(ctx, r.AuditIndex, q, func(h hit) error {
		res.Lines++
		var e struct {
			Timestamp time.Time           `json:"@timestamp"`
			Layer     string              `json:"audit_request_layer"`
			Category  string              `json:"audit_category"`
			Path      string              `json:"audit_rest_request_path"`
			Method    string              `json:"audit_rest_request_method"`
			Body      string              `json:"audit_request_body"`
			Params    map[string]any      `json:"audit_rest_request_params"`
			Headers   map[string][]string `json:"audit_rest_request_headers"`
		}
		if err := json.Unmarshal(h.Source, &e); err != nil {
			res.Gaps = append(res.Gaps, Gap{Key: "opensearch-audit-unparsed", Origin: h.ID, Reason: err.Error()})
			return nil
		}
		for k := range e.Headers {
			if strings.EqualFold(k, Header) {
				return nil // the analyzer's own request
			}
		}
		if e.Layer != "REST" {
			return nil
		}
		if e.Category != "AUTHENTICATED" {
			return nil // failed or denied requests read nothing
		}
		if strings.HasPrefix(e.Path, "/"+probePrefix) {
			return nil // a liveness probe
		}
		reads, dsl := readingEndpoint(e.Method, e.Path)
		if !reads {
			return nil
		}
		u := Use{Source: "audit", Origin: e.Method + " " + e.Path, When: e.Timestamp, Opaque: !dsl}
		if !multiTarget(e.Path) {
			u.Indices = indicesOf(e.Path)
		}
		for _, p := range []string{"q", "search_pipeline", "source"} {
			if _, ok := e.Params[p]; ok {
				u.Opaque = true // a Lucene query string, a pipeline that may rewrite it, or a body in the URL
			}
		}
		if !u.Opaque && e.Body != "" {
			q, ok := dslQuery([]byte(e.Body))
			u.Query, u.Opaque = q, !ok
		}
		// Identical requests are one use: a busy cluster repeats the same searches millions of times.
		k := u.Origin + "\x00" + strings.Join(u.Indices, ",") + "\x00" + string(u.Query) + "\x00" + strconv.FormatBool(u.Opaque)
		if i, ok := seen[k]; ok {
			res.Uses[i].Count++
			if u.When.After(res.Uses[i].When) {
				res.Uses[i].When = u.When
			}
			return nil
		}
		u.Count = 1
		seen[k] = len(res.Uses)
		res.Uses = append(res.Uses, u)
		return nil
	})
}

func (r *Reader) readMonitors(ctx context.Context, res *Result) error {
	const size = 10000
	var out struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []hit `json:"hits"`
		} `json:"hits"`
	}
	err := r.C.do(ctx, http.MethodPost, "/_plugins/_alerting/monitors/_search", map[string]any{"size": size, "track_total_hits": true,
		"query": map[string]any{"match_all": map[string]any{}}}, &out)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 404") && strings.Contains(err.Error(), "no such index") {
			return nil // no monitor was ever created
		}
		return err
	}
	if out.Hits.Total.Value > len(out.Hits.Hits) {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-monitors-unreadable", Origin: "alerting",
			Reason: fmt.Sprintf("only %d of %d monitors were read", len(out.Hits.Hits), out.Hits.Total.Value)})
	}
	for _, h := range out.Hits.Hits {
		type monitor struct {
			Type   string                       `json:"type"`
			Name   string                       `json:"name"`
			Inputs []map[string]json.RawMessage `json:"inputs"`
		}
		// The alerting config index stores a monitor at the top level of _source with type
		// "monitor"; older releases wrapped it in a "monitor" object. Workflows only chain monitors
		// that are read on their own.
		var doc struct {
			monitor
			Monitor *monitor `json:"monitor"`
		}
		if err := json.Unmarshal(h.Source, &doc); err != nil {
			res.Gaps = append(res.Gaps, Gap{Key: "opensearch-monitors-unparsed", Origin: h.ID, Reason: err.Error()})
			continue
		}
		m := doc.monitor
		if doc.Monitor != nil {
			m = *doc.Monitor
		}
		switch {
		case doc.Monitor == nil && m.Type == "workflow":
			continue
		case doc.Monitor == nil && m.Type != "monitor":
			res.Uses = append(res.Uses, Use{Source: "monitor", Origin: "alerting object " + h.ID + " of type " + strconv.Quote(m.Type), Opaque: true})
			continue
		}
		origin := "monitor " + m.Name + " (" + h.ID + ")"
		for _, in := range m.Inputs {
			for kind, raw := range in {
				switch kind {
				case "search":
					var s struct {
						Indices []string        `json:"indices"`
						Query   json.RawMessage `json:"query"`
					}
					opaque := json.Unmarshal(raw, &s) != nil
					q, ok := dslQuery(s.Query)
					res.Uses = append(res.Uses, Use{Source: "monitor", Origin: origin, Indices: expandList(s.Indices), Query: q, Opaque: opaque || !ok})
				case "doc_level_input":
					var d struct {
						Indices []string `json:"indices"`
					}
					_ = json.Unmarshal(raw, &d)
					res.Uses = append(res.Uses, Use{Source: "monitor", Origin: origin, Indices: expandList(d.Indices), Opaque: true})
				case "uri":
					// cluster metrics monitors call cluster APIs; a path reading documents is treated like any request
					var u struct {
						Path string `json:"path"`
					}
					_ = json.Unmarshal(raw, &u)
					if reads, _ := readingEndpoint(http.MethodGet, u.Path); reads {
						res.Uses = append(res.Uses, Use{Source: "monitor", Origin: origin, Indices: indicesOf(u.Path), Opaque: true})
					}
				default:
					res.Uses = append(res.Uses, Use{Source: "monitor", Origin: origin + " input " + kind, Opaque: true})
				}
			}
		}
	}
	return nil
}

// expandList normalizes stored index lists: an empty list or _all means every index.
func expandList(in []string) []string {
	var out []string
	for _, e := range in {
		for _, p := range strings.Split(e, ",") {
			p = strings.TrimSpace(p)
			if p == "_all" || strings.HasPrefix(p, "<") {
				return nil
			}
			if p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// queryTypes are the saved objects that run searches against an index pattern.
var queryTypes = []string{"search", "visualization", "visualization-visbuilder", "augment-vis"}

func (r *Reader) readSavedObjects(ctx context.Context, res *Result) error {
	patterns := map[string]string{} // index-pattern id -> title
	var searches []hit
	var savedQueries []string
	isQuery := map[string]bool{}
	for _, t := range queryTypes {
		isQuery[t] = true
	}
	// Every object is read and filtered here: the type field's mapping is not relied on.
	if err := r.scan(ctx, r.DashboardsIndex, map[string]any{"match_all": map[string]any{}}, func(h hit) error {
		var doc struct {
			Type         string `json:"type"`
			IndexPattern struct {
				Title string `json:"title"`
			} `json:"index-pattern"`
		}
		if err := json.Unmarshal(h.Source, &doc); err != nil {
			res.Gaps = append(res.Gaps, Gap{Key: "opensearch-dashboards-unparsed", Origin: h.ID + " in " + h.Index, Reason: err.Error()})
			return nil
		}
		switch {
		case doc.Type == "index-pattern":
			patterns[h.Index+"\x00"+strings.TrimPrefix(h.ID, "index-pattern:")] = doc.IndexPattern.Title
		case doc.Type == "query":
			savedQueries = append(savedQueries, h.ID+" in "+h.Index)
		case isQuery[doc.Type]:
			searches = append(searches, h)
		}
		return nil
	}); err != nil {
		return err
	}
	if len(savedQueries) > 0 {
		res.Gaps = append(res.Gaps, Gap{Key: "opensearch-saved-queries", Origin: r.DashboardsIndex,
			Reason: "saved queries can be applied to any index pattern: " + strings.Join(savedQueries, ", ")})
	}
	for _, h := range searches {
		var doc struct {
			References []struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"references"`
		}
		_ = json.Unmarshal(h.Source, &doc)
		var indices []string
		unresolved := false
		for _, ref := range doc.References {
			if ref.Type != "index-pattern" {
				continue
			}
			t, ok := patterns[h.Index+"\x00"+ref.ID]
			if !ok {
				unresolved = true
				continue
			}
			indices = append(indices, strings.Split(t, ",")...)
		}
		if unresolved || len(indices) == 0 {
			indices = nil // unknown target (a missing pattern, or a spec naming indices itself): every index
		}
		// Saved searches and visualizations carry KQL or Lucene query strings and structured filters,
		// none of which are interpreted, so they read everything in their indices.
		res.Uses = append(res.Uses, Use{Source: "savedobject", Origin: h.ID + " in " + h.Index, Indices: expandList(indices), Opaque: true})
	}
	return nil
}
