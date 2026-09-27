package loki

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/logfmt"
	"github.com/Bisman-Singh/sievelog/internal/logql"
)

// QueryLog reads the queries Loki executed from Loki's own logs. Loki writes one line per query
// from metrics.go when frontend.log_queries_longer_than is negative; the line from the
// query-frontend carries the query exactly as the user sent it, the querier lines carry split and
// re-formatted sub-queries.
type QueryLog struct {
	// Logs is where Loki's own logs can be read: a Loki that ingests them.
	Logs *Client
	// Selector is a LogQL stream selector for Loki's own log streams, e.g. {k8s_container_name="loki"}.
	Selector string
}

// ExecutedQuery is one distinct query text seen in the query log.
type ExecutedQuery struct {
	Query     string
	Type      string // metric | filter | limited | series | labels ...
	Count     int
	First     time.Time
	Last      time.Time
	Component string // frontend, or querier when the deployment has no frontend
	Sources   []string
}

// Result is what the query log proves.
type Result struct {
	Queries []ExecutedQuery
	// Component the queries were taken from.
	Component string
	// Oldest is the oldest query-log line found; usage before it is unknown.
	Oldest time.Time
	// Lines is how many query-log lines were read.
	Lines int
	// Unparsed counts query-log lines whose logfmt could not be parsed. They are reported, and any
	// such line makes the evidence incomplete.
	Unparsed int
	// Metadata counts labels, series and stats requests: they read the index, not lines.
	Metadata int
	// Tails and Patterns count live tails and pattern requests (Logs Drilldown) read as usage.
	Tails, Patterns int
}

// queryLogLines selects the three kinds of query-log line: metrics.go lines are range and instant
// queries; live tails and pattern requests are logged elsewhere: "starting to tail logs" by the
// querier, and the frontend's query stats line (frontend.query_stats_enabled) for
// /loki/api/v1/patterns.
const queryLogLines = ` |~ "caller=metrics\\.go|starting to tail logs|path=/loki/api/v1/patterns "`

// Read collects executed queries between start and end. Queries the analyzer itself sent (tagged
// with Tag) are excluded.
func (q *QueryLog) Read(ctx context.Context, start, end time.Time) (Result, error) {
	// Executions are folded per component as they stream in: a query log can hold millions of lines.
	r := &logReader{byComponent: map[string]executions{}, other: executions{}}
	if err := q.Logs.EachWindow(ctx, q.Selector+queryLogLines, start, end, 5000, r.line); err != nil {
		return Result{}, err
	}
	return r.result(), nil
}

// executions are the executions of each distinct query text.
type executions map[string]*ExecutedQuery

// add records one execution of query at ts.
func (x executions) add(query, typ, component string, ts time.Time) *ExecutedQuery {
	eq := x[query]
	if eq == nil {
		eq = &ExecutedQuery{Query: query, Type: typ, First: ts, Last: ts, Component: component}
		x[query] = eq
	}
	eq.Count++
	eq.absorbTime(ts, ts)
	return eq
}

func (eq *ExecutedQuery) absorbTime(first, last time.Time) {
	if first.Before(eq.First) {
		eq.First = first
	}
	if last.After(eq.Last) {
		eq.Last = last
	}
}

// logReader classifies query-log lines as they stream in.
type logReader struct {
	res         Result
	byComponent map[string]executions // range and instant queries, by the component that logged them
	other       executions            // tails and pattern requests: logged once each, by one component
}

func (r *logReader) line(e Entry) error {
	r.res.Lines++
	m, err := logfmt.Parse(e.Line)
	if err != nil {
		r.res.Unparsed++
		return nil
	}
	switch {
	case m["msg"] == "starting to tail logs" && m["selectors"] != "":
		r.seen(e.TS)
		if !strings.Contains(m["selectors"], probePrefix) {
			r.res.Tails++
			r.other.add(m["selectors"], "tail", "tail", e.TS) // a person watching lines arrive
		}
	case m["path"] == "/loki/api/v1/patterns" && m["param_query"] != "":
		r.seen(e.TS)
		if !strings.Contains(m["param_query"], probePrefix) {
			r.res.Patterns++
			r.other.add(m["param_query"], "patterns", "patterns", e.TS) // pattern counts change with the lines
		}
	case strings.HasPrefix(m["caller"], "metrics.go") && m["query"] != "":
		r.seen(e.TS)
		r.query(m, e.TS)
	}
	return nil
}

// seen extends how far back the query log is known to reach.
func (r *logReader) seen(ts time.Time) {
	if r.res.Oldest.IsZero() || ts.Before(r.res.Oldest) {
		r.res.Oldest = ts
	}
}

// query records one range or instant query line.
func (r *logReader) query(m map[string]string, ts time.Time) {
	if isOwnQuery(m["source"]) || strings.Contains(m["query"], probePrefix) {
		return // the analyzer's own reads and liveness markers are not usage
	}
	switch m["query_type"] {
	case "labels", "series", "stats":
		// These read the index, never a line: label names and values, series label sets and size
		// estimates. Removal changes them only by emptying a stream, which analysis checks
		// directly. They carry no query tags, so the analyzer's own cannot be told apart anyway.
		r.res.Metadata++
		return
	}
	comp := m["component"]
	if r.byComponent[comp] == nil {
		r.byComponent[comp] = executions{}
	}
	eq := r.byComponent[comp].add(m["query"], m["query_type"], comp, ts)
	if src := m["source"]; src != "" && !slices.Contains(eq.Sources, src) {
		eq.Sources = append(eq.Sources, src)
	}
}

// result folds every component's executions into distinct queries. The frontend logs each query
// once, as sent; queriers log it again split by time (with an offset) and the ruler logs its own
// evaluations re-formatted. A line whose canonical form matches a frontend query adds to that
// query, and so does a leg of one; anything else is its own reader: a query that bypassed the
// frontend is still a query.
func (r *logReader) result() Result {
	res := r.res
	res.Component = "querier"
	distinct := map[string]*ExecutedQuery{} // by canonical form
	merge := func(x executions) {
		for _, k := range slices.Sorted(maps.Keys(x)) {
			c := logql.Canonical(k)
			if prev, ok := distinct[c]; ok {
				prev.Count += x[k].Count
				prev.absorbTime(x[k].First, x[k].Last)
				continue
			}
			distinct[c] = x[k]
		}
	}
	frontend, hasFrontend := r.byComponent["frontend"]
	if hasFrontend {
		res.Component = "frontend"
		merge(frontend)
	}
	fronts := frontendQueries(frontend)
	for _, comp := range slices.Sorted(maps.Keys(r.byComponent)) {
		if comp == "frontend" {
			continue
		}
		own := executions{}
		for k, eq := range r.byComponent[comp] {
			if parent, ok := legOf(fronts, k, eq); ok {
				distinct[parent].Count += eq.Count
				continue
			}
			own[k] = eq
		}
		merge(own)
	}
	merge(r.other)
	for _, eq := range distinct {
		res.Queries = append(res.Queries, *eq)
	}
	sort.Slice(res.Queries, func(i, j int) bool { return res.Queries[i].Query < res.Queries[j].Query })
	return res
}

// frontendQuery is a query as the frontend logged it, kept to recognise its legs.
type frontendQuery struct {
	canonical   string
	padded      string // canonical form with a space at each end, so only whole tokens match
	selections  []logql.Selection
	first, last time.Time
}

func frontendQueries(x executions) []frontendQuery {
	var out []frontendQuery
	for _, k := range slices.Sorted(maps.Keys(x)) {
		q, err := logql.Parse(k)
		if err != nil {
			continue // it cannot be shown to contain any leg
		}
		c := logql.Canonical(k)
		out = append(out, frontendQuery{canonical: c, padded: " " + c + " ", selections: q.Selections, first: x[k].First, last: x[k].Last})
	}
	return out
}

// legWindow is how far from its frontend query a leg can be logged: legs run while the query runs.
const legWindow = 2 * time.Minute

// legOf returns the canonical form of the frontend query that query k is a leg of. The frontend
// splits a query into legs (each side of a binary operation, each time range) and queriers log
// every leg; a leg executed around the same time is part of that execution, not a query of its
// own: someone who ran it alone went through the frontend too. A leg must appear in the query's
// text and read nothing the query does not read (each of its selections is one of the query's),
// so folding it can never hide a reader.
func legOf(fronts []frontendQuery, k string, eq *ExecutedQuery) (string, bool) {
	leg, err := logql.Parse(k)
	if err != nil || len(leg.Selections) == 0 {
		return "", false
	}
	padded := " " + logql.Canonical(k) + " "
	for _, f := range fronts {
		if strings.Contains(f.padded, padded) && !eq.First.Before(f.first.Add(-legWindow)) && !eq.Last.After(f.last.Add(legWindow)) &&
			selectionsWithin(leg.Selections, f.selections) {
			return f.canonical, true
		}
	}
	return "", false
}

// selectionsWithin reports whether every selection in leg is one of query's.
func selectionsWithin(leg, query []logql.Selection) bool {
	for _, l := range leg {
		if !slices.ContainsFunc(query, l.Same) {
			return false
		}
	}
	return true
}

// probePrefix starts every liveness marker. The marker selects a label no stream carries, so it
// reads nothing, and it is never counted as usage.
const probePrefix = "sievelog_probe_"

// isOwnQuery recognises the analyzer's tag. Loki lower-cases query-tag values in its log line.
func isOwnQuery(source string) bool { return strings.EqualFold(source, "sievelog") }

// ProveLive sends a unique marker query to target and waits until it shows up in the query log.
// It proves the query log is being written and is readable, end to end. The marker is sent without
// the analyzer's tag so it is logged like a user query.
func (q *QueryLog) ProveLive(ctx context.Context, target *Client, timeout time.Duration) error {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	marker := probePrefix + hex.EncodeToString(nonce)
	probe := *target
	probe.untagged = true
	sent := time.Now().Add(-time.Second)
	if _, err := probe.QueryRange(ctx, `{sievelog_probe="`+marker+`"}`, sent.Add(-time.Minute), sent.Add(time.Minute), 1); err != nil {
		return fmt.Errorf("sending marker query: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		entries, err := q.Logs.QueryRange(ctx, q.Selector+` |= "`+marker+`"`, sent.Add(-time.Minute), time.Now().Add(time.Minute), 100)
		if err != nil {
			return fmt.Errorf("reading query log: %w", err)
		}
		for _, e := range entries {
			if m, err := logfmt.Parse(e.Line); err == nil && strings.HasPrefix(m["caller"], "metrics.go") && strings.Contains(m["query"], marker) {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("marker query %s never appeared in the query log within %s: the query log is not enabled (frontend.log_queries_longer_than must be negative) or its logs are not collected by %s", marker, timeout, q.Selector)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// ErrNotServed means the target does not serve the endpoint at all, so nobody can use it.
var ErrNotServed = fmt.Errorf("loki: endpoint not served")

// ProveTail opens a live tail with a unique marker and waits until the query log records it.
// ErrNotServed means the target refuses tails.
func (q *QueryLog) ProveTail(ctx context.Context, target *Client, timeout time.Duration) error {
	marker, err := newMarker()
	if err != nil {
		return err
	}
	probe := *target
	probe.untagged = true
	if err := probe.OpenTail(ctx, `{sievelog_probe="`+marker+`"}`); err != nil {
		return err
	}
	return q.waitFor(ctx, marker, timeout, func(m map[string]string) bool {
		return m["msg"] == "starting to tail logs" && strings.Contains(m["selectors"], marker)
	}, "live tails are not logged (they need info-level logs from the queriers)")
}

// ProvePatterns sends a unique marker pattern request, as Logs Drilldown does, and waits until the
// query log records it. ErrNotServed means the target does not serve patterns.
func (q *QueryLog) ProvePatterns(ctx context.Context, target *Client, timeout time.Duration) error {
	marker, err := newMarker()
	if err != nil {
		return err
	}
	probe := *target
	probe.untagged = true
	v := url.Values{}
	v.Set("query", `{sievelog_probe="`+marker+`"}`)
	v.Set("start", strconv.FormatInt(time.Now().Add(-time.Hour).UnixNano(), 10))
	v.Set("end", strconv.FormatInt(time.Now().UnixNano(), 10))
	if _, err := probe.get(ctx, "/loki/api/v1/patterns", v); err != nil {
		var he *HTTPError
		if errors.As(err, &he) && (he.Status == 404 || he.Status == 501) {
			return ErrNotServed
		}
		return fmt.Errorf("sending marker pattern request: %w", err)
	}
	return q.waitFor(ctx, marker, timeout, func(m map[string]string) bool {
		return m["path"] == "/loki/api/v1/patterns" && strings.Contains(m["param_query"], marker)
	}, "pattern requests are not logged (set frontend.query_stats_enabled: true)")
}

func newMarker() (string, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return probePrefix + hex.EncodeToString(nonce), nil
}

func (q *QueryLog) waitFor(ctx context.Context, marker string, timeout time.Duration, match func(map[string]string) bool, why string) error {
	sent := time.Now().Add(-time.Minute)
	deadline := time.Now().Add(timeout)
	for {
		entries, err := q.Logs.QueryRange(ctx, q.Selector+` |= "`+marker+`"`, sent, time.Now().Add(time.Minute), 100)
		if err != nil {
			return fmt.Errorf("reading the query log: %w", err)
		}
		for _, e := range entries {
			if m, err := logfmt.Parse(e.Line); err == nil && match(m) {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("marker %s never appeared in the query log within %s: %s", marker, timeout, why)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
