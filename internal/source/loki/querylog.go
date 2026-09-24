package loki

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/logfmt"
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

// Read collects executed queries between start and end. Queries the analyzer itself sent (tagged
// with Tag) are excluded.
func (q *QueryLog) Read(ctx context.Context, start, end time.Time) (Result, error) {
	// metrics.go lines are range and instant queries; live tails and pattern requests are logged
	// elsewhere: "starting to tail logs" by the querier, and the frontend's query stats line
	// (frontend.query_stats_enabled) for /loki/api/v1/patterns.
	logQuery := q.Selector + ` |~ "caller=metrics\\.go|starting to tail logs|path=/loki/api/v1/patterns "`
	var res Result
	other := map[string]*ExecutedQuery{} // tails and pattern requests: logged once each, by one component
	record := func(byQuery map[string]*ExecutedQuery, query, typ, comp string, ts time.Time) {
		eq := byQuery[query]
		if eq == nil {
			eq = &ExecutedQuery{Query: query, Type: typ, First: ts, Component: comp}
			byQuery[query] = eq
		}
		eq.Count++
		if ts.Before(eq.First) {
			eq.First = ts
		}
		if ts.After(eq.Last) {
			eq.Last = ts
		}
	}
	// Executions are folded per component as they stream in: a query log can hold millions of lines.
	byComponent := map[string]map[string]*ExecutedQuery{}
	err := q.Logs.EachWindow(ctx, logQuery, start, end, 5000, func(e Entry) error {
		res.Lines++
		m, err := logfmt.Parse(e.Line)
		if err != nil {
			res.Unparsed++
			return nil
		}
		switch {
		case m["msg"] == "starting to tail logs" && m["selectors"] != "":
			if res.Oldest.IsZero() || e.TS.Before(res.Oldest) {
				res.Oldest = e.TS
			}
			if strings.Contains(m["selectors"], probePrefix) {
				return nil
			}
			res.Tails++
			record(other, m["selectors"], "tail", "tail", e.TS) // a person watching lines arrive
			return nil
		case m["path"] == "/loki/api/v1/patterns" && m["param_query"] != "":
			if res.Oldest.IsZero() || e.TS.Before(res.Oldest) {
				res.Oldest = e.TS
			}
			if strings.Contains(m["param_query"], probePrefix) {
				return nil
			}
			res.Patterns++
			record(other, m["param_query"], "patterns", "patterns", e.TS) // pattern counts change with the lines
			return nil
		}
		if !strings.HasPrefix(m["caller"], "metrics.go") || m["query"] == "" {
			return nil
		}
		if res.Oldest.IsZero() || e.TS.Before(res.Oldest) {
			res.Oldest = e.TS
		}
		if isOwnQuery(m["source"]) || strings.Contains(m["query"], probePrefix) {
			return nil // the analyzer's own reads and liveness markers are not usage
		}
		switch m["query_type"] {
		case "labels", "series", "stats":
			// These read the index, never a line: label names and values, series label sets and size
			// estimates. Removal changes them only by emptying a stream, which analysis checks
			// directly. They carry no query tags, so the analyzer's own cannot be told apart anyway.
			res.Metadata++
			return nil
		}
		comp := m["component"]
		byQuery := byComponent[comp]
		if byQuery == nil {
			byQuery = map[string]*ExecutedQuery{}
			byComponent[comp] = byQuery
		}
		eq := byQuery[m["query"]]
		if eq == nil {
			eq = &ExecutedQuery{Query: m["query"], Type: m["query_type"], First: e.TS, Component: comp}
			byQuery[m["query"]] = eq
		}
		eq.Count++
		if e.TS.Before(eq.First) {
			eq.First = e.TS
		}
		if e.TS.After(eq.Last) {
			eq.Last = e.TS
		}
		if src := m["source"]; src != "" && !contains(eq.Sources, src) {
			eq.Sources = append(eq.Sources, src)
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	// The frontend logs every query once; queriers log sub-queries. Prefer the frontend when present.
	byQuery := byComponent["frontend"]
	res.Component = "frontend"
	if byQuery == nil {
		// No query frontend: queriers log the queries themselves, without a component field.
		res.Component, byQuery = "querier", map[string]*ExecutedQuery{}
		for _, m := range byComponent {
			for k, eq := range m {
				if prev, ok := byQuery[k]; ok {
					prev.Count += eq.Count
					if eq.First.Before(prev.First) {
						prev.First = eq.First
					}
					if eq.Last.After(prev.Last) {
						prev.Last = eq.Last
					}
					continue
				}
				byQuery[k] = eq
			}
		}
	}
	for k, eq := range other {
		if prev, ok := byQuery[k]; ok {
			prev.Count += eq.Count
			if eq.Last.After(prev.Last) {
				prev.Last = eq.Last
			}
			continue
		}
		byQuery[k] = eq
	}
	for _, eq := range byQuery {
		res.Queries = append(res.Queries, *eq)
	}
	sort.Slice(res.Queries, func(i, j int) bool { return res.Queries[i].Query < res.Queries[j].Query })
	return res, nil
}

// probePrefix starts every liveness marker. The marker selects a label no stream carries, so it
// reads nothing, and it is never counted as usage.
const probePrefix = "sievelog_probe_"

// isOwnQuery recognises the analyzer's tag. Loki lower-cases query-tag values in its log line.
func isOwnQuery(source string) bool { return strings.EqualFold(source, "sievelog") }

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

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
