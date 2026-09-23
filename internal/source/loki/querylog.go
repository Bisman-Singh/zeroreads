package loki

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
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
}

// Read collects executed queries between start and end. Queries the analyzer itself sent (tagged
// with Tag) are excluded.
func (q *QueryLog) Read(ctx context.Context, start, end time.Time) (Result, error) {
	logQuery := q.Selector + ` |= "metrics.go" |= "query="`
	entries, err := q.Logs.QueryWindow(ctx, logQuery, start, end, 5000)
	if err != nil {
		return Result{}, err
	}
	res := Result{Lines: len(entries)}
	type obs struct {
		component, query, typ, source string
		ts                            time.Time
	}
	var all []obs
	frontend := false
	for _, e := range entries {
		m, err := logfmt.Parse(e.Line)
		if err != nil {
			res.Unparsed++
			continue
		}
		if !strings.HasPrefix(m["caller"], "metrics.go") || m["query"] == "" {
			continue
		}
		if res.Oldest.IsZero() || e.TS.Before(res.Oldest) {
			res.Oldest = e.TS
		}
		if isOwnQuery(m["source"]) || strings.Contains(m["query"], probePrefix) {
			continue // the analyzer's own reads and liveness markers are not usage
		}
		if m["component"] == "frontend" {
			frontend = true
		}
		all = append(all, obs{component: m["component"], query: m["query"], typ: m["query_type"], source: m["source"], ts: e.TS})
	}
	res.Component = "querier"
	if frontend {
		res.Component = "frontend"
	}
	byQuery := map[string]*ExecutedQuery{}
	for _, o := range all {
		if o.component != res.Component {
			continue
		}
		eq := byQuery[o.query]
		if eq == nil {
			eq = &ExecutedQuery{Query: o.query, Type: o.typ, First: o.ts, Component: o.component}
			byQuery[o.query] = eq
		}
		eq.Count++
		if o.ts.Before(eq.First) {
			eq.First = o.ts
		}
		if o.ts.After(eq.Last) {
			eq.Last = o.ts
		}
		if o.source != "" && !contains(eq.Sources, o.source) {
			eq.Sources = append(eq.Sources, o.source)
		}
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
