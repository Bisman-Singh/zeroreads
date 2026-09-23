// Package loki reads usage evidence from Loki over its HTTP API. It only ever reads.
package loki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Client talks to one Loki (or a gateway in front of it).
type Client struct {
	Base        string // e.g. http://loki:3100
	OrgID       string // X-Scope-OrgID for multi-tenant Loki; empty for single tenant
	Username    string // basic auth, optional
	Password    string
	BearerToken string
	HTTP        *http.Client

	untagged bool // send without Tag (only for the query-log liveness marker)
}

// Tag is sent as X-Query-Tags on every request, so the analyzer's own queries can be told apart in
// Loki's query log and never counted as usage.
const Tag = "Source=sievelog"

// Entry is one log line with its stream labels.
type Entry struct {
	Labels map[string]string
	TS     time.Time
	Line   string
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *Client) get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.Base, "/")+path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if !c.untagged {
		req.Header.Set("X-Query-Tags", Tag)
	}
	if c.OrgID != "" {
		req.Header.Set("X-Scope-OrgID", c.OrgID)
	}
	switch {
	case c.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	case c.Username != "":
		req.SetBasicAuth(c.Username, c.Password)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	return body, nil
}

// HTTPError is a non-200 answer from Loki.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("loki: HTTP %d: %s", e.Status, e.Body) }

// ErrTruncated means a single timestamp holds more lines than MaxLimit, so they cannot all be read.
var ErrTruncated = errors.New("loki: more lines share one timestamp than the largest page allowed")

// MaxLimit is the largest page QueryRange asks for when one timestamp needs it.
var MaxLimit = 1 << 20

// Chunk bounds the time range of one QueryRange call made by QueryWindow, keeping each request
// under Loki's query length limits.
var Chunk = 24 * time.Hour

// QueryWindow reads [start, end) in consecutive chunks of at most Chunk.
func (c *Client) QueryWindow(ctx context.Context, query string, start, end time.Time, pageSize int) ([]Entry, error) {
	var out []Entry
	for s := start; s.Before(end); s = s.Add(Chunk) {
		e := s.Add(Chunk)
		if e.After(end) {
			e = end
		}
		part, err := c.QueryRange(ctx, query, s, e, pageSize)
		if err != nil {
			return nil, fmt.Errorf("window %s..%s: %w", s.Format(time.RFC3339), e.Format(time.RFC3339), err)
		}
		out = append(out, part...)
	}
	return out, nil
}

// QueryRange returns every line of a log query in [start, end), oldest first, paging forward by
// time. A page never splits the lines of one timestamp: the last timestamp of a full page is re-read
// by the next page, and a timestamp holding more lines than a page is read on its own with a larger
// limit.
func (c *Client) QueryRange(ctx context.Context, query string, start, end time.Time, pageSize int) ([]Entry, error) {
	if pageSize <= 0 {
		pageSize = 5000
	}
	var out []Entry
	cursor := start
	for cursor.Before(end) {
		page, err := c.page(ctx, query, cursor, end, pageSize)
		if err != nil {
			return nil, err
		}
		if len(page) < pageSize {
			return append(out, page...), nil
		}
		last := page[len(page)-1].TS
		if !last.Equal(page[0].TS) {
			for _, e := range page {
				if e.TS.Before(last) {
					out = append(out, e)
				}
			}
			cursor = last
			continue
		}
		// The whole page is one timestamp: read that nanosecond alone until it fits.
		for limit := pageSize * 2; ; limit *= 2 {
			if limit > MaxLimit {
				return nil, ErrTruncated
			}
			all, err := c.page(ctx, query, last, last.Add(time.Nanosecond), limit)
			if err != nil {
				return nil, err
			}
			if len(all) < limit {
				out = append(out, all...)
				break
			}
		}
		cursor = last.Add(time.Nanosecond)
	}
	return out, nil
}

func (c *Client) page(ctx context.Context, query string, start, end time.Time, limit int) ([]Entry, error) {
	q := url.Values{}
	q.Set("query", query)
	q.Set("direction", "forward")
	q.Set("limit", strconv.Itoa(limit))
	q.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	body, err := c.get(ctx, "/loki/api/v1/query_range", q)
	if err != nil {
		return nil, err
	}
	page, err := decodeStreams(body)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(page, func(i, j int) bool { return page[i].TS.Before(page[j].TS) })
	return page, nil
}

func decodeStreams(body []byte) ([]Entry, error) {
	var resp struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Stream map[string]string   `json:"stream"`
				Values [][]json.RawMessage `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("loki: decode: %w", err)
	}
	if resp.Data.ResultType != "streams" {
		return nil, fmt.Errorf("loki: expected streams, got %q", resp.Data.ResultType)
	}
	var out []Entry
	for _, r := range resp.Data.Result {
		for _, v := range r.Values {
			if len(v) < 2 {
				return nil, fmt.Errorf("loki: malformed value")
			}
			var tsStr, line string
			if err := json.Unmarshal(v[0], &tsStr); err != nil {
				return nil, err
			}
			if err := json.Unmarshal(v[1], &line); err != nil {
				return nil, err
			}
			ns, err := strconv.ParseInt(tsStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("loki: timestamp %q: %w", tsStr, err)
			}
			out = append(out, Entry{Labels: r.Stream, TS: time.Unix(0, ns).UTC(), Line: line})
		}
	}
	return out, nil
}

// Sample is one series of an instant metric query.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Instant runs a metric query at time at.
func (c *Client) Instant(ctx context.Context, query string, at time.Time) ([]Sample, error) {
	q := url.Values{}
	q.Set("query", query)
	q.Set("time", strconv.FormatInt(at.UnixNano(), 10))
	body, err := c.get(ctx, "/loki/api/v1/query", q)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string  `json:"metric"`
				Value  [2]json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("loki: decode: %w", err)
	}
	if resp.Data.ResultType != "vector" {
		return nil, fmt.Errorf("loki: expected vector, got %q", resp.Data.ResultType)
	}
	var out []Sample
	for _, r := range resp.Data.Result {
		var s string
		if err := json.Unmarshal(r.Value[1], &s); err != nil {
			return nil, err
		}
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, fmt.Errorf("loki: value %q: %w", s, err)
		}
		out = append(out, Sample{Labels: r.Metric, Value: v})
	}
	return out, nil
}

// LabelValues lists the values of a label seen in [start, end).
func (c *Client) LabelValues(ctx context.Context, label string, start, end time.Time) ([]string, error) {
	q := url.Values{}
	q.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	body, err := c.get(ctx, "/loki/api/v1/label/"+url.PathEscape(label)+"/values", q)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []string `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("loki: decode: %w", err)
	}
	sort.Strings(resp.Data)
	return resp.Data, nil
}
