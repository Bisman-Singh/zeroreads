// Package loki reads usage evidence from Loki over its HTTP API. Its one write, SetRuleGroup, is
// only used when an operator applies rewrites with rewrite -apply.
package loki

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bisman-Singh/zeroreads/internal/fetch"
	"go.yaml.in/yaml/v3"
)

// Client talks to one Loki (or a gateway in front of it).
type Client struct {
	Base        string // e.g. http://loki:3100
	OrgID       string // X-Scope-OrgID for multi-tenant Loki; empty for single tenant
	Username    string // basic auth, optional
	Password    string
	BearerToken string
	HTTP        *http.Client
	// MaxPage is the largest page asked for when one timestamp holds more lines than a normal page;
	// 0 means 1<<20.
	MaxPage int
	// Chunk bounds the time range of one request made by EachWindow, keeping each under Loki's
	// query length limit; 0 means 24h.
	Chunk time.Duration

	untagged bool // send without Tag (only for the query-log liveness marker)
}

func (c *Client) maxPage() int { return cmp.Or(c.MaxPage, 1<<20) }

func (c *Client) chunk() time.Duration { return cmp.Or(c.Chunk, 24*time.Hour) }

// Tag is sent as X-Query-Tags on every request, so the analyzer's own queries can be told apart in
// Loki's query log and never counted as usage.
const Tag = "Source=zeroreads"

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
	return c.send(ctx, http.MethodGet, path+"?"+q.Encode(), "", nil)
}

func (c *Client) send(ctx context.Context, method, path, contentType string, body []byte) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if !c.untagged {
		req.Header.Set("X-Query-Tags", Tag)
	}
	c.authorize(req)
	res, err := fetch.Do(ctx, c.http(), req)
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, &HTTPError{Status: res.Status, Body: fetch.Excerpt(res.Body)}
	}
	out := res.Body
	return out, nil
}

// RuleNamespace returns every group of one ruler namespace, as the namespace file the ruler reads
// (groups: [...]). It is built from the rules listing, which every rule store supports.
func (c *Client) RuleNamespace(ctx context.Context, namespace string) ([]byte, error) {
	body, err := c.get(ctx, "/loki/api/v1/rules", url.Values{})
	if err != nil {
		return nil, err
	}
	var doc map[string][]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("loki: decode rules: %w", err)
	}
	groups, ok := doc[namespace]
	if !ok {
		return nil, fmt.Errorf("loki: no rule namespace %q", namespace)
	}
	return yaml.Marshal(map[string]any{"groups": groups})
}

// SetRuleGroup creates or replaces a rule group in a namespace through the ruler API. Rulers whose
// storage is read-only (local files) refuse it.
func (c *Client) SetRuleGroup(ctx context.Context, namespace string, group []byte) error {
	_, err := c.send(ctx, http.MethodPost, "/loki/api/v1/rules/"+url.PathEscape(namespace), "application/yaml", group)
	return err
}

// HTTPError is a non-2xx answer from Loki.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("loki: HTTP %d: %s", e.Status, e.Body) }

// ErrTruncated means a single timestamp holds more lines than the largest page, so they cannot all
// be read.
var ErrTruncated = errors.New("loki: more lines share one timestamp than the largest page allowed")

// QueryWindow reads [start, end) in consecutive chunks of at most c.Chunk.
func (c *Client) QueryWindow(ctx context.Context, query string, start, end time.Time, pageSize int) ([]Entry, error) {
	var out []Entry
	err := c.EachWindow(ctx, query, start, end, pageSize, func(e Entry) error { out = append(out, e); return nil })
	return out, err
}

// EachWindow calls fn for every line of [start, end), oldest first, in chunks of at most c.Chunk,
// without holding more than one page in memory.
func (c *Client) EachWindow(ctx context.Context, query string, start, end time.Time, pageSize int, fn func(Entry) error) error {
	for s := start; s.Before(end); s = s.Add(c.chunk()) {
		e := s.Add(c.chunk())
		if e.After(end) {
			e = end
		}
		if err := c.Each(ctx, query, s, e, pageSize, fn); err != nil {
			return fmt.Errorf("window %s..%s: %w", s.Format(time.RFC3339), e.Format(time.RFC3339), err)
		}
	}
	return nil
}

// QueryRange returns every line of a log query in [start, end), oldest first.
func (c *Client) QueryRange(ctx context.Context, query string, start, end time.Time, pageSize int) ([]Entry, error) {
	var out []Entry
	if err := c.Each(ctx, query, start, end, pageSize, func(e Entry) error { out = append(out, e); return nil }); err != nil {
		return nil, err
	}
	return out, nil
}

// Each calls fn for every line of a log query in [start, end), oldest first, paging forward by
// time. A page never splits the lines of one timestamp: the last timestamp of a full page is re-read
// by the next page, and a timestamp holding more lines than a page is read on its own with a larger
// limit.
func (c *Client) Each(ctx context.Context, query string, start, end time.Time, pageSize int, fn func(Entry) error) error {
	if pageSize <= 0 {
		pageSize = 5000
	}
	emit := func(es []Entry) error {
		for _, e := range es {
			if err := fn(e); err != nil {
				return err
			}
		}
		return nil
	}
	cursor := start
	for cursor.Before(end) {
		page, err := c.page(ctx, query, cursor, end, pageSize)
		if err != nil {
			return err
		}
		if len(page) < pageSize {
			return emit(page)
		}
		last := page[len(page)-1].TS
		if !last.Equal(page[0].TS) {
			var before []Entry
			for _, e := range page {
				if e.TS.Before(last) {
					before = append(before, e)
				}
			}
			if err := emit(before); err != nil {
				return err
			}
			cursor = last
			continue
		}
		// The whole page is one timestamp: read that nanosecond alone until it fits.
		for limit := pageSize * 2; ; limit *= 2 {
			if limit > c.maxPage() {
				return ErrTruncated
			}
			all, err := c.page(ctx, query, last, last.Add(time.Nanosecond), limit)
			if err != nil {
				return err
			}
			if len(all) < limit {
				if err := emit(all); err != nil {
					return err
				}
				break
			}
		}
		cursor = last.Add(time.Nanosecond)
	}
	return nil
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
	// A line outside the requested range (a misbehaving proxy or cache) would move the paging cursor
	// backwards and repeat pages forever, or count lines twice.
	for _, e := range page {
		if e.TS.Before(start) || !e.TS.Before(end) {
			return nil, fmt.Errorf("loki: a line at %s is outside the requested range %s..%s", e.TS.Format(time.RFC3339Nano), start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))
		}
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

// LabelNames lists the index label names of the streams a selector matches in [start, end).
// Structured metadata are not index labels and are not listed.
func (c *Client) LabelNames(ctx context.Context, selector string, start, end time.Time) ([]string, error) {
	q := url.Values{}
	q.Set("query", selector)
	q.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	body, err := c.get(ctx, "/loki/api/v1/labels", q)
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

// Sample returns at most limit lines of a log query in [start, end), oldest first, in one request.
// It is for bounded samples; use QueryRange to read everything.
func (c *Client) Sample(ctx context.Context, query string, start, end time.Time, limit int) ([]Entry, error) {
	return c.page(ctx, query, start, end, limit)
}

// authorize adds the tenant and credentials to req.
func (c *Client) authorize(req *http.Request) {
	if c.OrgID != "" {
		req.Header.Set("X-Scope-OrgID", c.OrgID)
	}
	switch {
	case c.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	case c.Username != "":
		req.SetBasicAuth(c.Username, c.Password)
	}
}

// tlsConfig is the TLS configuration of the client's HTTP transport (its CA, for example), for
// connections made outside it.
func (c *Client) tlsConfig(server string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.HTTP != nil {
		if tr, ok := c.HTTP.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
			cfg = tr.TLSClientConfig.Clone()
		}
	}
	cfg.ServerName = server
	return cfg
}

// OpenTail opens a live tail over a websocket, reads the handshake answer and closes it. Loki logs
// the tail when it starts.
func (c *Client) OpenTail(ctx context.Context, query string) error {
	u, err := url.Parse(strings.TrimRight(c.Base, "/") + "/loki/api/v1/tail?query=" + url.QueryEscape(query))
	if err != nil {
		return err
	}
	host := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		host = net.JoinHostPort(u.Hostname(), port)
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	if u.Scheme == "https" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: c.tlsConfig(u.Hostname())}).DialContext(ctx, "tcp", host)
	} else {
		conn, err = d.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() // the probe only needs the tail registered
	key := make([]byte, 16)
	if _, err := crand.Read(key); err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(key))
	c.authorize(req)
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := req.Write(conn); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close() // a switching-protocols answer has no body; the status is what counts
	switch resp.StatusCode {
	case http.StatusSwitchingProtocols:
		select { // let the querier register the tail before closing
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			return nil
		}
	case http.StatusNotFound, http.StatusNotImplemented:
		return ErrNotServed
	}
	return fmt.Errorf("loki: tail: HTTP %d", resp.StatusCode)
}
