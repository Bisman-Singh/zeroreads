package loki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"testing"
	"time"
)

type fakeLine struct {
	stream string
	ts     int64
	line   string
}

// fakeLoki answers query_range like Loki: lines with start <= ts < end, oldest first for
// direction=forward, at most limit lines, grouped by stream.
func fakeLoki(t *testing.T, lines []fakeLine, calls *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if r.Header.Get("X-Query-Tags") != Tag {
			t.Errorf("missing query tag")
		}
		q := r.URL.Query()
		start, _ := strconv.ParseInt(q.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(q.Get("end"), 10, 64)
		limit, _ := strconv.Atoi(q.Get("limit"))
		var sel []fakeLine
		for _, l := range lines {
			if l.ts >= start && l.ts < end {
				sel = append(sel, l)
			}
		}
		sort.SliceStable(sel, func(i, j int) bool { return sel[i].ts < sel[j].ts })
		if len(sel) > limit {
			sel = sel[:limit]
		}
		byStream := map[string][][2]string{}
		for _, l := range sel {
			byStream[l.stream] = append(byStream[l.stream], [2]string{strconv.FormatInt(l.ts, 10), l.line})
		}
		type res struct {
			Stream map[string]string `json:"stream"`
			Values [][2]string       `json:"values"`
		}
		var out []res
		for s, v := range byStream {
			out = append(out, res{Stream: map[string]string{"s": s}, Values: v})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": out}})
	}))
}

func multiset(entries []Entry) map[string]int {
	m := map[string]int{}
	for _, e := range entries {
		m[fmt.Sprintf("%s|%d|%s", e.Labels["s"], e.TS.UnixNano(), e.Line)]++
	}
	return m
}

func TestQueryRangePagesWithoutLossOrDuplication(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	var lines []fakeLine
	for i := 0; i < 2000; i++ {
		ts := int64(1000 + r.IntN(300)) // many lines share timestamps
		lines = append(lines, fakeLine{stream: []string{"a", "b", "c"}[r.IntN(3)], ts: ts, line: fmt.Sprintf("l%d", r.IntN(50))})
	}
	// Identical duplicates at one timestamp, straddling page boundaries.
	for i := 0; i < 30; i++ {
		lines = append(lines, fakeLine{stream: "a", ts: 1150, line: "dup"})
	}
	want := map[string]int{}
	for _, l := range lines {
		want[fmt.Sprintf("%s|%d|%s", l.stream, l.ts, l.line)]++
	}
	for _, page := range []int{7, 50, 64, 333, 5000} {
		calls := 0
		srv := fakeLoki(t, lines, &calls)
		c := &Client{Base: srv.URL}
		got, err := c.QueryRange(context.Background(), `{s=~".+"}`, time.Unix(0, 0), time.Unix(0, 5000), page)
		srv.Close()
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		g := multiset(got)
		if len(got) != len(lines) {
			t.Fatalf("page %d: got %d lines, want %d", page, len(got), len(lines))
		}
		for k, n := range want {
			if g[k] != n {
				t.Fatalf("page %d: %s got %d want %d", page, k, g[k], n)
			}
		}
		for i := 1; i < len(got); i++ {
			if got[i].TS.Before(got[i-1].TS) {
				t.Fatalf("page %d: not oldest first", page)
			}
		}
	}
}

// A timestamp holding more lines than a page is read on its own with a larger limit.
func TestQueryRangeCrowdedTimestamp(t *testing.T) {
	var lines []fakeLine
	for i := 0; i < 200; i++ {
		lines = append(lines, fakeLine{stream: "a", ts: 100, line: fmt.Sprint(i)})
	}
	lines = append(lines, fakeLine{stream: "a", ts: 99, line: "before"}, fakeLine{stream: "a", ts: 101, line: "after"})
	calls := 0
	srv := fakeLoki(t, lines, &calls)
	defer srv.Close()
	c := &Client{Base: srv.URL}
	got, err := c.QueryRange(context.Background(), `{s="a"}`, time.Unix(0, 0), time.Unix(0, 1000), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 202 {
		t.Fatalf("got %d lines, want 202", len(got))
	}
}

func TestHTTPErrorsSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "parse error", http.StatusBadRequest)
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL}
	_, err := c.QueryRange(context.Background(), `{a="b"}`, time.Unix(0, 0), time.Unix(0, 10), 5)
	he, ok := err.(*HTTPError)
	if !ok || he.Status != 400 {
		t.Fatalf("got %v", err)
	}
}

func TestQueryRangeTruncatedAtCap(t *testing.T) {
	old := MaxLimit
	MaxLimit = 40
	defer func() { MaxLimit = old }()
	var lines []fakeLine
	for i := 0; i < 100; i++ {
		lines = append(lines, fakeLine{stream: "a", ts: 100, line: fmt.Sprint(i)})
	}
	calls := 0
	srv := fakeLoki(t, lines, &calls)
	defer srv.Close()
	c := &Client{Base: srv.URL}
	if _, err := c.QueryRange(context.Background(), `{s="a"}`, time.Unix(0, 0), time.Unix(0, 1000), 5); err != ErrTruncated {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
}

func TestQueryWindowChunks(t *testing.T) {
	old := Chunk
	Chunk = 100
	defer func() { Chunk = old }()
	var lines []fakeLine
	for i := int64(0); i < 1000; i += 3 {
		lines = append(lines, fakeLine{stream: "a", ts: i, line: fmt.Sprint(i)})
	}
	calls := 0
	srv := fakeLoki(t, lines, &calls)
	defer srv.Close()
	c := &Client{Base: srv.URL}
	got, err := c.QueryWindow(context.Background(), `{s="a"}`, time.Unix(0, 0), time.Unix(0, 1000), 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(lines) {
		t.Fatalf("got %d want %d", len(got), len(lines))
	}
	if calls < 10 {
		t.Fatalf("expected chunked requests, got %d calls", calls)
	}
}

func TestQueryLogSkipsIndexOnlyRequests(t *testing.T) {
	base := time.Now().Add(-time.Minute).UnixNano()
	line := func(typ, query string) string {
		return `level=info caller=metrics.go:340 component=frontend org_id=fake query_type=` + typ + ` query="` + query + `"`
	}
	lines := []fakeLine{
		{"loki", base, line("labels", `{service_name=\"checkout\"}`)},
		{"loki", base + 1, line("series", `{service_name=\"checkout\"}`)},
		{"loki", base + 2, line("stats", `{service_name=\"checkout\"}`)},
		{"loki", base + 3, line("filter", `{service_name=\"checkout\"} |= \"x\"`)},
		{"loki", base + 4, line("metric", `sum(count_over_time({service_name=\"checkout\"}[5m]))`)},
	}
	calls := 0
	srv := fakeLoki(t, lines, &calls)
	defer srv.Close()
	ql := &QueryLog{Logs: &Client{Base: srv.URL}, Selector: `{s="loki"}`}
	res, err := ql.Read(context.Background(), time.Unix(0, base-1), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata != 3 || len(res.Queries) != 2 {
		t.Fatalf("metadata %d, queries %+v", res.Metadata, res.Queries)
	}
}

func TestQueryLogWithoutFrontend(t *testing.T) {
	base := time.Now().Add(-time.Minute).UnixNano()
	lines := []fakeLine{
		{"loki", base, `level=info caller=metrics.go:227 org_id=fake query_type=filter query="{a=\"b\"} |= \"x\""`},
		{"loki", base + 1, `level=info caller=metrics.go:227 org_id=fake query_type=filter query="{a=\"b\"} |= \"x\""`},
	}
	calls := 0
	srv := fakeLoki(t, lines, &calls)
	defer srv.Close()
	res, err := (&QueryLog{Logs: &Client{Base: srv.URL}, Selector: `{s="loki"}`}).Read(context.Background(), time.Unix(0, base-1), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Component != "querier" || len(res.Queries) != 1 || res.Queries[0].Count != 2 {
		t.Fatalf("%+v", res)
	}
}

func TestProofsOfTailAndPatterns(t *testing.T) {
	// A Loki that serves neither endpoint: nobody can tail or ask for patterns.
	none := httptest.NewServer(http.NotFoundHandler())
	defer none.Close()
	ql := &QueryLog{Logs: &Client{Base: none.URL}, Selector: `{s="loki"}`}
	if err := ql.ProvePatterns(context.Background(), &Client{Base: none.URL}, time.Second); !errors.Is(err, ErrNotServed) {
		t.Fatalf("patterns on a server without them: %v", err)
	}
	if err := ql.ProveTail(context.Background(), &Client{Base: none.URL}, time.Second); !errors.Is(err, ErrNotServed) {
		t.Fatalf("tail on a server without it: %v", err)
	}
	// A Loki that serves patterns but never logs them: the proof must fail, not pass.
	quiet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/loki/api/v1/patterns" {
			w.Write([]byte(`{"status":"success","data":[]}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": []any{}}})
	}))
	defer quiet.Close()
	ql = &QueryLog{Logs: &Client{Base: quiet.URL}, Selector: `{s="loki"}`}
	if err := ql.ProvePatterns(context.Background(), &Client{Base: quiet.URL}, 100*time.Millisecond); err == nil || errors.Is(err, ErrNotServed) {
		t.Fatalf("patterns served but never logged must fail the proof: %v", err)
	}
}

// Every component counts; copies of a frontend query (a querier's time split, the ruler's own
// formatting) fold into it, and a query only a querier logged stays a reader of its own.
func TestQueryLogKeepsEveryComponent(t *testing.T) {
	base := time.Now().Add(-time.Minute).UnixNano()
	line := func(comp, query string) string {
		c := ""
		if comp != "" {
			c = " component=" + comp
		}
		return `level=info caller=metrics.go:237` + c + ` org_id=fake query_type=metric query=` + strconv.Quote(query)
	}
	lines := []fakeLine{
		{"loki", base, line("frontend", `sum(count_over_time({a="b"} |= "x" [5m])) > 1`)},
		{"loki", base + 1, line("querier", `sum(count_over_time({a="b"} |= "x"[5m] offset 1h0m0s)) > 1`)},
		{"loki", base + 2, line("ruler", `(sum(count_over_time({a="b"} |= "x"[5m])) > 1)`)},
		{"loki", base + 3, line("querier", `{a="direct"}`)},
		{"loki", base + 4, line("", `{a="nocomponent"}`)},
	}
	calls := 0
	srv := fakeLoki(t, lines, &calls)
	defer srv.Close()
	res, err := (&QueryLog{Logs: &Client{Base: srv.URL}, Selector: `{s="loki"}`}).Read(context.Background(), time.Unix(0, base-1), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, q := range res.Queries {
		got[q.Query] = q.Count
	}
	if len(got) != 3 || got[`sum(count_over_time({a="b"} |= "x" [5m])) > 1`] != 3 || got[`{a="direct"}`] != 1 || got[`{a="nocomponent"}`] != 1 {
		t.Fatalf("%v", got)
	}
}

// Queriers log each leg of a frontend query; a leg logged around the frontend execution is part of
// it, a leg logged at another time is a query of its own.
func TestQueryLogFoldsLegsOfFrontendQueries(t *testing.T) {
	now := time.Now().Add(-10 * time.Minute)
	at := func(d time.Duration) int64 { return now.Add(d).UnixNano() }
	line := func(comp, query string) string {
		return `level=info caller=metrics.go:237 component=` + comp + ` org_id=fake query_type=metric query=` + strconv.Quote(query)
	}
	full := `(sum(count_over_time({a="b"} != "x" | sievelog_rule="" [5m])) + sum(count_over_time({a="b"} |~ "y" [5m])))`
	leg := `sum(count_over_time({a="b"} |~ "y"[5m] offset 1m0s))`
	lines := []fakeLine{
		{"loki", at(0), line("querier", leg)},
		{"loki", at(time.Second), line("frontend", full)},
		{"loki", at(8 * time.Minute), line("querier", `sum(count_over_time({a="b"} |~ "y"[5m]))`)},
	}
	calls := 0
	srv := fakeLoki(t, lines, &calls)
	defer srv.Close()
	res, err := (&QueryLog{Logs: &Client{Base: srv.URL}, Selector: `{s="loki"}`}).Read(context.Background(), now.Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, q := range res.Queries {
		got[q.Query] = q.Count
	}
	if len(got) != 2 || got[full] != 2 || got[`sum(count_over_time({a="b"} |~ "y"[5m]))`] != 1 {
		t.Fatalf("%v", got)
	}
}

// Only the ruler's own "no rule groups found" means no rules. A 404 from anything that does not
// route the ruler API (Loki 3.7.8 answers "404 page not found") leaves the rules unknown. Found by
// the v1 audit: every 404 read as "no rules", so the ruler's alerts went unseen with no gap.
func TestRulesOnlyTrustTheRulersOwn404(t *testing.T) {
	for body, empty := range map[string]bool{"no rule groups found\n": true, "404 page not found\n": false, "": false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, body)
		}))
		rules, err := (&Client{Base: srv.URL}).Rules(context.Background())
		srv.Close()
		if empty && (err != nil || len(rules) != 0) {
			t.Fatalf("%q: %v %v, want no rules", body, rules, err)
		}
		if !empty && err == nil {
			t.Fatalf("%q: read as no rules", body)
		}
	}
}
