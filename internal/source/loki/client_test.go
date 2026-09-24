package loki

import (
	"context"
	"encoding/json"
	"fmt"
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
