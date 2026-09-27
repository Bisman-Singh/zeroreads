package opensearch

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCannotRead(t *testing.T) {
	cat := Catalog{
		Indices:     []string{"logs-checkout-000001", "logs-auth-000001", ".ds-applogs-000001", ".ds-applogs-000002", "metrics-1", "logs-auth"},
		Aliases:     map[string][]string{"all-logs": {"logs-checkout-000001", "logs-auth-000001"}, "auth-only": {"logs-auth-000001"}, "chk": {".ds-applogs-000002"}},
		DataStreams: map[string][]string{"applogs": {".ds-applogs-000001", ".ds-applogs-000002"}},
	}
	checkout := Scope{Indices: []string{"logs-checkout*", "applogs"}, ServiceField: "service.name", Service: "checkout"}.Expand(cat)
	cases := []struct {
		name string
		use  Use
		want bool
	}{
		{"other index", Use{Indices: []string{"metrics-*"}}, true},
		{"other exact index", Use{Indices: []string{"metrics-1"}}, true},
		{"wildcard overlap, no query", Use{Indices: []string{"logs-*"}}, false},
		{"exact other service index", Use{Indices: []string{"logs-auth"}}, true},
		{"alias to checkout", Use{Indices: []string{"all-logs"}}, false},
		{"alias to auth only", Use{Indices: []string{"auth-only"}}, true},
		{"no index: all", Use{}, false},
		{"data stream name", Use{Indices: []string{"applogs"}}, false},
		{"backing index", Use{Indices: []string{".ds-applogs-000001"}}, false},
		{"hidden wildcard", Use{Indices: []string{".ds-*"}}, false},
		{"alias over backing index", Use{Indices: []string{"chk"}}, false},
		{"alias glob to checkout", Use{Indices: []string{"all-*"}}, false},
		{"alias glob to auth only", Use{Indices: []string{"auth-o*"}}, true},
		{"cross cluster", Use{Indices: []string{"remote:logs-checkout-000001"}}, false},
		{"cross cluster other", Use{Indices: []string{"remote:metrics"}}, true},
		{"exclusion ignored", Use{Indices: []string{"logs-*", "-logs-checkout*"}}, false},
		{"opaque", Use{Indices: []string{"logs-*"}, Opaque: true, Query: json.RawMessage(`{"term":{"service.name":"auth"}}`)}, false},
		{"term other service", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"term":{"service.name":"auth"}}`)}, true},
		{"term object form", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"term":{"service.name":{"value":"auth"}}}`)}, true},
		{"term case insensitive", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"term":{"service.name":{"value":"AUTH","case_insensitive":true}}}`)}, false},
		{"term same service", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"term":{"service.name":"checkout"}}`)}, false},
		{"terms without", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"terms":{"service.name":["auth","orders"]}}`)}, true},
		{"terms with", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"terms":{"service.name":["auth","checkout"]}}`)}, false},
		{"terms lookup", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"terms":{"service.name":{"index":"x","id":"1","path":"p"}}}`)}, false},
		{"bool filter excludes", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"bool":{"filter":[{"term":{"service.name":"auth"}}],"must":[{"match":{"body":"x"}}]}}`)}, true},
		{"bool must single", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"bool":{"must":{"term":{"service.name":"auth"}}}}`)}, true},
		{"bool should does not exclude", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"bool":{"should":[{"term":{"service.name":"auth"}}]}}`)}, false},
		{"must_not same service", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"bool":{"must_not":[{"term":{"service.name":"checkout"}}]}}`)}, true},
		{"must_not other service", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"bool":{"must_not":[{"term":{"service.name":"auth"}}]}}`)}, false},
		{"constant score", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"constant_score":{"filter":{"term":{"service.name":"auth"}}}}`)}, true},
		{"match on service field is not exact", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"match":{"service.name":"auth"}}`)}, false},
		{"other field term", Use{Indices: []string{"logs-*"}, Query: json.RawMessage(`{"term":{"level":"error"}}`)}, false},
		// A name the cluster no longer has may have been an alias over the scope during the window.
		// Found by the v1 audit: it was judged by its name alone.
		{"removed alias", Use{Source: "audit", Indices: []string{"everything"}}, false},
		{"removed alias, other service term", Use{Source: "audit", Indices: []string{"everything"}, Query: json.RawMessage(`{"term":{"service.name":"auth"}}`)}, true},
		{"removed alias beside a known index", Use{Source: "audit", Indices: []string{"metrics-1", "everything"}}, false},
		{"stored query on a missing name runs against today's names", Use{Source: "monitor", Indices: []string{"everything"}}, true},
	}
	for _, c := range cases {
		if got := c.use.CannotRead(checkout); got != c.want {
			t.Fatalf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestReadingEndpoints(t *testing.T) {
	for _, c := range []struct {
		method, path string
		reads, dsl   bool
	}{
		{"POST", "/logs-*/_search", true, true},
		{"GET", "/logs-*/_count", true, true},
		{"POST", "/_msearch", true, false},
		{"POST", "/_plugins/_ppl", true, false},
		{"POST", "/_plugins/_sql", true, false},
		{"GET", "/logs-a/_doc/1", true, false},
		{"POST", "/logs-a/_doc", false, false},
		{"POST", "/_bulk", false, false},
		{"GET", "/_cat/indices", false, false},
		{"POST", "/_search/scroll", false, false},
		{"GET", "/_unknown_endpoint", true, false},
		{"POST", "/_plugins/_alerting/monitors", false, false},
		{"POST", "/_plugins/_alerting/monitors/_search", false, false},
		{"POST", "/_plugins/_alerting/monitors/abc/_execute", true, false},
		{"POST", "/_plugins/_alerting/monitors/_execute", true, false},
	} {
		reads, dsl := readingEndpoint(c.method, c.path)
		if reads != c.reads || dsl != c.dsl {
			t.Fatalf("%s %s: reads=%v dsl=%v, want %v %v", c.method, c.path, reads, dsl, c.reads, c.dsl)
		}
	}
}

func TestDSLQuery(t *testing.T) {
	for _, c := range []struct {
		body string
		ok   bool
	}{
		{`{"query":{"term":{"a":"b"}},"size":10,"sort":["@timestamp"],"track_total_hits":true}`, true},
		{`{}`, true},
		{`{"query":{"term":{"a":"b"}},"aggs":{"x":{"date_histogram":{"field":"t"},"aggs":{"y":{"top_hits":{}}}}}}`, true},
		{`{"query":{"term":{"a":"b"}},"aggregations":{"x":{"terms":{"field":"t"},"meta":{"k":1}}}}`, true},
		{`{"query":{"term":{"a":"b"}},"aggs":{"x":{"global":{}}}}`, false},
		{`{"query":{"term":{"a":"b"}},"aggs":{"x":{"terms":{"field":"t"},"aggs":{"g":{"global":{}}}}}}`, false},
		{`{"query":{"term":{"a":"b"}},"aggs":{"x":{"significant_terms":{"field":"t"}}}}`, false},
		{`{"query":{"term":{"a":"b"}},"aggs":{"x":{"children":{"type":"c"}}}}`, false},
		{`{"query":{"term":{"a":"b"}},"aggs":{"x":{"some_new_agg":{}}}}`, false},
		{`{"query":{"term":{"a":"b"}},"suggest":{"s":{"text":"x","term":{"field":"body"}}}}`, false},
		{`{"query":{"term":{"service.name":"b"}},"derived":{"service.name":{"type":"keyword","script":"emit('checkout')"}}}`, false},
		{`{"query":{"term":{"a":"b"}},"runtime_mappings":{}}`, false},
		{`{"query":{"term":{"a":"b"}},"ext":{}}`, false},
		{`{"query":{"term":{"a":"b"}},"pit":{"id":"x"}}`, false},
		{`not json`, false},
	} {
		if _, ok := dslQuery([]byte(c.body)); ok != c.ok {
			t.Fatalf("%s: ok %v", c.body, ok)
		}
	}
}

// Each dashboard refresh sends a new time range. Found by the v1 audit: every refresh was a use of
// its own. Ranges are emptied where decisions look, and nothing else changes.
func TestWithoutRanges(t *testing.T) {
	a := withoutRanges(json.RawMessage(`{"bool":{"filter":[{"range":{"@timestamp":{"gte":"2026-09-01"}}},{"term":{"service.name":"auth"}}]}}`))
	b := withoutRanges(json.RawMessage(`{"bool":{"filter":[{"range":{"@timestamp":{"gte":"2026-09-02"}}},{"term":{"service.name":"auth"}}]}}`))
	if string(a) != string(b) {
		t.Fatalf("%s != %s", a, b)
	}
	s := Scope{ServiceField: "service.name", Service: "checkout"}
	if !(Use{Indices: []string{"x"}, Query: a}).excludes(s) {
		t.Fatalf("the term still excludes checkout: %s", a)
	}
	for _, q := range []string{
		`{"constant_score":{"filter":{"range":{"t":{"gte":1}}}}}`,
		`{"bool":{"must":{"range":{"t":{"gte":1}}},"must_not":[{"term":{"service.name":"checkout"}}]}}`,
		`{"term":{"range":"kept"}}`,
		`not json`,
	} {
		got := withoutRanges(json.RawMessage(q))
		if strings.Contains(string(got), `"gte"`) || (q == `{"term":{"range":"kept"}}` && !strings.Contains(string(got), "kept")) || (q == `not json` && string(got) != q) {
			t.Fatalf("%s -> %s", q, got)
		}
	}
	notCheckout := withoutRanges(json.RawMessage(`{"bool":{"must":{"range":{"t":{"gte":1}}},"must_not":[{"term":{"service.name":"checkout"}}]}}`))
	if !(Use{Indices: []string{"x"}, Query: notCheckout}).excludes(s) {
		t.Fatalf("must_not checkout no longer excludes it: %s", notCheckout)
	}
}
