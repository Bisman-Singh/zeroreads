package opensearch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
)

// Catalog is the cluster's current names: indices, aliases and data streams.
type Catalog struct {
	Indices     []string
	Aliases     map[string][]string // alias -> indices
	DataStreams map[string][]string // data stream -> backing indices
}

// Catalog reads every index, alias and data stream, hidden ones included.
func (c *Client) Catalog(ctx context.Context) (Catalog, error) {
	var raw struct {
		Indices []struct {
			Name string `json:"name"`
		} `json:"indices"`
		Aliases []struct {
			Name    string   `json:"name"`
			Indices []string `json:"indices"`
		} `json:"aliases"`
		DataStreams []struct {
			Name    string   `json:"name"`
			Backing []string `json:"backing_indices"`
		} `json:"data_streams"`
	}
	if err := c.do(ctx, http.MethodGet, "/_resolve/index/*,.*?expand_wildcards=all", nil, &raw); err != nil {
		return Catalog{}, err
	}
	cat := Catalog{Aliases: map[string][]string{}, DataStreams: map[string][]string{}}
	seen := map[string]bool{}
	for _, i := range raw.Indices {
		if !seen[i.Name] {
			seen[i.Name] = true
			cat.Indices = append(cat.Indices, i.Name)
		}
	}
	for _, a := range raw.Aliases {
		cat.Aliases[a.Name] = append(cat.Aliases[a.Name], a.Indices...)
	}
	for _, d := range raw.DataStreams {
		cat.DataStreams[d.Name] = append(cat.DataStreams[d.Name], d.Backing...)
	}
	return cat, nil
}

// Expand returns every name a request could use to reach the scope's documents: the configured
// expressions, the concrete indices they cover, and every alias or data stream over those indices.
func (s Scope) Expand(cat Catalog) Scope {
	concrete := map[string]bool{}
	matches := func(name string) bool {
		for _, g := range s.Indices {
			if overlaps(name, g) {
				return true
			}
		}
		return false
	}
	for _, i := range cat.Indices {
		if matches(i) {
			concrete[i] = true
		}
	}
	for _, m := range []map[string][]string{cat.Aliases, cat.DataStreams} {
		for name, backing := range m {
			if matches(name) {
				for _, i := range backing {
					concrete[i] = true
				}
			}
		}
	}
	names := map[string]bool{}
	for _, g := range s.Indices {
		names[g] = true
	}
	for i := range concrete {
		names[i] = true
	}
	for _, m := range []map[string][]string{cat.Aliases, cat.DataStreams} {
		for name, backing := range m {
			for _, i := range backing {
				if concrete[i] {
					names[name] = true
				}
			}
		}
	}
	out := s
	out.Indices = nil
	for n := range names {
		out.Indices = append(out.Indices, n)
	}
	sort.Strings(out.Indices)
	out.current = map[string]bool{}
	for _, i := range cat.Indices {
		out.current[i] = true
	}
	for _, m := range []map[string][]string{cat.Aliases, cat.DataStreams} {
		for name := range m {
			out.current[name] = true
		}
	}
	return out
}

func globRE(g string) string {
	var b strings.Builder
	b.WriteString(`\A`)
	for _, r := range g {
		if r == '*' {
			b.WriteString(`.*`)
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	b.WriteString(`\z`)
	return b.String()
}

// overlaps reports whether two index expressions (with * wildcards) can name the same index.
func overlaps(a, b string) bool {
	pa, err1 := automaton.Compile(globRE(a))
	pb, err2 := automaton.Compile(globRE(b))
	if err1 != nil || err2 != nil {
		return true
	}
	_, found, err := automaton.Intersects(pa, pb, 0)
	return err != nil || found
}

// Scope is where one service's logs live in OpenSearch.
type Scope struct {
	Indices      []string // index expressions holding the service's documents, e.g. logs-checkout*
	ServiceField string   // keyword field holding the service name
	Service      string
	current      map[string]bool // every index, alias and data stream name in the catalog, set by Expand
}

// Gone reports whether name is an exact index expression that the cluster no longer has. Audited
// requests span the evidence window, and an alias that pointed at the scope's indices then may
// have been removed since, so a request through it cannot be shown to have read nothing.
func (s Scope) Gone(name string) bool {
	return !strings.Contains(name, "*") && !s.current[name]
}

// CannotRead reports whether u provably reads nothing of the scope's documents. s must be expanded
// with the cluster's catalog so aliases and data streams are covered. An audited request that named
// an index expression the cluster no longer has may have read the scope through a removed alias.
func (u Use) CannotRead(s Scope) bool {
	if len(u.Indices) == 0 {
		return u.excludes(s)
	}
	for _, t := range u.Indices {
		t = strings.TrimSpace(t)
		if strings.HasPrefix(t, "-") {
			continue // an exclusion never adds indices; ignoring it only widens the target
		}
		_, remote, cross := strings.Cut(t, ":")
		if cross {
			t = remote // cross-cluster: the remote may be this cluster, whose names are judged by pattern
		} else if u.Source == "audit" && s.Gone(t) {
			return u.excludes(s) // it ran during the window; stored queries run against today's names
		}
		for _, si := range s.Indices {
			if overlaps(t, si) {
				return u.excludes(s)
			}
		}
	}
	return true
}

func (u Use) excludes(s Scope) bool {
	if u.Opaque || len(u.Query) == 0 || s.ServiceField == "" {
		return false
	}
	var q map[string]json.RawMessage
	if json.Unmarshal(u.Query, &q) != nil {
		return false
	}
	return proveExcludes(q, s)
}

// proveExcludes is true when the query clause can only match documents of other services.
func proveExcludes(q map[string]json.RawMessage, s Scope) bool {
	for kind, body := range q {
		switch kind {
		case "term":
			if vals, ok := termValues(body, s.ServiceField); ok {
				return !contains(vals, s.Service)
			}
		case "terms":
			if vals, ok := termsValues(body, s.ServiceField); ok {
				return !contains(vals, s.Service)
			}
		case "constant_score":
			var cs struct {
				Filter map[string]json.RawMessage `json:"filter"`
			}
			if json.Unmarshal(body, &cs) == nil && cs.Filter != nil {
				return proveExcludes(cs.Filter, s)
			}
		case "bool":
			var b map[string]json.RawMessage
			if json.Unmarshal(body, &b) != nil {
				return false
			}
			for _, occ := range []string{"filter", "must"} {
				for _, c := range clauses(b[occ]) {
					if proveExcludes(c, s) {
						return true
					}
				}
			}
			for _, c := range clauses(b["must_not"]) {
				if includesService(c, s) {
					return true
				}
			}
		}
	}
	return false
}

// includesService is true when the clause matches every document of the service (a term or terms on
// the service field that includes it), so negating it excludes the service.
func includesService(q map[string]json.RawMessage, s Scope) bool {
	for kind, body := range q {
		switch kind {
		case "term":
			if vals, ok := termValues(body, s.ServiceField); ok {
				return contains(vals, s.Service)
			}
		case "terms":
			if vals, ok := termsValues(body, s.ServiceField); ok {
				return contains(vals, s.Service)
			}
		}
	}
	return false
}

func clauses(raw json.RawMessage) []map[string]json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var list []map[string]json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var one map[string]json.RawMessage
	if json.Unmarshal(raw, &one) == nil {
		return []map[string]json.RawMessage{one}
	}
	return nil
}

// termValues reads {"field": "v"} or {"field": {"value": "v"}}; ok is false for other fields, for
// non-string values and for case_insensitive terms.
func termValues(body json.RawMessage, field string) ([]string, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil || len(m) != 1 {
		return nil, false
	}
	raw, ok := m[field]
	if !ok {
		return nil, false
	}
	var v string
	if json.Unmarshal(raw, &v) == nil {
		return []string{v}, true
	}
	var obj struct {
		Value           *string `json:"value"`
		CaseInsensitive bool    `json:"case_insensitive"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Value != nil && !obj.CaseInsensitive {
		return []string{*obj.Value}, true
	}
	return nil, false
}

func termsValues(body json.RawMessage, field string) ([]string, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return nil, false
	}
	raw, ok := m[field]
	if !ok {
		return nil, false
	}
	for k := range m {
		if k != field && k != "boost" && k != "_name" {
			return nil, false
		}
	}
	var vals []string
	if json.Unmarshal(raw, &vals) != nil {
		return nil, false // terms lookup or non-string values
	}
	return vals, true
}

func contains(vals []string, v string) bool {
	for _, x := range vals {
		if x == v {
			return true
		}
	}
	return false
}

// VerifyScope checks, against the cluster, that exact term reasoning on the service field is sound
// for this service, and that its documents live only where the scope says. It returns the scope to
// use (with ServiceField cleared when term reasoning is unsound), gaps and notes. s must be expanded.
func (c *Client) VerifyScope(ctx context.Context, s Scope) (Scope, []Gap, []string) {
	var gaps []Gap
	var notes []string
	origin := s.Service + " in " + strings.Join(s.Indices, ",")
	field := s.ServiceField
	target := url.PathEscape(strings.Join(s.Indices, ","))
	noTerms := func(why string) {
		if s.ServiceField != "" {
			notes = append(notes, fmt.Sprintf("opensearch %s: filters on %s are not used to rule out reads: %s", s.Service, s.ServiceField, why))
		}
		s.ServiceField = ""
	}
	count := func(index string, q any) (int, error) {
		var out struct {
			Count int `json:"count"`
		}
		err := c.do(ctx, http.MethodPost, "/"+index+"/_count?ignore_unavailable=true&allow_no_indices=true&expand_wildcards=all", map[string]any{"query": q}, &out)
		return out.Count, err
	}
	if s.ServiceField != "" {
		var m map[string]struct {
			Mappings map[string]struct {
				Mapping map[string]struct {
					Type        string `json:"type"`
					Normalizer  string `json:"normalizer"`
					IgnoreAbove int    `json:"ignore_above"`
				} `json:"mapping"`
			} `json:"mappings"`
		}
		if err := c.do(ctx, http.MethodGet, "/"+target+"/_mapping/field/"+url.PathEscape(s.ServiceField)+"?ignore_unavailable=true&allow_no_indices=true&expand_wildcards=all", nil, &m); err != nil {
			noTerms("its mapping could not be read: " + err.Error())
		}
		for index, v := range m {
			f, ok := v.Mappings[s.ServiceField]
			if !ok {
				continue // no document of this index has the field; checked below by counting
			}
			for _, fm := range f.Mapping {
				switch {
				case fm.Type != "keyword" && fm.Type != "constant_keyword":
					noTerms(fmt.Sprintf("it is mapped as %s in %s, so term filters do not compare whole values", fm.Type, index))
				case fm.Normalizer != "":
					noTerms(fmt.Sprintf("it has normalizer %s in %s, so term filters do not compare exact values", fm.Normalizer, index))
				case fm.IgnoreAbove > 0 && len([]rune(s.Service)) > fm.IgnoreAbove:
					noTerms(fmt.Sprintf("the service name is longer than ignore_above %d in %s, so it is not indexed", fm.IgnoreAbove, index))
				}
			}
		}
	}
	if s.ServiceField != "" {
		missing, err := count(target, map[string]any{"bool": map[string]any{"must_not": []any{map[string]any{"exists": map[string]any{"field": s.ServiceField}}}}})
		switch {
		case err != nil:
			noTerms("documents without it could not be counted: " + err.Error())
		case missing > 0:
			noTerms(fmt.Sprintf("%d documents in the scope have no value for it", missing))
		}
	}
	if s.ServiceField != "" {
		multi, err := count(target, map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{s.ServiceField: s.Service}},
			map[string]any{"script": map[string]any{"script": map[string]any{"lang": "painless",
				"source": "doc[params.f].size() > 1", "params": map[string]any{"f": s.ServiceField}}}},
		}}})
		switch {
		case err != nil:
			noTerms("multi-valued documents could not be ruled out: " + err.Error())
		case multi > 0:
			noTerms(fmt.Sprintf("%d documents carry more than one value", multi))
		}
	}
	switch {
	case field == "":
		gaps = append(gaps, Gap{Key: "opensearch-scope-unverified", Origin: origin,
			Reason: "no service field is configured, so it cannot be checked that this service's documents are only in the scope's indices"})
	default:
		// Count the service's documents with an exact term when the field allows it, otherwise with a
		// phrase match, which can only over-count and so only over-report documents outside.
		q := map[string]any{"match_phrase": map[string]any{field: s.Service}}
		if s.ServiceField != "" {
			q = map[string]any{"term": map[string]any{field: s.Service}}
		}
		inScope, err1 := count(target, q)
		all, err2 := count("*,.*", q)
		switch {
		case err1 != nil || err2 != nil:
			gaps = append(gaps, Gap{Key: "opensearch-scope-unverified", Origin: origin, Reason: fmt.Sprintf("the service's documents could not be counted: %v %v", err1, err2)})
		case inScope == 0:
			gaps = append(gaps, Gap{Key: "opensearch-scope-empty", Origin: origin,
				Reason: "no document of this service is in the scope's indices, so the indices or the service field are configured wrong or its lines do not arrive"})
		case all > inScope:
			gaps = append(gaps, Gap{Key: "opensearch-scope-outside", Origin: origin,
				Reason: fmt.Sprintf("%d of the service's %d documents are outside the scope's indices", all-inScope, all)})
		}
	}
	return s, gaps, notes
}

// bodyKeys are the search body keys that never widen what the query selects: they page, sort, shape
// or score the hits the query already matched.
var bodyKeys = map[string]bool{
	"query": true, "size": true, "from": true, "sort": true, "_source": true, "track_total_hits": true,
	"timeout": true, "fields": true, "docvalue_fields": true, "stored_fields": true, "highlight": true,
	"post_filter": true, "search_after": true, "version": true, "seq_no_primary_term": true, "explain": true,
	"min_score": true, "terminate_after": true, "track_scores": true, "collapse": true, "script_fields": true,
	"rescore": true, "indices_boost": true, "stats": true, "profile": true, "slice": true,
	"include_named_queries_score": true, "aggs": true, "aggregations": true,
}

// aggTypes are the aggregations that only see the documents the query matched. global,
// significant_terms/text (background set), children/parent (other documents) and anything unknown
// are left out.
var aggTypes = map[string]bool{
	"terms": true, "multi_terms": true, "rare_terms": true, "histogram": true, "date_histogram": true,
	"auto_date_histogram": true, "variable_width_histogram": true, "range": true, "date_range": true,
	"ip_range": true, "filter": true, "filters": true, "adjacency_matrix": true, "missing": true,
	"composite": true, "sampler": true, "diversified_sampler": true, "nested": true, "reverse_nested": true,
	"geohash_grid": true, "geotile_grid": true, "geo_distance": true, "avg": true, "sum": true, "min": true,
	"max": true, "value_count": true, "cardinality": true, "stats": true, "extended_stats": true,
	"percentiles": true, "percentile_ranks": true, "median_absolute_deviation": true, "top_hits": true,
	"weighted_avg": true, "scripted_metric": true, "geo_bounds": true, "geo_centroid": true,
	"matrix_stats": true, "avg_bucket": true, "sum_bucket": true, "min_bucket": true, "max_bucket": true,
	"stats_bucket": true, "extended_stats_bucket": true, "percentiles_bucket": true, "bucket_script": true,
	"bucket_selector": true, "bucket_sort": true, "cumulative_sum": true, "derivative": true,
	"moving_avg": true, "moving_fn": true, "serial_diff": true,
}

func aggsBounded(raw json.RawMessage) bool {
	var aggs map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &aggs) != nil {
		return false
	}
	for _, a := range aggs {
		for k, v := range a {
			switch {
			case k == "meta":
			case k == "aggs" || k == "aggregations":
				if !aggsBounded(v) {
					return false
				}
			case !aggTypes[k]:
				return false
			}
		}
	}
	return true
}

// dslQuery returns the query of a search body when everything else in the body is bounded by it.
// ok is false when the body cannot be modelled: then the request reads everything in its indices.
func dslQuery(body []byte) (query json.RawMessage, ok bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return nil, false
	}
	for k, v := range m {
		if !bodyKeys[k] {
			return nil, false // runtime or derived fields, suggesters, ext, pit, anything unknown
		}
		if (k == "aggs" || k == "aggregations") && !aggsBounded(v) {
			return nil, false
		}
	}
	return m["query"], true
}

// withoutRanges returns q with the body of every range clause the decision looks at emptied. Only
// term, terms, constant_score and bool clauses decide whether a query excludes a service, and a
// dashboard sends a new time range with every refresh, so without this each refresh of the same
// panel would be a use of its own. A query that does not decode is returned as it is.
func withoutRanges(q json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(q, &m) != nil {
		return q
	}
	for kind, body := range m {
		switch kind {
		case "range":
			m[kind] = json.RawMessage(`{}`)
		case "constant_score":
			var cs map[string]json.RawMessage
			if json.Unmarshal(body, &cs) == nil && cs["filter"] != nil {
				cs["filter"] = withoutRanges(cs["filter"])
				m[kind], _ = json.Marshal(cs)
			}
		case "bool":
			var b map[string]json.RawMessage
			if json.Unmarshal(body, &b) != nil {
				continue
			}
			for _, occ := range []string{"filter", "must", "must_not", "should"} {
				if b[occ] == nil {
					continue
				}
				var list []json.RawMessage
				if json.Unmarshal(b[occ], &list) == nil {
					for i := range list {
						list[i] = withoutRanges(list[i])
					}
					b[occ], _ = json.Marshal(list)
				} else {
					b[occ] = withoutRanges(b[occ])
				}
			}
			m[kind], _ = json.Marshal(b)
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return q
	}
	return out
}
