// Package rewrite rewrites counting LogQL queries so they return the same numbers after a rule's lines
// are rolled up: removed lines become one record per interval carrying their count.
//
// A rewritable term is sum [by (stream labels)] (count_over_time|rate(<selector> <line filters> [r])),
// whose line filters provably keep every line of each rule it covers. It becomes the sum of three
// terms over the same selector and range, whatever the number of covered rules:
//
//	X  the original filters with every covered rule's lines excluded (!~ D1|D2...)
//	Y  the covered rules' rollup records, unwrapping their count
//	Z  the covered rules' lines still stored raw (before enforcement starts, and lines removed in
//	   shadow mode), selected with the same alternation X excludes
//
// X and Z split the original lines exactly, so each line is counted once even when two rules in
// different scopes share a language. X + Y + Z equals the original at every point: before
// enforcement Y is empty, after it Z holds only lines outside the rules' scopes. Missing sides are
// handled with "or", so a side with no series never empties the result.
package rewrite

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
	"github.com/Bisman-Singh/sievelog/internal/emit"
	"github.com/Bisman-Singh/sievelog/internal/logql"
	"github.com/Bisman-Singh/sievelog/internal/usage"
)

// CountLabel is the label Loki exposes for the rollup count attribute (sievelog.dedup_count).
const CountLabel = "sievelog_dedup_count"

// RuleLabel is the label Loki exposes for the rollup rule attribute (sievelog.rule).
const RuleLabel = "sievelog_rule"

// Marker is the body of a rule's rollup records.
func Marker(id string) string { return emit.RollupMarker(id) }

// Rule is a rule whose lines are rolled up.
type Rule struct {
	ID       string
	Language string // anchored RE2
	Scope    map[string]string
}

// Result is a rewritten query.
type Result struct {
	Expr    string
	Changed bool
	Rules   []string // rules whose counting terms were rewritten
}

type edit struct {
	start, end int
	text       string
}

// Query rewrites every rewritable term of expr for the given rules. streamLabels are the index
// label names of the streams involved: a "sum by" over any other label is not rewritten, because
// rollup records do not carry the removed lines' structured metadata.
func Query(expr string, rules []Rule, streamLabels map[string]bool) (Result, error) {
	q, err := logql.Parse(expr)
	if err != nil {
		return Result{}, err
	}
	patterns := make([]usage.Rule, len(rules))
	for i, r := range rules {
		p, err := automaton.Compile(r.Language)
		if err != nil {
			return Result{}, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		patterns[i] = usage.Rule{ID: r.ID, Scope: r.Scope, Language: p}
	}
	var edits []edit
	applied := map[string]bool{}
	for _, v := range q.VectorAggs {
		ra, ok := countingTerm(q, v, streamLabels)
		if !ok {
			continue
		}
		covered := coveredRules(q.Selections[ra.Selection], rules, patterns)
		if len(covered) == 0 {
			continue
		}
		t, ok := termsFor(v, ra, covered)
		if !ok {
			continue
		}
		edits = append(edits, edit{v.Start, v.End, t.sum()})
		for _, r := range covered {
			applied[r.ID] = true
		}
	}
	if len(edits) == 0 {
		return Result{Expr: expr}, nil
	}
	res := Result{Expr: applyEdits(expr, edits), Changed: true}
	for _, r := range rules {
		if applied[r.ID] {
			res.Rules = append(res.Rules, r.ID)
		}
	}
	return res, nil
}

// countingTerm returns the range aggregation under v when v is a rewritable count: a sum, by stream
// labels only, of a plain count_over_time or rate.
func countingTerm(q *logql.Query, v logql.VectorAgg, streamLabels map[string]bool) (logql.RangeAgg, bool) {
	if v.Func != "sum" || v.Param || v.Arg < 0 || v.Grouping == "without" {
		return logql.RangeAgg{}, false
	}
	for _, l := range v.Labels {
		if !streamLabels[l] {
			return logql.RangeAgg{}, false
		}
	}
	ra := q.RangeAggs[v.Arg]
	if !ra.Plain || (ra.Func != "count_over_time" && ra.Func != "rate") {
		return logql.RangeAgg{}, false
	}
	return ra, true
}

// coveredRules returns the rules whose every line sel reads.
func coveredRules(sel logql.Selection, rules []Rule, patterns []usage.Rule) []Rule {
	var covered []Rule
	for i, p := range patterns {
		if usage.Evaluate(sel, p).Used && usage.Covers(sel, p) {
			covered = append(covered, rules[i])
		}
	}
	return covered
}

// terms are the three instant vectors that replace one counting term (see the package comment).
type terms struct{ x, y, z string }

// sum adds the terms. The text is linear in the terms' size, whatever the number of rules.
func (t terms) sum() string { return outerSum(outerSum(t.x, t.y), t.z) }

// termsFor writes the X, Y and Z terms for one counting term. ok is false for a rate over a range
// that is not a literal duration: Y's per-second division needs its length.
func termsFor(v logql.VectorAgg, ra logql.RangeAgg, covered []Rule) (terms, bool) {
	var secs float64
	if ra.Func == "rate" {
		var ok bool
		if secs, ok = seconds(ra.Range); !ok {
			return terms{}, false
		}
	}
	group := ""
	if v.Grouping == "by" {
		group = " by (" + strings.Join(v.Labels, ", ") + ")"
	}
	window := "[" + ra.Range + "]"
	if ra.Offset != "" {
		window += " offset " + ra.Offset
	}
	filters := ""
	for _, f := range ra.Filters {
		filters += " " + f
	}
	ids := make([]string, len(covered))
	languages := make([]string, len(covered))
	for i, r := range covered {
		ids[i], languages[i] = r.ID, r.Language
	}
	removed := logql.Quote(Alternation(languages))
	// X keeps the original filters minus the rules' lines and minus every rollup record: a record's
	// marker text could pass the filters (!= "/healthz" does) and would be counted twice.
	x := fmt.Sprintf("sum%s(%s(%s%s !~ %s | %s=\"\" %s))", group, ra.Func, ra.Selector, filters, removed, RuleLabel, window)
	y := fmt.Sprintf("sum%s(sum_over_time(%s |= %s | %s | unwrap %s %s))", group, ra.Selector, markerFilter(ids), ruleFilter(ids), CountLabel, window)
	if ra.Func == "rate" {
		y += " / " + strconv.FormatFloat(secs, 'f', -1, 64)
	}
	z := fmt.Sprintf("sum%s(%s(%s |~ %s %s))", group, ra.Func, ra.Selector, removed, window)
	return terms{x, y, z}, true
}

// outerSum adds two instant vectors, keeping the series of either side when the other has none.
func outerSum(a, b string) string {
	return fmt.Sprintf("((%s + %s) or %s or %s)", a, b, a, b)
}

// Alternation is the language matching any of languages, written so a single language is
// unchanged.
func Alternation(languages []string) string {
	if len(languages) == 1 {
		return languages[0]
	}
	parts := make([]string, len(languages))
	for i, l := range languages {
		parts[i] = "(?:" + l + ")"
	}
	return strings.Join(parts, "|")
}

// markerFilter is the line filter alternatives selecting the rules' rollup records.
func markerFilter(ids []string) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = logql.Quote(Marker(id))
	}
	return strings.Join(parts, " or ")
}

// ruleFilter is the label filter selecting records of exactly these rules. Rule IDs are
// r-<hex>, so they need no regex escaping.
func ruleFilter(ids []string) string {
	if len(ids) == 1 {
		return RuleLabel + "=" + strconv.Quote(ids[0])
	}
	return RuleLabel + "=~" + strconv.Quote(strings.Join(ids, "|"))
}

// applyEdits replaces each edit's span. Aggregations end in source order and do not overlap once
// nested ones are skipped, so applying them from the last keeps the earlier offsets valid.
func applyEdits(expr string, edits []edit) string {
	for i := len(edits) - 1; i >= 0; i-- {
		e := edits[i]
		expr = expr[:e.start] + e.text + expr[e.end:]
	}
	return expr
}

var durRe = regexp.MustCompile(`^(?:[0-9]+(?:ms|s|m|h|d|w|y))+$`)
var durPart = regexp.MustCompile(`([0-9]+)(ms|s|m|h|d|w|y)`)

// seconds parses a LogQL range duration. Variables such as $__interval are not known here.
func seconds(r string) (float64, bool) {
	if !durRe.MatchString(r) {
		return 0, false
	}
	unit := map[string]float64{"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}
	total := 0.0
	for _, m := range durPart.FindAllStringSubmatch(r, -1) {
		n, _ := strconv.ParseFloat(m[1], 64)
		total += n * unit[m[2]]
	}
	return total, total > 0
}

// MarkerLanguage is the anchored language of a rule's rollup record text.
func MarkerLanguage(id string) string { return `\A` + regexp.QuoteMeta(Marker(id)) + `\z` }

// ReadsRollups reports whether sel can select rule id's rollup records other than as a sievelog
// rollup term: such a query's numbers or lines change once the rule rolls up.
func ReadsRollups(sel logql.Selection, id string, scope map[string]string) bool {
	if sel.NoRollups {
		return false
	}
	for _, st := range sel.Stages {
		if slices.Contains(markerIDs(st), id) {
			return false // the rollup term itself
		}
	}
	return usage.Evaluate(sel, usage.Rule{ID: id, Scope: scope, Language: automaton.MustCompile(MarkerLanguage(id))}).Used
}

// Compensated reports whether sel is a sievelog raw-line term (Z) covering rule id inside a
// rewritten query: a count of exactly the alternation of the languages whose rollup records the
// same query reads through the same selector, with id among them. Such a term counts removed lines
// only until enforcement starts and is summed with the rollup counts, so it is not a reader that
// removal would break. languages maps rule IDs to their languages.
func Compensated(q *logql.Query, sel logql.Selection, id string, languages map[string]string) bool {
	if !sel.Counting || sel.Rewritten || len(sel.Stages) != 1 {
		return false
	}
	st := sel.Stages[0]
	if st.Negative || len(st.Alternatives) != 1 || st.Alternatives[0].Kind != "regex" {
		return false
	}
	for _, other := range q.Selections {
		if !slices.Equal(other.Matchers, sel.Matchers) {
			continue
		}
		for _, s := range other.Stages {
			ids := markerIDs(s)
			if !slices.Contains(ids, id) {
				continue
			}
			if l, ok := languagesOf(ids, languages); ok && st.Alternatives[0].Value == Alternation(l) {
				return true
			}
		}
	}
	return false
}

// markerIDs returns the rules whose rollup records st selects when st is a sievelog rollup term's
// marker filter (every alternative a rollup marker), otherwise nil.
func markerIDs(st logql.Stage) []string {
	if st.Negative || len(st.Alternatives) == 0 {
		return nil
	}
	ids := make([]string, 0, len(st.Alternatives))
	for _, f := range st.Alternatives {
		id, ok := strings.CutPrefix(f.Value, Marker(""))
		if f.Kind != "contains" || !ok || id == "" {
			return nil
		}
		ids = append(ids, id)
	}
	return ids
}

// languagesOf returns the languages of ids in order, and false when one is unknown.
func languagesOf(ids []string, languages map[string]string) ([]string, bool) {
	out := make([]string, len(ids))
	for i, id := range ids {
		l, ok := languages[id]
		if !ok {
			return nil, false
		}
		out[i] = l
	}
	return out, true
}
