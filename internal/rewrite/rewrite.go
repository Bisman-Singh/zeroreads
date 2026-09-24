// Package rewrite rewrites counting LogQL queries so they return the same numbers after a rule's lines
// are rolled up: removed lines become one record per interval carrying their count.
//
// A rewritable term is sum [by (stream labels)] (count_over_time|rate(<selector> <line filters> [r])),
// whose line filters provably keep every line of the rule. It becomes the sum of three terms over the
// same selector and range:
//
//	X  the original filters with the rule's lines excluded (!~ D)
//	Y  the rule's rollup records, unwrapping their count
//	Z  the rule's lines still stored raw (before enforcement starts, and lines removed in shadow mode)
//
// X + Y + Z equals the original at every point: before enforcement Y is empty, after it Z is.
// Missing sides are handled with "or", so a side with no series never empties the result.
package rewrite

import (
	"fmt"
	"regexp"
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

// Query rewrites every rewritable term of expr for the given rules. streamLabels are the index
// label names of the streams involved: a "sum by" over any other label is not rewritten, because
// rollup records do not carry the removed lines' structured metadata.
func Query(expr string, rules []Rule, streamLabels map[string]bool) (Result, error) {
	q, err := logql.Parse(expr)
	if err != nil {
		return Result{}, err
	}
	var urules []usage.Rule
	for _, r := range rules {
		p, err := automaton.Compile(r.Language)
		if err != nil {
			return Result{}, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		urules = append(urules, usage.Rule{ID: r.ID, Scope: r.Scope, Language: p})
	}
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	applied := map[string]bool{}
	for _, v := range q.VectorAggs {
		if v.Func != "sum" || v.Param || v.Arg < 0 || v.Grouping == "without" {
			continue
		}
		ok := true
		for _, l := range v.Labels {
			if !streamLabels[l] {
				ok = false
			}
		}
		ra := q.RangeAggs[v.Arg]
		if !ok || !ra.Plain || (ra.Func != "count_over_time" && ra.Func != "rate") {
			continue
		}
		var secs float64
		if ra.Func == "rate" {
			if secs, ok = seconds(ra.Range); !ok {
				continue
			}
		}
		sel := q.Selections[ra.Selection]
		var covered []int
		for i, ur := range urules {
			if usage.Evaluate(sel, ur).Used && usage.Covers(sel, ur) {
				covered = append(covered, i)
			}
		}
		if len(covered) == 0 {
			continue
		}
		group := ""
		if v.Grouping == "by" {
			group = " by (" + strings.Join(v.Labels, ", ") + ")"
		}
		win := "[" + ra.Range + "]"
		if ra.Offset != "" {
			win += " offset " + ra.Offset
		}
		filters := strings.Join(ra.Filters, " ")
		if filters != "" {
			filters = " " + filters
		}
		excl := ""
		for _, i := range covered {
			excl += " !~ " + quote(rules[i].Language)
		}
		// The original filters, minus the rule's lines and minus every rollup record: a record's marker
		// text could pass the filters (!= "/healthz" does) and would be counted twice.
		terms := []string{fmt.Sprintf("sum%s(%s(%s%s%s | %s=\"\" %s))", group, ra.Func, ra.Selector, filters, excl, RuleLabel, win)}
		for _, i := range covered {
			r := rules[i]
			y := fmt.Sprintf("sum%s(sum_over_time(%s |= %s | %s=%s | unwrap %s %s))", group, ra.Selector, quote(Marker(r.ID)), RuleLabel, strconv.Quote(r.ID), CountLabel, win)
			if ra.Func == "rate" {
				y += " / " + strconv.FormatFloat(secs, 'f', -1, 64)
			}
			z := fmt.Sprintf("sum%s(%s(%s |~ %s %s))", group, ra.Func, ra.Selector, quote(r.Language), win)
			terms = append(terms, y, z)
			applied[r.ID] = true
		}
		acc := terms[0]
		for _, t := range terms[1:] {
			acc = fmt.Sprintf("((%s + %s) or %s or %s)", acc, t, acc, t)
		}
		edits = append(edits, edit{v.Start, v.End, acc})
	}
	if len(edits) == 0 {
		return Result{Expr: expr}, nil
	}
	out := expr
	for i := len(edits) - 1; i >= 0; i-- { // aggregations end in source order and do not overlap once nested ones are skipped
		e := edits[i]
		out = out[:e.start] + e.text + out[e.end:]
	}
	res := Result{Expr: out, Changed: true}
	for _, r := range rules {
		if applied[r.ID] {
			res.Rules = append(res.Rules, r.ID)
		}
	}
	return res, nil
}

// quote writes s as a LogQL string: a raw string when possible.
func quote(s string) string {
	if !strings.Contains(s, "`") {
		return "`" + s + "`"
	}
	return strconv.Quote(s)
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
		if !st.Negative && len(st.Alternatives) == 1 && st.Alternatives[0].Kind == "contains" && st.Alternatives[0].Value == Marker(id) {
			return false // the rollup term itself
		}
	}
	return usage.Evaluate(sel, usage.Rule{ID: id, Scope: scope, Language: automaton.MustCompile(MarkerLanguage(id))}).Used
}

// Compensated reports whether sel is a sievelog raw-line term (Z) for rule id inside a rewritten
// query: a count of exactly the rule's language whose query also reads the rule's rollup records
// through the same selector. Such a term counts removed lines only until enforcement starts and is
// summed with the rollup counts, so it is not a reader that removal would break.
func Compensated(q *logql.Query, sel logql.Selection, id, language string) bool {
	if !sel.Counting || sel.Rewritten || len(sel.Stages) != 1 {
		return false
	}
	st := sel.Stages[0]
	if st.Negative || len(st.Alternatives) != 1 || st.Alternatives[0].Kind != "regex" || st.Alternatives[0].Value != language {
		return false
	}
	for _, other := range q.Selections {
		if !sameMatchers(other.Matchers, sel.Matchers) {
			continue
		}
		for _, s := range other.Stages {
			if !s.Negative && len(s.Alternatives) == 1 && s.Alternatives[0].Kind == "contains" && s.Alternatives[0].Value == Marker(id) {
				return true
			}
		}
	}
	return false
}

func sameMatchers(a, b []logql.Matcher) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
