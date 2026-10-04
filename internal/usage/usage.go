// Package usage decides whether a query can read any line a rule would remove.
//
// Every decision over-approximates what the query reads. When something cannot be modelled exactly
// (an unknown label, a filter kind, a regex whose meaning in Loki differs from Go's), that constraint
// is dropped, which can only make the query read more. So a "not used" verdict is a proof, and a
// "used" verdict carries a witness line whenever one can be produced.
package usage

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"unicode"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
	"github.com/Bisman-Singh/sievelog/internal/logql"
)

// Rule is what a rule removes: lines in streams with these scope labels whose stored text is in
// Language.
type Rule struct {
	ID string
	// Scope maps backend label names to the values every removed line carries, for example
	// {"service_name": "checkout"}. Matchers on other labels cannot exclude the rule's lines.
	Scope map[string]string
	// Language is the anchored removal language over the stored line.
	Language *automaton.Pattern
	// Structured is true when the stored line is a structured record (for example JSON) and
	// Language describes only one field of it. Line filters then cannot be decided exactly.
	Structured bool
}

// Verdict is the answer for one selection and one rule.
type Verdict struct {
	Used     bool
	Counting bool
	Witness  string // a line in the rule's language the selection reads, when Used and decidable
	Reason   string
	// Widened lists, for a "used" verdict, every assumption that may make it broader than the truth:
	// parts of the query that are not modelled, or modelled as a superset. Empty means the verdict is
	// exact: the witness is a line the query really selects. A "not used" verdict is a proof either
	// way, so it never carries any.
	Widened []string
}

// limit bounds each automaton question. Exceeding it yields "used".
const limit = automaton.DefaultLimit

// Evaluate decides one selection against one rule.
func Evaluate(sel logql.Selection, r Rule) Verdict {
	v := Verdict{Counting: sel.Counting}
	var widened []string
	named := false
	for _, m := range sel.Matchers {
		if hasVariable(m.Name) {
			// It may name a scope label and exclude the rule's streams; ignoring it only widens.
			widened = append(widened, labelVariableAssumption(m))
			continue
		}
		val, scoped := r.Scope[m.Name]
		if !scoped {
			continue // not a scope label: cannot exclude
		}
		named = true
		ok, known := matchLabel(m, val)
		if known && !ok {
			v.Reason = fmt.Sprintf("stream matcher %s%s%q excludes %s=%q", m.Name, m.Op, m.Value, m.Name, val)
			return v
		}
		if !known {
			widened = append(widened, matcherAssumption(m))
		}
	}
	if !named && len(r.Scope) > 0 {
		widened = append(widened, noScopeAssumption(slices.Sorted(maps.Keys(r.Scope))))
	}
	if r.Structured && len(sel.Stages) > 0 {
		v.Used = true
		v.Reason = "line filters on structured records cannot be decided on one field; treated as reading every line"
		v.Widened = append(widened, v.Reason)
		return v
	}
	terms := []automaton.Term{{Pattern: r.Language}}
	var ignored, approximate []string
	for _, st := range sel.Stages {
		t, why := stageTerms(st)
		terms = append(terms, t...)
		ignored = append(ignored, why...)
		if len(why) == 0 {
			approximate = append(approximate, supersets(st)...)
		}
	}
	w, found, err := automaton.Witness(terms, limit)
	switch {
	case errors.Is(err, automaton.ErrLimit):
		v.Used = true
		v.Reason = "too complex to decide; treated as used"
		widened = append(widened, v.Reason)
	case err != nil:
		v.Used = true
		v.Reason = "decision error (" + err.Error() + "); treated as used"
		widened = append(widened, v.Reason)
	case found:
		v.Used = true
		v.Witness = w
		v.Reason = "reads lines of this rule"
	default:
		v.Reason = "no line of this rule passes the filters"
	}
	if len(ignored) > 0 {
		v.Reason += "; ignored (widening): " + strings.Join(ignored, "; ")
	}
	if v.Used {
		v.Widened = slices.Concat(widened, sel.Unmodelled, ignored, approximate)
	}
	return v
}

// supersets names the filters of a modelled stage whose model is a superset of what Loki keeps: a
// positive case-insensitive regex is modelled as both of Loki's readings, and a positive regex whose
// re-serialised form means something else is modelled as both forms.
func supersets(st logql.Stage) []string {
	if st.Negative {
		return nil // negative stages are modelled only when exact
	}
	var out []string
	for _, f := range st.Alternatives {
		if f.Kind != "regex" {
			continue
		}
		if reason := regexSuperset(f.Value); reason != "" {
			out = append(out, reason)
		}
	}
	return out
}

var supersetCache sync.Map // regex -> reason ("" when exact)

func regexSuperset(expr string) string {
	if r, ok := supersetCache.Load(expr); ok {
		return r.(string)
	}
	reason := ""
	ast, err := syntax.Parse(expr, syntax.Perl)
	switch {
	case err != nil:
		reason = fmt.Sprintf("regex %q does not parse", expr)
	case hasFold(ast):
		reason = fmt.Sprintf("case-insensitive filter %q is modelled as both of Loki's readings", expr)
	default:
		orig, err1 := automaton.Compile(expr)
		round, err2 := automaton.Compile(ast.Simplify().String())
		if err1 != nil || err2 != nil || !equivalent(orig, round) {
			reason = fmt.Sprintf("regex %q is modelled as both its written and its re-serialised form", expr)
		}
	}
	supersetCache.Store(expr, reason)
	return reason
}

// Assumptions lists what any "used" verdict on this selection assumes, whatever the rule: matchers
// on a scope label that cannot be evaluated, a selector that names no scope label, and every
// pipeline stage that is not modelled exactly. A selection with none is decided exactly for every
// rule, except that line filters on structured records never are.
func Assumptions(sel logql.Selection, scopeLabels []string) []string {
	var out []string
	named := false
	for _, m := range sel.Matchers {
		if hasVariable(m.Name) {
			out = append(out, labelVariableAssumption(m))
			continue
		}
		if !slices.Contains(scopeLabels, m.Name) {
			continue
		}
		named = true
		if _, known := matchLabel(m, ""); !known {
			out = append(out, matcherAssumption(m))
		}
	}
	if !named && len(scopeLabels) > 0 {
		out = append(out, noScopeAssumption(scopeLabels))
	}
	out = append(out, sel.Unmodelled...)
	for _, st := range sel.Stages {
		_, why := stageTerms(st)
		out = append(out, why...)
		if len(why) == 0 {
			out = append(out, supersets(st)...)
		}
	}
	return out
}

// kinds maps a phrase of an assumption to the kind of query part it names. The first match wins, so
// more specific phrases come first. The analysis adds two of its own: a query that does not parse,
// and an OpenSearch request, which is decided per service.
var kinds = []struct{ phrase, kind string }{
	{"query does not parse", "query does not parse"},
	{"per service, not per line", "OpenSearch request, decided per service"},
	{"template variable", "template variable"},
	{"names no scope label", "stream selector without the scope label"},
	{"stream matcher", "stream matcher not evaluated exactly"},
	{"after the line is rewritten", "line filter after line_format, decolorize or unpack"},
	{"label filter", "label filter"},
	{"structured records", "line filter on structured records"},
	{"case-insensitive", "case-insensitive filter"},
	{"re-serialised", "regex that Loki re-serialises with another meaning"},
	{"substring filters", "regex that Loki turns into substring filters"},
	{"pattern filter", "pattern filter (|> or !>)"},
	{"ip filter", "ip() filter"},
	{"too complex", "too complex to decide"},
	{"does not parse", "regex that does not parse"},
	{"does not compile", "regex that does not compile"},
}

// Kind names the kind of query part an assumption is about, for counting them.
func Kind(assumption string) string {
	for _, k := range kinds {
		if strings.Contains(assumption, k.phrase) {
			return k.kind
		}
	}
	return "other"
}

// matcherAssumption names a scope-label matcher whose value cannot be decided here.
func matcherAssumption(m logql.Matcher) string {
	why := "is not evaluated exactly"
	if hasVariable(m.Value) {
		why = "uses a template variable"
	}
	return fmt.Sprintf("stream matcher %s%s%q %s", m.Name, m.Op, m.Value, why)
}

// labelVariableAssumption names a matcher whose label name is a template variable.
func labelVariableAssumption(m logql.Matcher) string {
	return fmt.Sprintf("stream matcher %s%s%q uses a template variable as its label name", m.Name, m.Op, m.Value)
}

// noScopeAssumption names a selector without any scope label: its other matchers are assumed to
// select the rule's streams, since which streams they select is not known here.
func noScopeAssumption(scopeLabels []string) string {
	return "stream selector names no scope label (" + strings.Join(scopeLabels, ", ") + "); assumed to select the rule's streams"
}

// matchLabel evaluates a stream matcher against a known value. known is false when the matcher
// cannot be evaluated exactly (template variables, case-insensitive regex).
func matchLabel(m logql.Matcher, val string) (ok, known bool) {
	if hasVariable(m.Value) {
		return false, false
	}
	switch m.Op {
	case "=":
		return val == m.Value, true
	case "!=":
		return val != m.Value, true
	case "=~", "!~":
		if foldsCase(m.Value) {
			return false, false
		}
		re, err := regexp.Compile(`\A(?:` + m.Value + `)\z`)
		if err != nil {
			return false, false
		}
		return re.MatchString(val) == (m.Op == "=~"), true
	}
	return false, false
}

// variableRe matches Grafana template syntax: $name, ${name...}, [[name]].
var variableRe = regexp.MustCompile(`\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\[\[[^\]]*\]\]`)

// hasVariable reports whether s holds a Grafana template variable, whose value is unknown here.
func hasVariable(s string) bool { return variableRe.MatchString(s) }

// stageTerms turns one line filter stage into automaton terms, and says what it had to ignore.
func stageTerms(st logql.Stage) ([]automaton.Term, []string) {
	if !st.Negative {
		var alts []string
		for _, f := range st.Alternatives {
			exprs, ok, why := positiveExprs(f)
			if !ok {
				return nil, []string{why}
			}
			alts = append(alts, exprs...)
		}
		p, err := automaton.Compile("(?:" + strings.Join(alts, ")|(?:") + ")")
		if err != nil {
			return nil, []string{"positive stage did not compile: " + err.Error()}
		}
		return []automaton.Term{{Pattern: p}}, nil
	}
	var terms []automaton.Term
	var why []string
	for _, f := range st.Alternatives {
		p, ok, reason := exactPattern(f)
		if !ok {
			why = append(why, reason)
			continue
		}
		terms = append(terms, automaton.Term{Pattern: p, Negate: true})
	}
	return terms, why
}

// positiveExprs returns regexes whose union contains every line Loki's filter keeps.
func positiveExprs(f logql.Filter) ([]string, bool, string) {
	if hasVariable(f.Value) {
		return nil, false, fmt.Sprintf("filter %q uses a template variable", f.Value)
	}
	switch f.Kind {
	case "contains":
		return []string{regexp.QuoteMeta(f.Value)}, true, ""
	case "regex":
		ast, err := syntax.Parse(f.Value, syntax.Perl)
		if err != nil {
			return nil, false, fmt.Sprintf("regex %q does not parse", f.Value)
		}
		if lokiRewrites(ast.Simplify()) && !rewriteKeepsMeaning(ast.Simplify()) {
			return nil, false, rewrittenByLoki(f.Value)
		}
		out := []string{f.Value}
		// Loki re-serialises regexes before compiling them; include that form too.
		out = append(out, ast.Simplify().String())
		if hasFold(ast) {
			// Loki may evaluate case-insensitive literals with unicode.ToLower equality, and its regex
			// parser can carry one alternative's case-insensitivity over to another's shared prefix.
			out = append(out, lowerVariant(ast).String(), foldAll(ast).String())
		}
		return out, true, ""
	}
	return nil, false, fmt.Sprintf("%s filter %q not modelled", f.Kind, f.Value)
}

// exactPattern returns the exact set of lines a filter matches (what a negative filter drops and a
// positive one keeps), only when that set is known exactly.
func exactPattern(f logql.Filter) (*automaton.Pattern, bool, string) {
	if hasVariable(f.Value) {
		return nil, false, fmt.Sprintf("filter %q uses a template variable", f.Value)
	}
	switch f.Kind {
	case "contains":
		return automaton.Literal(f.Value), true, ""
	case "regex":
		ast, err := syntax.Parse(f.Value, syntax.Perl)
		if err != nil {
			return nil, false, fmt.Sprintf("regex %q does not parse", f.Value)
		}
		if lokiRewrites(ast.Simplify()) && !rewriteKeepsMeaning(ast.Simplify()) {
			return nil, false, rewrittenByLoki(f.Value)
		}
		if hasFold(ast) {
			return nil, false, fmt.Sprintf("case-insensitive negative regex %q not modelled", f.Value)
		}
		orig, err := automaton.Compile(f.Value)
		if err != nil {
			return nil, false, fmt.Sprintf("regex %q does not compile", f.Value)
		}
		// Loki compiles the re-serialised form. Use it only if it denotes the same language.
		round, err := automaton.Compile(ast.Simplify().String())
		if err != nil {
			return nil, false, fmt.Sprintf("re-serialised regex %q does not compile", f.Value)
		}
		if !equivalent(orig, round) {
			return nil, false, fmt.Sprintf("regex %q changes meaning when re-serialised", f.Value)
		}
		return orig, true, ""
	}
	return nil, false, fmt.Sprintf("negative %s filter %q not modelled", f.Kind, f.Value)
}

func equivalent(a, b *automaton.Pattern) bool {
	ab, _, err1 := automaton.Subset(a, b, limit)
	ba, _, err2 := automaton.Subset(b, a, limit)
	return err1 == nil && err2 == nil && ab && ba
}

func foldsCase(expr string) bool {
	ast, err := syntax.Parse(expr, syntax.Perl)
	return err != nil || hasFold(ast)
}

func hasFold(re *syntax.Regexp) bool {
	if re.Flags&syntax.FoldCase != 0 {
		return true
	}
	for _, s := range re.Sub {
		if hasFold(s) {
			return true
		}
	}
	return false
}

// lowerVariant rewrites case-insensitive literals into classes of every rune whose unicode.ToLower
// equals the literal rune's, which is how Loki's containsLower compares.
func lowerVariant(re *syntax.Regexp) *syntax.Regexp {
	c := *re
	c.Sub = nil
	for _, s := range re.Sub {
		c.Sub = append(c.Sub, lowerVariant(s))
	}
	if re.Op == syntax.OpLiteral && re.Flags&syntax.FoldCase != 0 {
		var parts []*syntax.Regexp
		for _, r := range re.Rune {
			class := lowerClass(unicode.ToLower(r))
			var ranges []rune
			for _, x := range class {
				ranges = append(ranges, x, x)
			}
			parts = append(parts, &syntax.Regexp{Op: syntax.OpCharClass, Rune: ranges})
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return &syntax.Regexp{Op: syntax.OpConcat, Sub: parts}
	}
	c.Flags &^= syntax.FoldCase
	return &c
}

var (
	lowerOnce  sync.Once
	lowerIndex map[rune][]rune
)

func lowerClass(lower rune) []rune {
	lowerOnce.Do(func() {
		lowerIndex = map[rune][]rune{}
		for r := rune(0); r <= unicode.MaxRune; r++ {
			if r >= 0xD800 && r <= 0xDFFF {
				continue
			}
			l := unicode.ToLower(r)
			if l != r {
				lowerIndex[l] = append(lowerIndex[l], r)
			}
		}
	})
	return append([]rune{lower}, lowerIndex[lower]...)
}

// Covers reports whether the selection keeps every line of the rule's language: its scope matchers
// provably select the rule's streams and each line filter provably keeps (or provably never drops)
// every line in the language. Only filters whose kept set is known exactly count; anything else
// gives false. Matchers on other labels are not decided here: a rewrite reuses the same selector.
func Covers(sel logql.Selection, r Rule) bool {
	if sel.Rewritten {
		return false
	}
	for _, m := range sel.Matchers {
		val, scoped := r.Scope[m.Name]
		if !scoped {
			continue
		}
		if ok, known := matchLabel(m, val); !known || !ok {
			return false
		}
	}
	if r.Structured && len(sel.Stages) > 0 {
		return false
	}
	for _, st := range sel.Stages {
		if st.Negative {
			for _, f := range st.Alternatives {
				p, ok, _ := exactPattern(f)
				if !ok {
					return false
				}
				if _, found, err := automaton.Intersects(r.Language, p, limit); err != nil || found {
					return false
				}
			}
			continue
		}
		var alts []string
		for _, f := range st.Alternatives {
			p, ok, _ := exactPattern(f) // the exact kept set, the same for either polarity
			if !ok {
				return false
			}
			alts = append(alts, p.String())
		}
		kept, err := automaton.Compile("(?:" + strings.Join(alts, ")|(?:") + ")")
		if err != nil {
			return false
		}
		if sub, _, err := automaton.Subset(r.Language, kept, limit); err != nil || !sub {
			return false
		}
	}
	return true
}

// Loki 3.7.8 turns a line-filter regex into substring filters when its simplified form is made only of
// literals, alternations, concatenations, groups, .*, .+ and empty matches, and that does not keep
// every regex's meaning: a .* between a literal and an alternation is dropped, and so is an empty or .*
// alternative. Such a regex is modelled only in the shapes whose substring filters match the same
// lines. A regex with any other part stays a regex in Loki and is modelled as one.

// lokiRewrites reports whether Loki may turn the simplified regex re into substring filters.
func lokiRewrites(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral, syntax.OpEmptyMatch:
		return true
	case syntax.OpStar, syntax.OpPlus:
		return re.Sub[0].Op == syntax.OpAnyCharNotNL
	case syntax.OpConcat, syntax.OpAlternate, syntax.OpCapture:
		for _, s := range re.Sub {
			if !lokiRewrites(s) {
				return false
			}
		}
		return true
	}
	return false
}

// rewriteKeepsMeaning reports whether a regex Loki turns into substring filters is one whose filters
// match the same lines: one literal, alone or between .*, or an alternation of literals that share
// their flags.
func rewriteKeepsMeaning(re *syntax.Regexp) bool {
	re = uncapture(re)
	switch re.Op {
	case syntax.OpLiteral:
		return true
	case syntax.OpConcat:
		literals := 0
		for _, s := range re.Sub {
			s = uncapture(s)
			switch {
			case s.Op == syntax.OpLiteral:
				literals++
			case s.Op == syntax.OpStar && s.Sub[0].Op == syntax.OpAnyCharNotNL:
			default:
				return false
			}
		}
		return literals == 1
	case syntax.OpAlternate:
		first := uncapture(re.Sub[0])
		for _, s := range re.Sub {
			s = uncapture(s)
			if s.Op != syntax.OpLiteral || s.Flags != first.Flags {
				return false
			}
		}
		return true
	}
	return false
}

func uncapture(re *syntax.Regexp) *syntax.Regexp {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	return re
}

func rewrittenByLoki(expr string) string {
	return fmt.Sprintf("regex %q is turned by Loki into substring filters that may keep other lines", expr)
}

// foldAll is re with every literal case-insensitive.
func foldAll(re *syntax.Regexp) *syntax.Regexp {
	c := *re
	c.Sub = nil
	for _, s := range re.Sub {
		c.Sub = append(c.Sub, foldAll(s))
	}
	if c.Op == syntax.OpLiteral {
		c.Flags |= syntax.FoldCase
	}
	return &c
}
