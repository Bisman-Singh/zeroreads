package logql

import (
	"fmt"
	"strings"
)

// Query is what a LogQL expression reads.
type Query struct {
	Selections []Selection
}

// Selection is one stream selector with the pipeline that follows it.
type Selection struct {
	Matchers []Matcher
	// Stages are the line filters that run on the original line, in order: every line filter that
	// comes before the first stage that rewrites the line (line_format, decolorize). Filters after a
	// rewrite are not listed; ignoring them can only widen what the selection reads.
	Stages []Stage
	// Counting is true when the selection feeds a range aggregation: its result depends on how many
	// lines (or bytes) exist, not only on which lines exist.
	Counting bool
	// Rewritten is true when the pipeline rewrites the line at some point.
	Rewritten bool
}

// Matcher is one stream selector matcher.
type Matcher struct {
	Name, Op, Value string // Op is = != =~ !~
}

// Stage is one line filter stage. Positive stages keep a line matching any alternative; negative
// stages keep a line matching none of them (Loki turns `!= "a" or "b"` into `!= "a" != "b"`).
type Stage struct {
	Negative     bool
	Alternatives []Filter
}

// Filter is one line filter alternative.
type Filter struct {
	Kind  string // contains | regex | pattern | ip
	Value string
}

// Parse parses a LogQL query.
func Parse(src string) (*Query, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	q := &Query{}
	p.q = q
	if err := p.expr(0); err != nil {
		return nil, err
	}
	if p.peek().kind != tEOF {
		return nil, p.errf("unexpected %s", p.peek())
	}
	if len(q.Selections) == 0 {
		return nil, fmt.Errorf("query has no stream selector")
	}
	return q, nil
}

type parser struct {
	toks     []token
	i        int
	q        *Query
	counting int // >0 while inside a range aggregation
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) peekAt(n int) token {
	if p.i+n < len(p.toks) {
		return p.toks[p.i+n]
	}
	return p.toks[len(p.toks)-1]
}
func (p *parser) next() token { t := p.toks[p.i]; p.i++; return t }
func (p *parser) errf(f string, a ...any) error {
	return fmt.Errorf("logql: at %d: %s", p.peek().pos, fmt.Sprintf(f, a...))
}
func (p *parser) isOp(s string) bool { t := p.peek(); return t.kind == tOp && t.text == s }
func (p *parser) isKw(s string) bool {
	t := p.peek()
	return t.kind == tIdent && strings.EqualFold(t.text, s)
}
func (p *parser) expectOp(s string) error {
	if !p.isOp(s) {
		return p.errf("expected %q, got %s", s, p.peek())
	}
	p.i++
	return nil
}

// Binary operator precedence, lowest first.
var binPrec = map[string]int{
	"or": 1, "and": 2, "unless": 2,
	"==": 3, "!=": 3, ">": 3, ">=": 3, "<": 3, "<=": 3,
	"+": 4, "-": 4, "*": 5, "/": 5, "%": 5, "^": 6,
}

func (p *parser) binOp() (string, bool) {
	t := p.peek()
	switch t.kind {
	case tOp:
		if _, ok := binPrec[t.text]; ok {
			return t.text, true
		}
	case tIdent:
		l := strings.ToLower(t.text)
		if l == "or" || l == "and" || l == "unless" {
			return l, true
		}
	}
	return "", false
}

// expr parses a binary expression with precedence climbing.
func (p *parser) expr(minPrec int) error {
	if err := p.unary(); err != nil {
		return err
	}
	for {
		op, ok := p.binOp()
		if !ok || binPrec[op] < minPrec {
			return nil
		}
		p.i++
		if err := p.binModifiers(); err != nil {
			return err
		}
		next := binPrec[op] + 1
		if op == "^" {
			next = binPrec[op] // right associative
		}
		if err := p.expr(next); err != nil {
			return err
		}
	}
}

func (p *parser) binModifiers() error {
	if p.isKw("bool") {
		p.i++
	}
	if p.isKw("on") || p.isKw("ignoring") {
		p.i++
		if err := p.labelList(); err != nil {
			return err
		}
		if p.isKw("group_left") || p.isKw("group_right") {
			p.i++
			if p.isOp("(") {
				if err := p.labelList(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (p *parser) labelList() error {
	if err := p.expectOp("("); err != nil {
		return err
	}
	for !p.isOp(")") {
		if p.peek().kind != tIdent {
			return p.errf("expected label, got %s", p.peek())
		}
		p.i++
		if p.isOp(",") {
			p.i++
		}
	}
	p.i++
	return nil
}

var rangeOps = map[string]bool{
	"rate": true, "rate_counter": true, "count_over_time": true, "bytes_rate": true, "bytes_over_time": true,
	"avg_over_time": true, "sum_over_time": true, "min_over_time": true, "max_over_time": true,
	"stdvar_over_time": true, "stddev_over_time": true, "quantile_over_time": true,
	"first_over_time": true, "last_over_time": true, "absent_over_time": true,
}

var vectorOps = map[string]bool{
	"sum": true, "avg": true, "max": true, "min": true, "count": true, "stddev": true, "stdvar": true,
	"bottomk": true, "topk": true, "sort": true, "sort_desc": true, "approx_topk": true,
}

func (p *parser) unary() error {
	t := p.peek()
	switch {
	case t.kind == tOp && (t.text == "-" || t.text == "+"):
		p.i++
		return p.unary()
	case t.kind == tNumber:
		p.i++
		return nil
	case t.kind == tOp && t.text == "(":
		p.i++
		if err := p.expr(0); err != nil {
			return err
		}
		if err := p.expectOp(")"); err != nil {
			return err
		}
		// A parenthesised log expression may be followed by more pipeline stages or a range.
		return nil
	case t.kind == tOp && t.text == "{":
		return p.logExpr(false)
	case t.kind == tIdent:
		name := strings.ToLower(t.text)
		switch {
		case rangeOps[name] && p.peekAt(1).kind == tOp && p.peekAt(1).text == "(":
			return p.rangeAgg()
		case vectorOps[name]:
			return p.vectorAgg()
		case name == "label_replace":
			p.i++
			if err := p.expectOp("("); err != nil {
				return err
			}
			if err := p.expr(0); err != nil {
				return err
			}
			for k := 0; k < 4; k++ {
				if err := p.expectOp(","); err != nil {
					return err
				}
				if p.peek().kind != tString {
					return p.errf("expected string in label_replace")
				}
				p.i++
			}
			return p.expectOp(")")
		case name == "vector":
			p.i++
			if err := p.expectOp("("); err != nil {
				return err
			}
			if p.peek().kind != tNumber {
				return p.errf("expected number in vector()")
			}
			p.i++
			return p.expectOp(")")
		case name == "variants":
			return p.variants()
		}
	}
	return p.errf("unexpected %s", t)
}

func (p *parser) grouping() error {
	if p.isKw("by") || p.isKw("without") {
		p.i++
		return p.labelList()
	}
	return nil
}

func (p *parser) vectorAgg() error {
	p.i++ // op
	if err := p.grouping(); err != nil {
		return err
	}
	if err := p.expectOp("("); err != nil {
		return err
	}
	if p.peek().kind == tNumber && p.peekAt(1).kind == tOp && p.peekAt(1).text == "," {
		p.i += 2
	}
	if err := p.expr(0); err != nil {
		return err
	}
	if err := p.expectOp(")"); err != nil {
		return err
	}
	return p.grouping()
}

func (p *parser) rangeAgg() error {
	p.i++ // op
	if err := p.expectOp("("); err != nil {
		return err
	}
	if p.peek().kind == tNumber && p.peekAt(1).kind == tOp && p.peekAt(1).text == "," {
		p.i += 2
	}
	p.counting++
	err := p.logExpr(true)
	p.counting--
	if err != nil {
		return err
	}
	if err := p.expectOp(")"); err != nil {
		return err
	}
	return p.grouping()
}

func (p *parser) variants() error {
	p.i++
	if err := p.expectOp("("); err != nil {
		return err
	}
	for {
		if err := p.expr(0); err != nil {
			return err
		}
		if p.isOp(",") {
			p.i++
			continue
		}
		break
	}
	if err := p.expectOp(")"); err != nil {
		return err
	}
	if !p.isKw("of") {
		return p.errf("expected of")
	}
	p.i++
	if err := p.expectOp("("); err != nil {
		return err
	}
	p.counting++
	err := p.logExpr(true)
	p.counting--
	if err != nil {
		return err
	}
	return p.expectOp(")")
}

// logExpr parses a selector with its pipeline, possibly parenthesised, and, inside a range
// aggregation, the range, offset and unwrap parts in any of the orders the grammar allows.
func (p *parser) logExpr(inRange bool) error {
	depth := 0
	for p.isOp("(") {
		p.i++
		depth++
	}
	sel, err := p.selector()
	if err != nil {
		return err
	}
	sel.Counting = p.counting > 0
	seenRange := false
	for {
		switch {
		case p.peek().kind == tRange && inRange && !seenRange:
			p.i++
			seenRange = true
			if p.isKw("offset") {
				p.i++
				if p.isOp("-") {
					p.i++
				}
				if p.peek().kind != tDuration {
					return p.errf("expected duration after offset")
				}
				p.i++
			}
			continue
		case p.isOp(")") && depth > 0:
			p.i++
			depth--
			continue
		case p.isLineFilterStart():
			if err := p.lineFilterStage(&sel); err != nil {
				return err
			}
			continue
		case p.isOp("|"):
			if err := p.pipeStage(&sel, inRange); err != nil {
				return err
			}
			continue
		}
		break
	}
	if depth != 0 {
		return p.errf("unbalanced parentheses in log expression")
	}
	if inRange && !seenRange {
		return p.errf("range aggregation without a range")
	}
	if !inRange && p.peek().kind == tRange {
		return p.errf("range outside a range aggregation")
	}
	p.q.Selections = append(p.q.Selections, sel)
	return nil
}

func (p *parser) selector() (Selection, error) {
	var sel Selection
	if err := p.expectOp("{"); err != nil {
		return sel, err
	}
	for !p.isOp("}") {
		m, err := p.matcher()
		if err != nil {
			return sel, err
		}
		sel.Matchers = append(sel.Matchers, m)
		if p.isOp(",") {
			p.i++
		} else if !p.isOp("}") {
			return sel, p.errf("expected , or } in selector")
		}
	}
	p.i++
	return sel, nil
}

func (p *parser) matcher() (Matcher, error) {
	name := p.peek()
	if name.kind != tIdent {
		return Matcher{}, p.errf("expected label name, got %s", name)
	}
	p.i++
	op := p.peek()
	if op.kind != tOp || (op.text != "=" && op.text != "!=" && op.text != "=~" && op.text != "!~") {
		return Matcher{}, p.errf("expected matcher operator, got %s", op)
	}
	p.i++
	val := p.peek()
	if val.kind != tString {
		return Matcher{}, p.errf("expected string, got %s", val)
	}
	p.i++
	return Matcher{Name: name.text, Op: op.text, Value: val.text}, nil
}

func (p *parser) isLineFilterStart() bool {
	t := p.peek()
	if t.kind != tOp {
		return false
	}
	switch t.text {
	case "|=", "|~", "|>", "!=", "!~", "!>":
		return true
	}
	return false
}

func filterKind(op string) (kind string, negative bool) {
	switch op {
	case "|=":
		return "contains", false
	case "!=":
		return "contains", true
	case "|~":
		return "regex", false
	case "!~":
		return "regex", true
	case "|>":
		return "pattern", false
	case "!>":
		return "pattern", true
	}
	return "", false
}

// lineFilterStage parses one line filter and its "or" chain.
func (p *parser) lineFilterStage(sel *Selection) error {
	op := p.next().text
	kind, neg := filterKind(op)
	st := Stage{Negative: neg}
	f, err := p.filterValue(kind)
	if err != nil {
		return err
	}
	st.Alternatives = append(st.Alternatives, f)
	for p.isKw("or") && (p.peekAt(1).kind == tString || (p.peekAt(1).kind == tIdent && strings.EqualFold(p.peekAt(1).text, "ip"))) {
		p.i++
		f, err := p.filterValue(kind)
		if err != nil {
			return err
		}
		st.Alternatives = append(st.Alternatives, f)
	}
	if !sel.Rewritten {
		sel.Stages = append(sel.Stages, st)
	}
	return nil
}

func (p *parser) filterValue(kind string) (Filter, error) {
	if p.isKw("ip") && p.peekAt(1).kind == tOp && p.peekAt(1).text == "(" {
		p.i += 2
		if p.peek().kind != tString {
			return Filter{}, p.errf("expected string in ip()")
		}
		v := p.next().text
		if err := p.expectOp(")"); err != nil {
			return Filter{}, err
		}
		return Filter{Kind: "ip", Value: v}, nil
	}
	if p.peek().kind != tString {
		return Filter{}, p.errf("expected string after line filter, got %s", p.peek())
	}
	return Filter{Kind: kind, Value: p.next().text}, nil
}

// pipeStage parses one "| ..." stage.
func (p *parser) pipeStage(sel *Selection, inRange bool) error {
	p.i++ // |
	t := p.peek()
	if t.kind != tIdent && !(t.kind == tOp && t.text == "(") {
		return p.errf("unexpected %s after |", t)
	}
	switch strings.ToLower(t.text) {
	case "json":
		p.i++
		return p.extractionList()
	case "logfmt":
		p.i++
		for p.peek().kind == tFlag {
			p.i++
		}
		return p.extractionList()
	case "regexp", "pattern":
		p.i++
		if p.peek().kind != tString {
			return p.errf("expected string after %s", t.text)
		}
		p.i++
		return nil
	case "unpack":
		p.i++
		return nil
	case "line_format":
		p.i++
		if p.peek().kind != tString {
			return p.errf("expected string after line_format")
		}
		p.i++
		sel.Rewritten = true
		return nil
	case "decolorize":
		p.i++
		sel.Rewritten = true
		return nil
	case "label_format":
		p.i++
		for {
			if p.peek().kind != tIdent {
				return p.errf("expected label in label_format")
			}
			p.i++
			if err := p.expectOp("="); err != nil {
				return err
			}
			if v := p.peek(); v.kind != tString && v.kind != tIdent {
				return p.errf("expected value in label_format")
			}
			p.i++
			if !p.isOp(",") {
				return nil
			}
			p.i++
		}
	case "drop", "keep":
		p.i++
		for {
			if p.peek().kind != tIdent {
				return p.errf("expected label in %s", t.text)
			}
			if op := p.peekAt(1); op.kind == tOp && (op.text == "=" || op.text == "!=" || op.text == "=~" || op.text == "!~") {
				if _, err := p.matcher(); err != nil {
					return err
				}
			} else {
				p.i++
			}
			if !p.isOp(",") {
				return nil
			}
			p.i++
		}
	case "unwrap":
		if !inRange {
			return p.errf("unwrap outside a range aggregation")
		}
		p.i++
		if p.peek().kind != tIdent {
			return p.errf("expected label after unwrap")
		}
		conv := strings.ToLower(p.peek().text)
		if (conv == "bytes" || conv == "duration" || conv == "duration_seconds") && p.peekAt(1).kind == tOp && p.peekAt(1).text == "(" {
			p.i += 2
			if p.peek().kind != tIdent {
				return p.errf("expected label in conversion")
			}
			p.i++
			return p.expectOp(")")
		}
		p.i++
		return nil
	}
	return p.labelFilter()
}

func (p *parser) extractionList() error {
	for p.peek().kind == tIdent && !p.isStageEnd() {
		p.i++
		if p.isOp("=") {
			p.i++
			if p.peek().kind != tString {
				return p.errf("expected string in extraction")
			}
			p.i++
		}
		if !p.isOp(",") {
			return nil
		}
		p.i++
	}
	return nil
}

func (p *parser) isStageEnd() bool {
	t := p.peek()
	return t.kind == tEOF || t.kind == tRange || (t.kind == tOp && (t.text == "|" || t.text == ")")) || p.isLineFilterStart()
}

// labelFilter parses a boolean combination of label comparisons. Its semantics are not needed:
// ignoring a label filter can only widen what a selection reads.
func (p *parser) labelFilter() error {
	if err := p.labelFilterTerm(); err != nil {
		return err
	}
	for {
		switch {
		case p.isKw("and") || p.isKw("or") || p.isOp(","):
			p.i++
		case p.isOp("(") || (p.peek().kind == tIdent && p.peekAt(1).kind == tOp && isCmp(p.peekAt(1).text)):
		default:
			return nil
		}
		if err := p.labelFilterTerm(); err != nil {
			return err
		}
	}
}

func isCmp(s string) bool {
	switch s {
	case "=", "!=", "=~", "!~", ">", ">=", "<", "<=", "==":
		return true
	}
	return false
}

func (p *parser) labelFilterTerm() error {
	if p.isOp("(") {
		p.i++
		if err := p.labelFilter(); err != nil {
			return err
		}
		return p.expectOp(")")
	}
	if p.peek().kind != tIdent {
		return p.errf("expected label filter, got %s", p.peek())
	}
	p.i++
	op := p.peek()
	if op.kind != tOp || !isCmp(op.text) {
		return p.errf("expected comparison, got %s", op)
	}
	p.i++
	v := p.peek()
	switch {
	case v.kind == tString || v.kind == tNumber || v.kind == tDuration || v.kind == tBytes:
		p.i++
	case v.kind == tOp && v.text == "-" && (p.peekAt(1).kind == tNumber || p.peekAt(1).kind == tDuration):
		p.i += 2
	case v.kind == tIdent && strings.EqualFold(v.text, "ip") && p.peekAt(1).kind == tOp && p.peekAt(1).text == "(":
		p.i += 2
		if p.peek().kind != tString {
			return p.errf("expected string in ip()")
		}
		p.i++
		return p.expectOp(")")
	default:
		return p.errf("expected value in label filter, got %s", v)
	}
	return nil
}
