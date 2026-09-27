// Package automaton decides questions about regular languages written in RE2 syntax, with Go's
// regexp semantics: does some string match all of these patterns and none of those?
//
// It works directly on the program Go's own regexp/syntax compiles, so a pattern here means exactly
// what it means to Go's regexp package, which is also what Loki and the OpenTelemetry Collector use.
// Matching is search semantics (like regexp.MatchString): a pattern matches a string if it matches
// any substring, subject to its anchors. Wrap a pattern in \A(?:...)\z for whole-string semantics.
//
// Every "found" answer carries a witness string, and the witness is re-checked with the real regexp
// package before it is returned. A mismatch is reported as an error, never as an answer.
package automaton

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Pattern is a compiled RE2 pattern.
type Pattern struct {
	src  string
	prog *syntax.Prog
	re   *regexp.Regexp
}

// Compile parses and compiles an RE2 pattern with Go's default (Perl) flags, the same flags
// regexp.Compile uses.
func Compile(expr string) (*Pattern, error) {
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	ast, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, err
	}
	prog, err := syntax.Compile(ast.Simplify())
	if err != nil {
		return nil, err
	}
	return &Pattern{src: expr, prog: prog, re: re}, nil
}

// MustCompile is Compile that panics on error. For patterns that are constants.
func MustCompile(expr string) *Pattern {
	p, err := Compile(expr)
	if err != nil {
		panic(err)
	}
	return p
}

// Literal returns a pattern matching any string that contains s.
func Literal(s string) *Pattern { return MustCompile(regexp.QuoteMeta(s)) }

// String returns the source expression.
func (p *Pattern) String() string { return p.src }

// Regexp returns the equivalent compiled Go regexp.
func (p *Pattern) Regexp() *regexp.Regexp { return p.re }

// Term is one constraint: the string must match Pattern, or must not match it when Negate is set.
type Term struct {
	Pattern *Pattern
	Negate  bool
}

// ErrLimit is returned when a question needs more states, or more work, than the caller allowed.
// Callers must treat it as "unknown", never as "no".
var ErrLimit = errors.New("automaton: state or work limit exceeded")

// DefaultLimit bounds the explored product states.
const DefaultLimit = 200000

// workPerState bounds the work of a question as a multiple of its state limit. Each state is
// stepped once per character-class cell and pattern, and a pattern of many Unicode classes has
// hundreds of cells, so counting states alone does not bound time. The largest question in the unit
// and e2e suites needs about 66,000 steps; the bound for the default limit is 3.2 million.
const workPerState = 16

// Glob is the anchored pattern of a wildcard expression, where * matches any run of characters and
// everything else is literal, as index names and Fluent Bit tags use them.
func Glob(g string) string {
	parts := strings.Split(g, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return `\A` + strings.Join(parts, ".*") + `\z`
}

// Overlap reports whether two patterns can match the same string. A pattern that does not compile,
// or a question too large to decide, counts as overlapping: callers use it to prove things apart.
func Overlap(a, b string) bool {
	pa, err1 := Compile(a)
	pb, err2 := Compile(b)
	if err1 != nil || err2 != nil {
		return true
	}
	_, found, err := Intersects(pa, pb, 0)
	return err != nil || found
}

// Witness searches for a string satisfying every term. It returns the string and true if one exists,
// or "" and false if none exists. It returns ErrLimit if deciding needs more than limit states.
func Witness(terms []Term, limit int) (string, bool, error) {
	if len(terms) == 0 {
		return "", true, nil
	}
	if limit <= 0 {
		limit = DefaultLimit
	}
	s := newSearch(terms)
	w, ok, err := s.run(limit)
	if err != nil || !ok {
		return "", ok, err
	}
	for _, t := range terms {
		if t.Pattern.re.MatchString(w) == t.Negate {
			return "", false, fmt.Errorf("automaton: witness %q fails %q (negate=%v); internal error", w, t.Pattern.src, t.Negate)
		}
	}
	return w, true, nil
}

// Intersects reports whether some string matches both patterns, with a witness.
func Intersects(a, b *Pattern, limit int) (string, bool, error) {
	return Witness([]Term{{Pattern: a}, {Pattern: b}}, limit)
}

// Subset reports whether every string matching a also matches b. When it does not, the returned
// string matches a and not b.
func Subset(a, b *Pattern, limit int) (bool, string, error) {
	w, found, err := Witness([]Term{{Pattern: a}, {Pattern: b, Negate: true}}, limit)
	if err != nil {
		return false, "", err
	}
	return !found, w, nil
}

// Accepts runs the automaton on s. It exists so tests can compare it with regexp.MatchString.
func (p *Pattern) Accepts(s string) bool {
	m := machine{prog: p.prog}
	st := m.start()
	prev := ctxStart
	for _, r := range s {
		next := classOf(r)
		cl, matched := m.closure(st, prev, next)
		if matched {
			return true
		}
		st = m.step(cl, r)
		prev = next
	}
	_, matched := m.closure(st, prev, ctxEnd)
	return matched
}

// context classes of the characters around a position, as far as empty-width assertions care.
type ctx uint8

const (
	ctxStart   ctx = iota // before the first rune
	ctxEnd                // after the last rune
	ctxWord               // [0-9A-Za-z_]
	ctxNewline            // \n
	ctxOther
)

func classOf(r rune) ctx {
	switch {
	case r == '\n':
		return ctxNewline
	case r < utf8.RuneSelf && syntax.IsWordChar(r):
		return ctxWord
	}
	return ctxOther
}

func isWord(c ctx) bool { return c == ctxWord }

// emptyOK reports whether an empty-width assertion holds between prev and next.
func emptyOK(op syntax.EmptyOp, prev, next ctx) bool {
	if op&syntax.EmptyBeginText != 0 && prev != ctxStart {
		return false
	}
	if op&syntax.EmptyEndText != 0 && next != ctxEnd {
		return false
	}
	if op&syntax.EmptyBeginLine != 0 && prev != ctxStart && prev != ctxNewline {
		return false
	}
	if op&syntax.EmptyEndLine != 0 && next != ctxEnd && next != ctxNewline {
		return false
	}
	if op&syntax.EmptyWordBoundary != 0 && isWord(prev) == isWord(next) {
		return false
	}
	if op&syntax.EmptyNoWordBoundary != 0 && isWord(prev) != isWord(next) {
		return false
	}
	return true
}

// machine runs one program with search semantics.
type machine struct{ prog *syntax.Prog }

// state is a sorted set of program counters waiting at a position (before epsilon closure). The
// program start is re-added at every position, which gives search semantics.
type state []uint32

func (m machine) start() state { return state{uint32(m.prog.Start)} }

// closure follows epsilon transitions from st plus the program start, given the characters around
// the position. It returns the consuming instructions reached and whether Match was reached.
func (m machine) closure(st state, prev, next ctx) ([]uint32, bool) {
	seen := make(map[uint32]bool, 16)
	var out []uint32
	matched := false
	stack := append([]uint32{uint32(m.prog.Start)}, st...)
	for len(stack) > 0 {
		pc := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[pc] {
			continue
		}
		seen[pc] = true
		in := &m.prog.Inst[pc]
		switch in.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			stack = append(stack, in.Out, in.Arg)
		case syntax.InstCapture, syntax.InstNop:
			stack = append(stack, in.Out)
		case syntax.InstEmptyWidth:
			if emptyOK(syntax.EmptyOp(in.Arg), prev, next) {
				stack = append(stack, in.Out)
			}
		case syntax.InstMatch:
			matched = true
		case syntax.InstFail:
		default: // consuming instructions
			out = append(out, pc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, matched
}

// step consumes r from the consuming instructions cl.
func (m machine) step(cl []uint32, r rune) state {
	var next []uint32
	for _, pc := range cl {
		in := &m.prog.Inst[pc]
		if in.MatchRune(r) {
			next = append(next, in.Out)
		}
	}
	sort.Slice(next, func(i, j int) bool { return next[i] < next[j] })
	return dedup(next)
}

func dedup(s []uint32) state {
	if len(s) < 2 {
		return s
	}
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// ranges returns the rune ranges (inclusive pairs) the consuming instruction pc accepts.
func (m machine) ranges(pc uint32) [][2]rune {
	in := &m.prog.Inst[pc]
	switch in.Op {
	case syntax.InstRuneAny:
		return [][2]rune{{0, unicode.MaxRune}}
	case syntax.InstRuneAnyNotNL:
		return [][2]rune{{0, '\n' - 1}, {'\n' + 1, unicode.MaxRune}}
	case syntax.InstRune1:
		return [][2]rune{{in.Rune[0], in.Rune[0]}}
	case syntax.InstRune:
		if len(in.Rune) == 1 {
			r0 := in.Rune[0]
			out := [][2]rune{{r0, r0}}
			if syntax.Flags(in.Arg)&syntax.FoldCase != 0 {
				for r := unicode.SimpleFold(r0); r != r0; r = unicode.SimpleFold(r) {
					out = append(out, [2]rune{r, r})
				}
			}
			return out
		}
		var out [][2]rune
		for i := 0; i+1 < len(in.Rune); i += 2 {
			out = append(out, [2]rune{in.Rune[i], in.Rune[i+1]})
		}
		return out
	}
	panic(fmt.Sprintf("automaton: unexpected consuming op %v", in.Op))
}

// search explores the product of all machines on the fly.
type search struct {
	terms    []Term
	machines []machine
}

func newSearch(terms []Term) *search {
	s := &search{terms: terms}
	for _, t := range terms {
		s.machines = append(s.machines, machine{prog: t.Pattern.prog})
	}
	return s
}

// node is one product state. matched[i] means machine i has already matched; its pcs are dropped.
type node struct {
	pcs     []state
	matched []bool
	prev    ctx
	parent  int
	via     rune
}

func (n *node) key() string {
	var b strings.Builder
	b.WriteByte(byte(n.prev))
	for i, st := range n.pcs {
		if n.matched[i] {
			b.WriteString("|M")
			continue
		}
		b.WriteByte('|')
		for _, pc := range st {
			fmt.Fprintf(&b, "%d,", pc)
		}
	}
	return b.String()
}

// classCuts are boundaries that separate context classes, so each alphabet cell has one class.
var classCuts = []rune{'\n', '\n' + 1, '0', '9' + 1, 'A', 'Z' + 1, '_', '_' + 1, 'a', 'z' + 1, utf8.RuneSelf}

func (s *search) run(limit int) (string, bool, error) {
	n0 := &node{prev: ctxStart, parent: -1}
	for _, m := range s.machines {
		n0.pcs = append(n0.pcs, m.start())
		n0.matched = append(n0.matched, false)
	}
	nodes := []*node{n0}
	seen := map[string]bool{n0.key(): true}
	work, maxWork := 0, limit*workPerState
	for qi := 0; qi < len(nodes); qi++ {
		n := nodes[qi]
		if s.acceptsAtEnd(n) {
			return s.witness(nodes, qi), true, nil
		}
		// Closures depend on the class of the next rune; compute them for each class.
		type cl struct {
			pcs     []uint32
			matched bool
		}
		closures := map[ctx][]cl{}
		for _, c := range []ctx{ctxWord, ctxNewline, ctxOther} {
			var row []cl
			for i, m := range s.machines {
				if n.matched[i] {
					row = append(row, cl{matched: true})
					continue
				}
				pcs, matched := m.closure(n.pcs[i], n.prev, c)
				row = append(row, cl{pcs: pcs, matched: matched})
			}
			closures[c] = row
		}
		cuts := append([]rune(nil), classCuts...)
		for _, row := range closures {
			for i, c := range row {
				for _, pc := range c.pcs {
					for _, r := range s.machines[i].ranges(pc) {
						cuts = append(cuts, r[0], r[1]+1)
					}
				}
			}
		}
		cs := cells(cuts)
		if work += len(cs) * len(s.machines); work > maxWork {
			return "", false, ErrLimit
		}
		for _, cell := range cs {
			rep, ok := representative(cell)
			if !ok {
				continue
			}
			row := closures[classOf(rep)]
			child := &node{prev: classOf(rep), parent: qi, via: rep}
			dead := false
			for i, c := range row {
				matched := c.matched
				if matched && s.terms[i].Negate {
					dead = true // a negated pattern matched; no extension can undo it
					break
				}
				child.matched = append(child.matched, matched)
				if matched {
					child.pcs = append(child.pcs, nil)
					continue
				}
				child.pcs = append(child.pcs, s.machines[i].step(c.pcs, rep))
			}
			if dead {
				continue
			}
			k := child.key()
			if seen[k] {
				continue
			}
			seen[k] = true
			nodes = append(nodes, child)
			if len(nodes) > limit {
				return "", false, ErrLimit
			}
		}
	}
	return "", false, nil
}

func (s *search) acceptsAtEnd(n *node) bool {
	for i, m := range s.machines {
		acc := n.matched[i]
		if !acc {
			_, acc = m.closure(n.pcs[i], n.prev, ctxEnd)
		}
		if acc == s.terms[i].Negate {
			return false
		}
	}
	return true
}

func (s *search) witness(nodes []*node, i int) string {
	var rs []rune
	for ; nodes[i].parent >= 0; i = nodes[i].parent {
		rs = append(rs, nodes[i].via)
	}
	for l, r := 0, len(rs)-1; l < r; l, r = l+1, r-1 {
		rs[l], rs[r] = rs[r], rs[l]
	}
	return string(rs)
}

// cells turns cut points into disjoint half-open rune intervals covering [0, MaxRune].
func cells(cuts []rune) [][2]rune {
	cuts = append(cuts, 0, unicode.MaxRune+1)
	sort.Slice(cuts, func(i, j int) bool { return cuts[i] < cuts[j] })
	var out [][2]rune
	for i := 0; i+1 < len(cuts); i++ {
		lo, hi := cuts[i], cuts[i+1]
		if lo == hi || lo < 0 || lo > unicode.MaxRune {
			continue
		}
		if hi > unicode.MaxRune+1 {
			hi = unicode.MaxRune + 1
		}
		out = append(out, [2]rune{lo, hi - 1})
	}
	return out
}

// representative picks a rune from the cell that can occur in a Go string, preferring a space so
// witnesses stay readable. Surrogates cannot occur in valid UTF-8: a cell that starts inside the
// surrogate block is represented by its last rune if that is valid, and skipped otherwise.
func representative(c [2]rune) (rune, bool) {
	lo, hi := c[0], c[1]
	if lo <= ' ' && ' ' <= hi {
		return ' ', true
	}
	if utf8.ValidRune(lo) {
		return lo, true
	}
	if utf8.ValidRune(hi) {
		return hi, true
	}
	return 0, false
}
