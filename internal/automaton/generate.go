package automaton

import (
	"math/rand/v2"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Members returns up to n distinct strings matching expr as a whole (the expression is used as
// written; anchors in it are respected by filtering with the real regexp). Near reports strings
// derived from them by small edits, whatever their membership; callers decide membership with the
// real regexp. Both are for differential testing against other regex engines.
func Members(expr string, n int, seed uint64) ([]string, error) {
	p, err := Compile(expr)
	if err != nil {
		return nil, err
	}
	ast, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, err
	}
	ast = ast.Simplify()
	r := rand.New(rand.NewPCG(seed, 0x5eed))
	seen := map[string]bool{}
	var out []string
	for tries := 0; len(out) < n && tries < n*50; tries++ {
		var b strings.Builder
		gen(&b, ast, r)
		s := b.String()
		if seen[s] || !p.re.MatchString(s) {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if w, ok, err := Witness([]Term{{Pattern: p}}, 0); err == nil && ok && !seen[w] {
		out = append(out, w)
	}
	return out, nil
}

// Near returns edits of each input: deletions, insertions, substitutions, case flips, a trailing
// newline, surrounding spaces and look-alike runes.
func Near(in []string, perInput int, seed uint64) []string {
	r := rand.New(rand.NewPCG(seed, 0xed17))
	extra := []rune{' ', '\n', '\t', 'a', 'Z', '0', '9', '-', '.', '_', '<', '>', '"', '\\', 'é', 'İ', 'K', 'ſ', ' ', '​', '�'}
	var out []string
	for _, s := range in {
		rs := []rune(s)
		out = append(out, s+"\n", " "+s, s+" ", strings.ToUpper(s), strings.ToLower(s), s+s)
		for k := 0; k < perInput; k++ {
			c := append([]rune(nil), rs...)
			switch r.IntN(3) {
			case 0:
				if len(c) > 0 {
					i := r.IntN(len(c))
					c = append(c[:i], c[i+1:]...)
				}
			case 1:
				i := r.IntN(len(c) + 1)
				c = append(c[:i], append([]rune{extra[r.IntN(len(extra))]}, c[i:]...)...)
			default:
				if len(c) > 0 {
					c[r.IntN(len(c))] = extra[r.IntN(len(extra))]
				}
			}
			out = append(out, string(c))
		}
	}
	return out
}

func gen(b *strings.Builder, re *syntax.Regexp, r *rand.Rand) {
	switch re.Op {
	case syntax.OpLiteral:
		for _, c := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 && r.IntN(2) == 0 {
				c = unicode.SimpleFold(c)
			}
			b.WriteRune(c)
		}
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			return
		}
		i := r.IntN(len(re.Rune)/2) * 2
		lo, hi := re.Rune[i], re.Rune[i+1]
		if hi > lo+0x10000 {
			hi = lo + 0x10000 // stay near the start of huge ranges (readable, valid)
		}
		c := lo + rune(r.IntN(int(hi-lo)+1))
		if !utf8.ValidRune(c) {
			c = lo
		}
		b.WriteRune(c)
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		b.WriteRune(rune('a' + r.IntN(26)))
	case syntax.OpCapture:
		gen(b, re.Sub[0], r)
	case syntax.OpConcat:
		for _, s := range re.Sub {
			gen(b, s, r)
		}
	case syntax.OpAlternate:
		gen(b, re.Sub[r.IntN(len(re.Sub))], r)
	case syntax.OpStar:
		for k := r.IntN(4); k > 0; k-- {
			gen(b, re.Sub[0], r)
		}
	case syntax.OpPlus:
		for k := 1 + r.IntN(3); k > 0; k-- {
			gen(b, re.Sub[0], r)
		}
	case syntax.OpQuest:
		if r.IntN(2) == 0 {
			gen(b, re.Sub[0], r)
		}
	case syntax.OpRepeat:
		max := re.Max
		if max < 0 {
			max = re.Min + 3
		}
		for k := re.Min + r.IntN(max-re.Min+1); k > 0; k-- {
			gen(b, re.Sub[0], r)
		}
	}
	// Empty-width ops (anchors, boundaries) and empty matches write nothing.
}
