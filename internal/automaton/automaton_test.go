package automaton

import (
	"errors"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
	"time"
)

// alphabet used by random strings and brute force. It contains a word char, a digit, a space, a
// newline, punctuation, an uppercase letter (for case folding) and a non-ASCII rune.
var alphabet = []rune{'a', 'b', 'A', '1', ' ', '\n', '.', 'é'}

// genRegex builds a random RE2 pattern over the alphabet, exercising alternation, repetition,
// classes, anchors, word boundaries, case folding, dot and multi-line flags.
func genRegex(r *rand.Rand, depth int) string {
	if depth <= 0 {
		return genAtom(r)
	}
	switch r.IntN(9) {
	case 0:
		return genRegex(r, depth-1) + genRegex(r, depth-1)
	case 1:
		return "(?:" + genRegex(r, depth-1) + "|" + genRegex(r, depth-1) + ")"
	case 2:
		return "(?:" + genRegex(r, depth-1) + ")*"
	case 3:
		return "(?:" + genRegex(r, depth-1) + ")+"
	case 4:
		return "(?:" + genRegex(r, depth-1) + ")?"
	case 5:
		return "(?:" + genRegex(r, depth-1) + "){1,2}"
	case 6:
		return []string{"(?i)", "(?s)", "(?m)", "(?U)"}[r.IntN(4)] + genRegex(r, depth-1)
	default:
		return genAtom(r)
	}
}

func genAtom(r *rand.Rand) string {
	atoms := []string{"a", "b", "A", "1", " ", `\n`, `\.`, "é", ".", `\w`, `\W`, `\d`, `\s`, `[ab]`, `[^a]`,
		`[a-z]`, `[[:upper:]]`, `\p{L}`, "^", "$", `\A`, `\z`, `\b`, `\B`, ""}
	return atoms[r.IntN(len(atoms))]
}

func randString(r *rand.Rand, max int) string {
	n := r.IntN(max + 1)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteRune(alphabet[r.IntN(len(alphabet))])
	}
	return b.String()
}

// Membership must agree with regexp.MatchString on every pattern and string.
func TestAcceptsMatchesGoRegexp(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 3000; i++ {
		expr := genRegex(r, 4)
		p, err := Compile(expr)
		if err != nil {
			continue
		}
		for j := 0; j < 60; j++ {
			s := randString(r, 7)
			if got, want := p.Accepts(s), p.re.MatchString(s); got != want {
				t.Fatalf("pattern %q on %q: automaton %v, regexp %v", expr, s, got, want)
			}
		}
	}
}

// allStrings enumerates every string over the alphabet up to length n.
func allStrings(n int) []string {
	out := []string{""}
	level := []string{""}
	for l := 1; l <= n; l++ {
		var next []string
		for _, s := range level {
			for _, c := range alphabet {
				next = append(next, s+string(c))
			}
		}
		out = append(out, next...)
		level = next
	}
	return out
}

// For random term sets, Witness must agree with brute force: if brute force finds a string that
// satisfies every term, Witness must find one too (witnesses are verified inside Witness). If Witness
// says none exists, brute force must find none.
func TestWitnessAgreesWithBruteForce(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	strs := allStrings(4)
	checked := 0
	for i := 0; i < 1500; i++ {
		var terms []Term
		var res []*regexp.Regexp
		for k := 0; k < 1+r.IntN(3); k++ {
			expr := genRegex(r, 3)
			p, err := Compile(expr)
			if err != nil {
				continue
			}
			terms = append(terms, Term{Pattern: p, Negate: r.IntN(3) == 0})
			res = append(res, p.re)
		}
		if len(terms) == 0 {
			continue
		}
		bruteFound := ""
		bruteOK := false
		for _, s := range strs {
			ok := true
			for k, t := range terms {
				if res[k].MatchString(s) == t.Negate {
					ok = false
					break
				}
			}
			if ok {
				bruteFound, bruteOK = s, true
				break
			}
		}
		w, found, err := Witness(terms, 0)
		if err != nil {
			t.Fatalf("terms %v: %v", describe(terms), err)
		}
		if bruteOK && !found {
			t.Fatalf("terms %v: brute force found %q, Witness found none", describe(terms), bruteFound)
		}
		if found && !bruteOK && len([]rune(w)) <= 4 && onlyAlphabet(w) {
			t.Fatalf("terms %v: Witness found %q that brute force missed", describe(terms), w)
		}
		checked++
	}
	if checked < 1000 {
		t.Fatalf("only %d term sets checked", checked)
	}
}

func onlyAlphabet(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune(string(alphabet), c) {
			return false
		}
	}
	return true
}

func describe(terms []Term) []string {
	var out []string
	for _, t := range terms {
		s := t.Pattern.src
		if t.Negate {
			s = "NOT " + s
		}
		out = append(out, s)
	}
	return out
}

func TestKnownAnswers(t *testing.T) {
	cases := []struct {
		name  string
		terms []Term
		want  bool
	}{
		{"substring inside anchored template", []Term{{Pattern: MustCompile(`\AINFO GET /healthz 200 [0-9]{1,3}ms\z`)}, {Pattern: Literal("heartbeat")}}, false},
		{"status 503 reachable", []Term{{Pattern: MustCompile(`\AINFO request [0-9a-f]{16} status (?:200|201|404|503) took [0-9]{1,3}ms\z`)}, {Pattern: Literal("status 503")}}, true},
		{"status=503 not reachable", []Term{{Pattern: MustCompile(`\AINFO request [0-9a-f]{16} status (?:200|201|404|503) took [0-9]{1,3}ms\z`)}, {Pattern: Literal("status=503")}}, false},
		{"negative filter keeps some lines", []Term{{Pattern: MustCompile(`\AINFO user [a-z]+ logged in\z`)}, {Pattern: Literal("alice"), Negate: true}}, true},
		{"negative filter excludes all lines", []Term{{Pattern: MustCompile(`\AINFO user [a-z]+ logged in\z`)}, {Pattern: Literal("logged"), Negate: true}}, false},
		{"case-insensitive filter", []Term{{Pattern: MustCompile(`\AERROR payment\z`)}, {Pattern: MustCompile(`(?i)error`)}}, true},
		{"word boundary", []Term{{Pattern: MustCompile(`\Acache hit\z`)}, {Pattern: MustCompile(`\bhit\b`)}}, true},
		{"no word boundary inside", []Term{{Pattern: MustCompile(`\Acachehit\z`)}, {Pattern: MustCompile(`\bhit`)}}, false},
		{"sibling templates disjoint", []Term{{Pattern: MustCompile(`\AINFO user [a-z]+ logged in\z`)}, {Pattern: MustCompile(`\AWARN user [a-z]+ failed MFA and was logged in\z`)}}, false},
		{"wide matcher would overlap", []Term{{Pattern: MustCompile(`\AINFO user .* logged in\z`)}, {Pattern: MustCompile(`\AINFO user admin failed MFA and was logged in\z`)}}, true},
	}
	for _, c := range cases {
		w, found, err := Witness(c.terms, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if found != c.want {
			t.Fatalf("%s: found=%v (witness %q), want %v", c.name, found, w, c.want)
		}
	}
}

func TestSubset(t *testing.T) {
	a := MustCompile(`\A[0-9]{1,3}ms\z`)
	b := MustCompile(`ms\z`)
	ok, _, err := Subset(a, b, 0)
	if err != nil || !ok {
		t.Fatalf("expected subset, got %v %v", ok, err)
	}
	ok, w, err := Subset(b, a, 0)
	if err != nil || ok {
		t.Fatalf("expected not subset, got %v %v", ok, err)
	}
	if !b.re.MatchString(w) || a.re.MatchString(w) {
		t.Fatalf("counterexample %q is wrong", w)
	}
}

func TestLimit(t *testing.T) {
	// (a|b)*a(a|b){12} needs an exponential DFA; negating it forces determinisation.
	p := MustCompile(`(?:a|b)*a(?:a|b){12}\z`)
	q := MustCompile(`\A(?:a|b){40}\z`)
	_, _, err := Witness([]Term{{Pattern: q}, {Pattern: p, Negate: true}}, 50)
	if err != ErrLimit {
		t.Fatalf("expected ErrLimit, got %v", err)
	}
}

// Case folding includes runes outside ASCII: (?i)k matches the Kelvin sign and (?i)s matches the
// long s. Missing these would make Witness answer "impossible" when a string exists.
func TestFoldOrbits(t *testing.T) {
	for _, c := range []struct{ fold, plain, want string }{
		{`(?i)k`, `[kK]`, "K"},
		{`(?i)s`, `[sS]`, "ſ"},
	} {
		w, found, err := Witness([]Term{{Pattern: MustCompile(c.fold)}, {Pattern: MustCompile(c.plain), Negate: true}}, 0)
		if err != nil || !found || w != c.want {
			t.Fatalf("%s and not %s: witness %q found=%v err=%v, want %q", c.fold, c.plain, w, found, err, c.want)
		}
	}
}

// Multi-line anchors hold next to newlines, not only at the ends of the text.
func TestMultiline(t *testing.T) {
	for _, c := range []struct {
		expr, s string
		want    bool
	}{
		{`(?m)a$`, "a\nb", true},
		{`a$`, "a\nb", false},
		{`(?m)^b`, "a\nb", true},
		{`^b`, "a\nb", false},
		{`(?m)a$\n`, "a\n", true},
	} {
		if got := MustCompile(c.expr).Accepts(c.s); got != c.want {
			t.Fatalf("%q on %q: got %v want %v", c.expr, c.s, got, c.want)
		}
	}
	w, found, err := Witness([]Term{{Pattern: MustCompile(`(?m)a$`)}, {Pattern: MustCompile(`a\z`), Negate: true}}, 0)
	if err != nil || !found || !strings.Contains(w, "a\n") {
		t.Fatalf("(?m)a$ and not a\\z: witness %q found=%v err=%v", w, found, err)
	}
	w, found, err = Witness([]Term{{Pattern: MustCompile(`(?m)^b`)}, {Pattern: MustCompile(`\Ab`), Negate: true}}, 0)
	if err != nil || !found {
		t.Fatalf("(?m)^b and not \\Ab: witness %q found=%v err=%v", w, found, err)
	}
}

func TestRepresentative(t *testing.T) {
	for _, c := range []struct {
		cell [2]rune
		want rune
		ok   bool
	}{
		{[2]rune{0, 0x10FFFF}, ' ', true},
		{[2]rune{'a', 'z'}, 'a', true},
		{[2]rune{0xD800, 0xDFFF}, 0, false},
		{[2]rune{0xD900, 0xE005}, 0xE005, true},
	} {
		got, ok := representative(c.cell)
		if got != c.want || ok != c.ok {
			t.Fatalf("representative(%x) = %x,%v want %x,%v", c.cell, got, ok, c.want, c.ok)
		}
	}
}

// Time is bounded, not only states: patterns of many Unicode classes make every state expensive.
// Found by the v1 audit: the limit counted states only, and this question took 3m19s without
// reaching it. Exceeding the work bound is ErrLimit, which callers treat as "reads".
func TestWorkIsBounded(t *testing.T) {
	class := `[\p{Greek}\p{Cyrillic}\p{Han}\p{Arabic}\p{Hebrew}\p{Thai}\p{Lu}\p{Nd}\p{Devanagari}\p{Hangul}]`
	a := MustCompile(`\A(?:` + class + `|a){0,150}b\z`)
	b := MustCompile(`\A(?:` + strings.ReplaceAll(class, "Greek", "Latin") + `|a){0,150}c(?:` + class + `){0,150}\z`)
	start := time.Now()
	_, _, err := Intersects(a, b, 0)
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("took %v", d)
	}
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("got %v, want ErrLimit", err)
	}
}
