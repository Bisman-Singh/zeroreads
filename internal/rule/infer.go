// Package rule turns a Drain template and the lines observed under it into an exact removal
// language: an anchored RE2 pattern that says precisely which lines a rule may remove.
//
// The language is defined on the templated text itself (the whole body for plain logs, the message
// field for structured ones). Safety never depends on how wide or narrow it is: every usage check and
// every overlap check runs against this same language, so whatever it covers is exactly what is
// analysed. Its precision only decides how much volume a rule can remove.
package rule

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Mask is a drainprocessor masking rule: matches of Pattern become the token "<Name>".
type Mask struct {
	Name    string
	Pattern string
}

// Options bound inference.
type Options struct {
	// MinSamples is the fewest aligned lines a template needs before a language is inferred.
	MinSamples int
	// MaxEnum is the largest set of distinct values written out literally at one position.
	MaxEnum int
	// EnumSupport is how many observations per distinct value an enumeration needs. With fewer,
	// the value set is probably not saturated and a shape class is used instead.
	EnumSupport int
}

// DefaultOptions returns conservative defaults.
func DefaultOptions() Options { return Options{MinSamples: 20, MaxEnum: 16, EnumSupport: 4} }

// Language is the inferred removal language for one template.
type Language struct {
	Template  string     // the Drain template it was inferred from
	Positions []Position // one per template token
	Regex     string     // anchored RE2 over the templated text
	Samples   int        // lines used for inference
	Skipped   int        // lines that could not be aligned token-for-token (never covered)
}

// Position describes how one token is constrained.
type Position struct {
	Token string // template token
	Kind  string // literal | enum | shape | mask
	Regex string // unanchored RE2 for this token
}

// ErrTooFewSamples means the template has too little evidence for a rule.
var ErrTooFewSamples = errors.New("rule: too few aligned samples")

// Infer builds the removal language for template from the raw texts observed under it.
func Infer(template string, masks []Mask, samples []string, opt Options) (Language, error) {
	tmplTokens := strings.Split(template, " ")
	var aligned [][]string
	skipped := 0
	for _, s := range samples {
		toks := strings.Split(s, " ")
		if len(toks) != len(tmplTokens) {
			skipped++ // a mask spanned whitespace, or leading/trailing space: not covered
			continue
		}
		aligned = append(aligned, toks)
	}
	if len(aligned) < opt.MinSamples {
		return Language{}, fmt.Errorf("%w: %d aligned of %d (need %d)", ErrTooFewSamples, len(aligned), len(samples), opt.MinSamples)
	}
	lang := Language{Template: template, Samples: len(aligned), Skipped: skipped}
	var parts []string
	for i, tt := range tmplTokens {
		values := make([]string, len(aligned))
		for j, toks := range aligned {
			values[j] = toks[i]
		}
		p, err := inferPosition(tt, values, masks, opt)
		if err != nil {
			return Language{}, fmt.Errorf("position %d (%q): %w", i, tt, err)
		}
		lang.Positions = append(lang.Positions, p)
		parts = append(parts, p.Regex)
	}
	lang.Regex = `\A` + strings.Join(parts, " ") + `\z`
	re, err := regexp.Compile(lang.Regex)
	if err != nil {
		return Language{}, fmt.Errorf("rule: built invalid regex %q: %w", lang.Regex, err)
	}
	for _, toks := range aligned {
		if s := strings.Join(toks, " "); !re.MatchString(s) {
			return Language{}, fmt.Errorf("rule: inferred language rejects its own sample %q; internal error", s)
		}
	}
	return lang, nil
}

func distinct(values []string) []string {
	set := map[string]bool{}
	for _, v := range values {
		set[v] = true
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func inferPosition(tt string, values []string, masks []Mask, opt Options) (Position, error) {
	d := distinct(values)
	// 1. The same text every time: a literal.
	if len(d) == 1 {
		return Position{Token: tt, Kind: "literal", Regex: regexp.QuoteMeta(d[0])}, nil
	}
	// 2. The template token carries mask tokens and every value fits literal-parts-plus-masks.
	if re, ok := maskRegex(tt, masks); ok && allFull(re, values) {
		return Position{Token: tt, Kind: "mask", Regex: re}, nil
	}
	// 3. A small, well-supported value set: written out exactly.
	if len(d) <= opt.MaxEnum && len(values) >= opt.EnumSupport*len(d) {
		q := make([]string, len(d))
		for i, v := range d {
			q[i] = regexp.QuoteMeta(v)
		}
		return Position{Token: tt, Kind: "enum", Regex: "(?:" + strings.Join(q, "|") + ")"}, nil
	}
	// 4. A shape: shared run structure, else the narrowest character class that holds every value.
	if re, ok := runShape(values); ok {
		return Position{Token: tt, Kind: "shape", Regex: re}, nil
	}
	return Position{Token: tt, Kind: "shape", Regex: classShape(values)}, nil
}

// maskRegex turns a template token containing mask tokens (for example "<ip>" or "host=<ip>")
// into literal parts plus the mask patterns.
func maskRegex(tt string, masks []Mask) (string, bool) {
	found := false
	var b strings.Builder
	for len(tt) > 0 {
		matched := false
		for _, m := range masks {
			tok := "<" + m.Name + ">"
			if strings.HasPrefix(tt, tok) {
				b.WriteString("(?:" + m.Pattern + ")")
				tt = tt[len(tok):]
				matched, found = true, true
				break
			}
		}
		if !matched {
			b.WriteString(regexp.QuoteMeta(tt[:1]))
			tt = tt[1:]
		}
	}
	return b.String(), found
}

func allFull(expr string, values []string) bool {
	re, err := regexp.Compile(`\A(?:` + expr + `)\z`)
	if err != nil {
		return false
	}
	for _, v := range values {
		if !re.MatchString(v) {
			return false
		}
	}
	return true
}

// run is one piece of a value: a digit run, a letter run, or a single other rune.
type run struct {
	kind byte // 'd' digits, 'a' letters, 'o' other
	text string
}

func runsOf(v string) []run {
	var out []run
	for _, r := range v {
		k := byte('o')
		switch {
		case r >= '0' && r <= '9':
			k = 'd'
		case r < unicode.MaxASCII && unicode.IsLetter(r):
			k = 'a'
		}
		if k != 'o' && len(out) > 0 && out[len(out)-1].kind == k {
			out[len(out)-1].text += string(r)
			continue
		}
		out = append(out, run{kind: k, text: string(r)})
	}
	return out
}

// runShape succeeds when every value has the same run structure (same kinds, same other-runes),
// for example "518ms" and "7ms", or "pay_123456" and "pay_998877".
func runShape(values []string) (string, bool) {
	first := runsOf(values[0])
	all := [][]run{first}
	for _, v := range values[1:] {
		rs := runsOf(v)
		if len(rs) != len(first) {
			return "", false
		}
		for i := range rs {
			if rs[i].kind != first[i].kind || (rs[i].kind == 'o' && rs[i].text != first[i].text) {
				return "", false
			}
		}
		all = append(all, rs)
	}
	var b strings.Builder
	for i := range first {
		texts := make([]string, len(all))
		for j := range all {
			texts[j] = all[j][i].text
		}
		d := distinct(texts)
		if len(d) == 1 {
			b.WriteString(regexp.QuoteMeta(d[0]))
			continue
		}
		b.WriteString(classFor(texts) + lengthBounds(texts))
	}
	return b.String(), true
}

// classShape is the fallback: the narrowest known class that holds every value, with bounds.
func classShape(values []string) string {
	return classFor(values) + lengthBounds(values)
}

var classes = []struct {
	re, name string
}{
	{`[0-9]`, "digits"},
	{`[0-9a-f]`, "lower hex"},
	{`[0-9A-F]`, "upper hex"},
	{`[a-z]`, "lower"},
	{`[A-Z]`, "upper"},
	{`[A-Za-z]`, "letters"},
	{`[0-9A-Za-z]`, "alnum"},
	{`[0-9A-Za-z_.\-]`, "word"},
	{`[^ ]`, "non-space"},
}

func classFor(values []string) string {
	for _, c := range classes {
		re := regexp.MustCompile(`\A` + c.re + `*\z`)
		ok := true
		for _, v := range values {
			if !re.MatchString(v) {
				ok = false
				break
			}
		}
		if ok {
			return c.re
		}
	}
	return `[^ ]` // unreachable: tokens never contain a space
}

func lengthBounds(values []string) string {
	lo, hi := -1, 0
	for _, v := range values {
		n := len([]rune(v))
		if lo < 0 || n < lo {
			lo = n
		}
		if n > hi {
			hi = n
		}
	}
	// RE2 caps counted repetition at 1000.
	switch {
	case hi > 1000 && lo == 0:
		return "*"
	case hi > 1000:
		return "+"
	case lo == hi:
		return fmt.Sprintf("{%d}", lo)
	}
	return fmt.Sprintf("{%d,%d}", lo, hi)
}
