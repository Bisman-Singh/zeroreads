package dialect

import (
	"fmt"
	"regexp/syntax"
	"strings"
	"unicode"
)

const asciiWord = `[0-9A-Za-z_]`

// Onigmo prints expr for Onigmo with Ruby syntax (Fluent Bit). Ruby's ^ and $ are line anchors, so
// Go's text anchors become \A and \z; case-insensitive literals become explicit classes of their
// simple-fold orbits, so Onigmo's full case folding never applies; word boundaries become ASCII
// lookarounds.
func Onigmo(expr string) (string, error) { return onigmo.translate(expr) }

var onigmo = engine{
	noMatch:        `(?!)`,
	anyChar:        `[\x{0}-\x{10ffff}]`,
	beginLine:      `^`,
	endLine:        `$`,
	wordBoundary:   `(?:(?<=` + asciiWord + `)(?!` + asciiWord + `)|(?<!` + asciiWord + `)(?=` + asciiWord + `))`,
	noWordBoundary: `(?:(?<=` + asciiWord + `)(?=` + asciiWord + `)|(?<!` + asciiWord + `)(?!` + asciiWord + `))`,
	literal:        onigLiteral,
}

func onigLiteral(b *strings.Builder, re *syntax.Regexp) {
	b.WriteString("(?:")
	for _, r := range re.Rune {
		if re.Flags&syntax.FoldCase != 0 && foldOrbit(b, r) {
			continue
		}
		onigLit(b, r)
	}
	b.WriteString(")")
}

// foldOrbit writes r's simple case-fold orbit as a class, and reports false when r folds to nothing
// else.
func foldOrbit(b *strings.Builder, r rune) bool {
	orbit := []rune{r}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		orbit = append(orbit, f)
	}
	if len(orbit) == 1 {
		return false
	}
	b.WriteString("[")
	for _, o := range orbit {
		fmt.Fprintf(b, `\x{%x}`, o)
	}
	b.WriteString("]")
	return true
}

// onigLit prints a literal rune. Unlike Rust output, a space is escaped too: Fluent Bit splits filter
// arguments such as "Key_value_matches KEY REGEX" on whitespace.
func onigLit(b *strings.Builder, r rune) {
	if r == ' ' {
		b.WriteString(`\x{20}`)
		return
	}
	lit(b, r)
}
