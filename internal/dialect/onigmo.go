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
func Onigmo(expr string) (string, error) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := printOnigmo(&b, re.Simplify()); err != nil {
		return "", err
	}
	return b.String(), nil
}

func printOnigmo(b *strings.Builder, re *syntax.Regexp) error {
	sub := func(r *syntax.Regexp) error { return printOnigmo(b, r) }
	switch re.Op {
	case syntax.OpNoMatch:
		b.WriteString(`(?!)`)
	case syntax.OpEmptyMatch:
		b.WriteString(`(?:)`)
	case syntax.OpLiteral:
		b.WriteString("(?:")
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				orbit := []rune{r}
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					orbit = append(orbit, f)
				}
				if len(orbit) > 1 {
					b.WriteString("[")
					for _, o := range orbit {
						fmt.Fprintf(b, `\x{%x}`, o)
					}
					b.WriteString("]")
					continue
				}
			}
			lit(b, r)
		}
		b.WriteString(")")
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			b.WriteString(`(?!)`)
			return nil
		}
		b.WriteString("[")
		for i := 0; i+1 < len(re.Rune); i += 2 {
			fmt.Fprintf(b, `\x{%x}-\x{%x}`, re.Rune[i], re.Rune[i+1])
		}
		b.WriteString("]")
	case syntax.OpAnyCharNotNL:
		b.WriteString(`[^\n]`)
	case syntax.OpAnyChar:
		b.WriteString(`[\x{0}-\x{10ffff}]`)
	case syntax.OpBeginLine:
		b.WriteString(`^`)
	case syntax.OpEndLine:
		b.WriteString(`$`)
	case syntax.OpBeginText:
		b.WriteString(`\A`)
	case syntax.OpEndText:
		b.WriteString(`\z`)
	case syntax.OpWordBoundary:
		b.WriteString(`(?:(?<=` + asciiWord + `)(?!` + asciiWord + `)|(?<!` + asciiWord + `)(?=` + asciiWord + `))`)
	case syntax.OpNoWordBoundary:
		b.WriteString(`(?:(?<=` + asciiWord + `)(?=` + asciiWord + `)|(?<!` + asciiWord + `)(?!` + asciiWord + `))`)
	case syntax.OpCapture:
		b.WriteString("(?:")
		if err := sub(re.Sub[0]); err != nil {
			return err
		}
		b.WriteString(")")
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		b.WriteString("(?:")
		if err := sub(re.Sub[0]); err != nil {
			return err
		}
		b.WriteString(")")
		b.WriteString(map[syntax.Op]string{syntax.OpStar: "*", syntax.OpPlus: "+", syntax.OpQuest: "?"}[re.Op])
		if re.Flags&syntax.NonGreedy != 0 {
			b.WriteString("?")
		}
	case syntax.OpRepeat:
		b.WriteString("(?:")
		if err := sub(re.Sub[0]); err != nil {
			return err
		}
		b.WriteString(")")
		switch {
		case re.Max == -1:
			fmt.Fprintf(b, "{%d,}", re.Min)
		case re.Min == re.Max:
			fmt.Fprintf(b, "{%d}", re.Min)
		default:
			fmt.Fprintf(b, "{%d,%d}", re.Min, re.Max)
		}
		if re.Flags&syntax.NonGreedy != 0 {
			b.WriteString("?")
		}
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if err := sub(s); err != nil {
				return err
			}
		}
	case syntax.OpAlternate:
		b.WriteString("(?:")
		for i, s := range re.Sub {
			if i > 0 {
				b.WriteString("|")
			}
			if err := sub(s); err != nil {
				return err
			}
		}
		b.WriteString(")")
	default:
		return fmt.Errorf("dialect: unsupported op %v", re.Op)
	}
	return nil
}
