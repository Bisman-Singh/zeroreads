// Package dialect rewrites a Go RE2 pattern for other regex engines so that it means exactly the
// same thing there. Every construct is printed in its most explicit form: character classes as
// code-point ranges, word boundaries as ASCII-only, literals as escapes when not alphanumeric.
package dialect

import (
	"fmt"
	"regexp/syntax"
	"strings"
)

// Rust prints expr for the Rust regex crate (Vector's VRL). Rust's \d \w \s \b are Unicode-aware
// where Go's are ASCII-only; Go's parser has already expanded Perl classes into explicit ranges, so
// printing ranges keeps Go's meaning. Word boundaries are printed as (?-u:\b), Rust's ASCII-only
// boundary.
func Rust(expr string) (string, error) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := printRust(&b, re.Simplify()); err != nil {
		return "", err
	}
	return b.String(), nil
}

func lit(b *strings.Builder, r rune) {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ':
		b.WriteRune(r)
	default:
		fmt.Fprintf(b, `\x{%x}`, r)
	}
}

func printRust(b *strings.Builder, re *syntax.Regexp) error {
	switch re.Op {
	case syntax.OpNoMatch:
		b.WriteString(`[^\x{0}-\x{10ffff}]`)
	case syntax.OpEmptyMatch:
		b.WriteString(`(?:)`)
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			b.WriteString("(?i:")
		} else {
			b.WriteString("(?:")
		}
		for _, r := range re.Rune {
			lit(b, r)
		}
		b.WriteString(")")
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			b.WriteString(`[^\x{0}-\x{10ffff}]`)
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
		b.WriteString(`(?s:.)`)
	case syntax.OpBeginLine:
		b.WriteString(`(?m:^)`)
	case syntax.OpEndLine:
		b.WriteString(`(?m:$)`)
	case syntax.OpBeginText:
		b.WriteString(`\A`)
	case syntax.OpEndText:
		b.WriteString(`\z`)
	case syntax.OpWordBoundary:
		b.WriteString(`(?-u:\b)`)
	case syntax.OpNoWordBoundary:
		b.WriteString(`(?-u:\B)`)
	case syntax.OpCapture:
		b.WriteString("(?:")
		if err := printRust(b, re.Sub[0]); err != nil {
			return err
		}
		b.WriteString(")")
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		b.WriteString("(?:")
		if err := printRust(b, re.Sub[0]); err != nil {
			return err
		}
		b.WriteString(")")
		b.WriteString(map[syntax.Op]string{syntax.OpStar: "*", syntax.OpPlus: "+", syntax.OpQuest: "?"}[re.Op])
		if re.Flags&syntax.NonGreedy != 0 {
			b.WriteString("?")
		}
	case syntax.OpRepeat:
		b.WriteString("(?:")
		if err := printRust(b, re.Sub[0]); err != nil {
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
			if err := printRust(b, s); err != nil {
				return err
			}
		}
	case syntax.OpAlternate:
		b.WriteString("(?:")
		for i, s := range re.Sub {
			if i > 0 {
				b.WriteString("|")
			}
			if err := printRust(b, s); err != nil {
				return err
			}
		}
		b.WriteString(")")
	default:
		return fmt.Errorf("dialect: unsupported op %v", re.Op)
	}
	return nil
}
