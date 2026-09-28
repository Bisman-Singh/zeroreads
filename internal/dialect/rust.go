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
func Rust(expr string) (string, error) { return rust.translate(expr) }

var rust = engine{
	noMatch:        `[^\x{0}-\x{10ffff}]`,
	anyChar:        `(?s:.)`,
	beginLine:      `(?m:^)`,
	endLine:        `(?m:$)`,
	wordBoundary:   `(?-u:\b)`,
	noWordBoundary: `(?-u:\B)`,
	literal: func(b *strings.Builder, re *syntax.Regexp) {
		if re.Flags&syntax.FoldCase != 0 {
			b.WriteString("(?i:")
		} else {
			b.WriteString("(?:")
		}
		for _, r := range re.Rune {
			lit(b, r)
		}
		b.WriteString(")")
	},
}

func lit(b *strings.Builder, r rune) {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ':
		b.WriteRune(r)
	default:
		fmt.Fprintf(b, `\x{%x}`, r)
	}
}

// engine is how one regex engine writes the constructs whose syntax or meaning differs between
// engines. Everything else (groups, repetition, concatenation, alternation, classes as code-point
// ranges, text anchors) is written the same way for every engine.
type engine struct {
	noMatch        string // matches nothing
	anyChar        string // any character, newline included
	beginLine      string // start of a line
	endLine        string // end of a line
	wordBoundary   string // an ASCII word boundary
	noWordBoundary string // not an ASCII word boundary
	literal        func(b *strings.Builder, re *syntax.Regexp)
}

func (e engine) translate(expr string) (string, error) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := e.print(&b, re.Simplify()); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (e engine) print(b *strings.Builder, re *syntax.Regexp) error {
	switch re.Op {
	case syntax.OpNoMatch:
		b.WriteString(e.noMatch)
	case syntax.OpEmptyMatch:
		b.WriteString(`(?:)`)
	case syntax.OpLiteral:
		e.literal(b, re)
	case syntax.OpCharClass:
		e.class(b, re.Rune)
	case syntax.OpAnyCharNotNL:
		b.WriteString(`[^\n]`)
	case syntax.OpAnyChar:
		b.WriteString(e.anyChar)
	case syntax.OpBeginLine:
		b.WriteString(e.beginLine)
	case syntax.OpEndLine:
		b.WriteString(e.endLine)
	case syntax.OpBeginText:
		b.WriteString(`\A`)
	case syntax.OpEndText:
		b.WriteString(`\z`)
	case syntax.OpWordBoundary:
		b.WriteString(e.wordBoundary)
	case syntax.OpNoWordBoundary:
		b.WriteString(e.noWordBoundary)
	case syntax.OpCapture:
		return e.group(b, re.Sub[0])
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		return e.repeat(b, re)
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if err := e.print(b, s); err != nil {
				return err
			}
		}
	case syntax.OpAlternate:
		b.WriteString("(?:")
		for i, s := range re.Sub {
			if i > 0 {
				b.WriteString("|")
			}
			if err := e.print(b, s); err != nil {
				return err
			}
		}
		b.WriteString(")")
	default:
		return fmt.Errorf("dialect: unsupported op %v", re.Op)
	}
	return nil
}

// class writes a character class as code-point ranges; an empty class matches nothing.
func (e engine) class(b *strings.Builder, ranges []rune) {
	if len(ranges) == 0 {
		b.WriteString(e.noMatch)
		return
	}
	b.WriteString("[")
	for i := 0; i+1 < len(ranges); i += 2 {
		fmt.Fprintf(b, `\x{%x}-\x{%x}`, ranges[i], ranges[i+1])
	}
	b.WriteString("]")
}

// group writes re as a non-capturing group.
func (e engine) group(b *strings.Builder, re *syntax.Regexp) error {
	b.WriteString("(?:")
	if err := e.print(b, re); err != nil {
		return err
	}
	b.WriteString(")")
	return nil
}

// repeat writes *, +, ? and {n,m} with their greediness.
func (e engine) repeat(b *strings.Builder, re *syntax.Regexp) error {
	if err := e.group(b, re.Sub[0]); err != nil {
		return err
	}
	switch {
	case re.Op == syntax.OpStar:
		b.WriteString("*")
	case re.Op == syntax.OpPlus:
		b.WriteString("+")
	case re.Op == syntax.OpQuest:
		b.WriteString("?")
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
	return nil
}
