// Package logql parses LogQL far enough to answer one question safely: which log lines can a query
// read, and does it count them. It is written from the published grammar, not derived from Loki's
// code. Anything it does not understand is reported, and callers treat such a query as reading every
// line of every stream and counting them.
package logql

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tString
	tNumber   // plain number
	tDuration // number with a duration unit, e.g. 5m, 1h30m
	tBytes    // number with a size unit, e.g. 10KB
	tRange    // [5m], the text between brackets
	tOp       // punctuation and operators
	tFlag     // --strict, --keep-empty
)

type token struct {
	kind tokKind
	text string // raw text; for strings the unquoted value
	pos  int
	end  int // byte offset just past the token in the source
}

func (t token) String() string { return fmt.Sprintf("%q@%d", t.text, t.pos) }

// ops are matched longest first.
var ops = []string{"|=", "|~", "|>", "!=", "!~", "!>", "=~", "==", ">=", "<=", "|", "=", ">", "<",
	"(", ")", "{", "}", ",", "+", "-", "*", "/", "%", "^"}

func lex(src string) ([]token, error) {
	if !utf8.ValidString(src) {
		return nil, fmt.Errorf("query is not valid UTF-8")
	}
	var out []token
	i := 0
	for i < len(src) {
		r, w := utf8.DecodeRuneInString(src[i:])
		switch {
		case r == utf8.RuneError && w == 1:
			return nil, fmt.Errorf("invalid UTF-8 at %d", i)
		case unicode.IsSpace(r):
			i += w
		case r == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case r == '"' || r == '`' || r == '\'':
			s, n, err := lexString(src[i:])
			if err != nil {
				return nil, fmt.Errorf("string at %d: %w", i, err)
			}
			out = append(out, token{kind: tString, text: s, pos: i, end: i + n})
			i += n
		case r == '[':
			end := strings.IndexByte(src[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("missing ] at %d", i)
			}
			out = append(out, token{kind: tRange, text: strings.TrimSpace(src[i+1 : i+end]), pos: i, end: i + end + 1})
			i += end + 1
		case r == '-' && strings.HasPrefix(src[i:], "--"):
			j := i + 2
			for j < len(src) && (isLetter(src[j]) || src[j] == '-') {
				j++
			}
			flag := src[i:j]
			if flag != "--strict" && flag != "--keep-empty" {
				return nil, fmt.Errorf("unknown flag %q at %d", flag, i)
			}
			out = append(out, token{kind: tFlag, text: flag, pos: i, end: j})
			i = j
		case r >= '0' && r <= '9' || (r == '.' && i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '9'):
			tok, n := lexNumber(src[i:])
			tok.pos, tok.end = i, i+n
			out = append(out, tok)
			i += n
		case r < utf8.RuneSelf && isLetter(byte(r)) || r == '_':
			j := i
			for j < len(src) && (isLetter(src[j]) || isDigit(src[j]) || src[j] == '_') {
				j++
			}
			out = append(out, token{kind: tIdent, text: src[i:j], pos: i, end: j})
			i = j
		default:
			matched := false
			for _, op := range ops {
				if strings.HasPrefix(src[i:], op) {
					out = append(out, token{kind: tOp, text: op, pos: i, end: i + len(op)})
					i += len(op)
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("unexpected %q at %d", r, i)
			}
		}
	}
	return append(out, token{kind: tEOF, pos: len(src), end: len(src)}), nil
}

func isLetter(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }
func isDigit(b byte) bool  { return b >= '0' && b <= '9' }

// lexString reads a quoted string and returns its value and length. Double and single quotes use Go
// escapes; backticks are raw.
func lexString(src string) (string, int, error) {
	q := src[0]
	if q == '`' {
		end := strings.IndexByte(src[1:], '`')
		if end < 0 {
			return "", 0, fmt.Errorf("unterminated raw string")
		}
		return src[1 : end+1], end + 2, nil
	}
	i := 1
	for i < len(src) {
		switch src[i] {
		case '\\':
			i += 2
			continue
		case q:
			lit := src[:i+1]
			if q == '\'' {
				// Go only allows single-rune '...' literals; LogQL accepts strings. Re-quote as "...".
				lit = `"` + strings.ReplaceAll(src[1:i], `"`, `\"`) + `"`
			}
			v, err := strconv.Unquote(lit)
			if err != nil {
				return "", 0, err
			}
			if !utf8.ValidString(v) {
				return "", 0, fmt.Errorf("string is not valid UTF-8")
			}
			return v, i + 1, nil
		case '\n':
			return "", 0, fmt.Errorf("newline in string")
		}
		i++
	}
	return "", 0, fmt.Errorf("unterminated string")
}

// durationUnits and byteUnits are the suffixes that turn a number into a duration or a size.
var durationUnits = "nsuµmhdwy"
var byteUnits = "BikKMGTPE"

func lexNumber(src string) (token, int) {
	i := 0
	for i < len(src) && (isDigit(src[i]) || src[i] == '.' || src[i] == 'e' || src[i] == 'E' ||
		((src[i] == '+' || src[i] == '-') && i > 0 && (src[i-1] == 'e' || src[i-1] == 'E'))) {
		// Stop at 'e' that starts a unit-less identifier? LogQL numbers never do; accept exponent.
		i++
	}
	// A unit run: durations like 1h30m5s, sizes like 10KB or 1.5MiB.
	j := i
	for j < len(src) && (isDigit(src[j]) || src[j] == '.' || strings.ContainsRune(durationUnits+byteUnits, rune(src[j])) ||
		strings.HasPrefix(src[j:], "µ")) {
		if strings.HasPrefix(src[j:], "µ") {
			j += len("µ")
			continue
		}
		j++
	}
	if j == i {
		return token{kind: tNumber, text: src[:i]}, i
	}
	text := src[:j]
	if isDuration(text) {
		return token{kind: tDuration, text: text}, j
	}
	if isBytes(text) {
		return token{kind: tBytes, text: text}, j
	}
	return token{kind: tNumber, text: src[:i]}, i
}

func isDuration(s string) bool {
	// Prometheus durations: one or more <int><unit> with units y w d h m s ms; Go durations add
	// ns us µs and fractions.
	units := []string{"ms", "ns", "us", "µs", "y", "w", "d", "h", "m", "s"}
	rest := s
	if rest == "" {
		return false
	}
	for rest != "" {
		k := 0
		for k < len(rest) && (isDigit(rest[k]) || rest[k] == '.') {
			k++
		}
		if k == 0 {
			return false
		}
		rest = rest[k:]
		found := false
		for _, u := range units {
			if strings.HasPrefix(rest, u) {
				rest = rest[len(u):]
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func isBytes(s string) bool {
	k := 0
	for k < len(s) && (isDigit(s[k]) || s[k] == '.') {
		k++
	}
	if k == 0 {
		return false
	}
	unit := strings.ToUpper(s[k:])
	switch unit {
	case "B", "KB", "KIB", "MB", "MIB", "GB", "GIB", "TB", "TIB", "PB", "PIB", "EB", "EIB", "K", "M", "G", "T", "P", "E", "KI", "MI", "GI", "TI", "PI", "EI":
		return true
	}
	return false
}
