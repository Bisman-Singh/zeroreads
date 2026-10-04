package app

import (
	"strconv"
	"strings"
	"unicode"
)

// Text from logs, stored queries and the systems zeroreads reads is untrusted. A query can hold a
// newline and then a GitHub workflow command, terminal escape sequences, or Markdown and HTML that
// would rewrite a report around it. Every such value is written through Printable or Code.

// Printable is s with every character that is not printable escaped as Go does, so the text stays on
// its own line and cannot drive a terminal or start a workflow command.
func Printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
			continue
		}
		q := strconv.QuoteRune(r)
		b.WriteString(q[1 : len(q)-1])
	}
	return b.String()
}

// Code is s as a Markdown code span that nothing in s can end: the fence is one backtick longer than
// the longest run of backticks in s, and s is padded with a space when it starts or ends with one.
func Code(s string) string {
	if s == "" {
		return "` `"
	}
	s = Printable(s)
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	fence := strings.Repeat("`", longest+1)
	return fence + s + fence
}
