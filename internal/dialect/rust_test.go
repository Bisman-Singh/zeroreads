package dialect

import (
	"regexp"
	"testing"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
)

// The printed pattern must mean the same as the original under Go itself: a guard against printer
// bugs, independent of any other engine.
func TestRustPrintKeepsGoMeaning(t *testing.T) {
	for _, expr := range []string{
		`\AINFO GET /healthz 200 [0-9]{1,3}ms\z`,
		`\AWARN retrying connection to (?:\b(?:\d{1,3}\.){3}\d{1,3}\b) attempt (?:1|2|3|4|5)\z`,
		`\Asays "hi" \\ bye 'q'\z`,
		`(?i)kelvin\s+\w+\b`,
		`\A[^ ]{2,5}\z`,
		`^a.b$`,
		`(?s)a.b`,
		`\Bx`,
		`a*?b+?c??d{2,}?`,
	} {
		out, err := Rust(expr)
		if err != nil {
			t.Fatal(err)
		}
		// Go can parse the printed form (Rust's (?-u:...) is not Go syntax, so compare only where
		// it is absent).
		if regexp.MustCompile(`\(\?-u`).MatchString(out) {
			continue
		}
		a, b := automaton.MustCompile(expr), automaton.MustCompile(out)
		ab, w1, err1 := automaton.Subset(a, b, 0)
		ba, w2, err2 := automaton.Subset(b, a, 0)
		if err1 != nil || err2 != nil || !ab || !ba {
			t.Fatalf("%s printed as %s changes meaning (%q / %q)", expr, out, w1, w2)
		}
	}
}
