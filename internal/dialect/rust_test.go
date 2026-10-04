package dialect

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Bisman-Singh/zeroreads/internal/automaton"
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
		`\AGET /api/[a-z]{4,94}/ 200\z`,
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

// A bounded repeat stays one repeat in every engine: expanded into nested optional groups, a bound past
// about 85 went beyond Rust's limit of 250 nested groups and Vector refused the whole configuration.
func TestBoundedRepeatsStayFlat(t *testing.T) {
	for name, translate := range map[string]func(string) (string, error){"rust": Rust, "onigmo": Onigmo} {
		out, err := translate(`\AGET /api/[a-z]{4,264}/ 200\z`)
		if err != nil {
			t.Fatal(err)
		}
		depth, deepest := 0, 0
		for i, r := range out {
			if r == '(' && (i == 0 || out[i-1] != '\\') {
				depth++
				deepest = max(deepest, depth)
			} else if r == ')' && out[i-1] != '\\' {
				depth--
			}
		}
		if deepest > 2 || !strings.Contains(out, "{4,264}") {
			t.Fatalf("%s: nesting %d in %s", name, deepest, out)
		}
	}
}
