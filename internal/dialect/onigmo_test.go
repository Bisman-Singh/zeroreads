package dialect

import (
	"strings"
	"testing"

	"github.com/Bisman-Singh/zeroreads/internal/automaton"
)

// Where the Onigmo form is also Go syntax (no lookarounds), it must mean the same under Go: a guard
// against printer bugs independent of Onigmo itself, which the docker tests check.
func TestOnigmoPrintKeepsGoMeaning(t *testing.T) {
	for _, expr := range []string{
		`\AINFO GET /healthz 200 [0-9]{1,3}ms\z`,
		`\Asays "hi" \\ bye 'q'\z`,
		`^a.b$`,
		`(?s)a.b`,
		`\A[^ ]{2,5}\z`,
		`(?i)kelvin ſtate`,
		`a*?b+?c??d{2,}?`,
		`(?:x|y|)z`,
		`\A(?:hit|miss) key [0-9a-f]{8}\z`,
	} {
		out, err := Onigmo(expr)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, " ") {
			t.Fatalf("%s printed as %q keeps a literal space; Fluent Bit splits arguments on it", expr, out)
		}
		a, b := automaton.MustCompile(expr), automaton.MustCompile(out)
		ab, w1, err1 := automaton.Subset(a, b, 0)
		ba, w2, err2 := automaton.Subset(b, a, 0)
		if err1 != nil || err2 != nil || !ab || !ba {
			t.Fatalf("%s printed as %s changes meaning (%q / %q)", expr, out, w1, w2)
		}
	}
}

func TestOnigmoShapes(t *testing.T) {
	for expr, want := range map[string]string{
		`^a$`:     `\A`,       // Ruby's ^ is a line anchor: Go's text anchor becomes \A
		`a$`:      `\z`,       // and $ becomes \z
		`\bx\b`:   `(?<!`,     // word boundaries become ASCII lookarounds
		`(?i)k`:   `\x{212a}`, // the Kelvin sign is in k's fold orbit
		`[^\s]`:   `[`,
		`(?m)^a$`: `^(?:a)$`, // in (?m) Go and Ruby line anchors agree
	} {
		out, err := Onigmo(expr)
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		if !strings.Contains(out, want) {
			t.Fatalf("%s printed as %s, want it to contain %s", expr, out, want)
		}
	}
	if _, err := Onigmo(`(`); err == nil {
		t.Fatal("a bad pattern must fail")
	}
	if _, err := Rust(`(`); err == nil {
		t.Fatal("a bad pattern must fail")
	}
}
