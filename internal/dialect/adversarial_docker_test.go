//go:build docker

package dialect

// Adversarial regex checks contributed by an external audit: each pattern, printed for Vector, must
// agree with Go on every input under real VRL; and the same harness must see disagreements when
// patterns are not translated, so it can detect a dialect difference at all.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
)

func vrlAll(t *testing.T, pattern string, inputs []string) []bool {
	t.Helper()
	dir := t.TempDir()
	var in strings.Builder
	for _, s := range inputs {
		b, _ := json.Marshal(map[string]string{"s": s})
		in.Write(b)
		in.WriteByte('\n')
	}
	os.WriteFile(filepath.Join(dir, "in.jsonl"), []byte(in.String()), 0o644)
	os.WriteFile(filepath.Join(dir, "p.vrl"), []byte("match(string!(.s), r'"+pattern+"')\n"), 0o644)
	out, err := exec.Command("docker", "run", "--rm", "-v", dir+":/w", "timberio/vector:0.58.0-debian", "vrl", "-i", "/w/in.jsonl", "-p", "/w/p.vrl").Output()
	if err != nil {
		t.Fatalf("vrl %s: %v %s", pattern, err, out)
	}
	var res []bool
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		res = append(res, strings.TrimSpace(l) == "true")
	}
	if len(res) != len(inputs) {
		t.Fatalf("vrl: %d results for %d inputs", len(res), len(inputs))
	}
	return res
}

var auditPatterns = []string{
	`\s+x`, `\S{2}`, `\w+`, `\W`, `\d{2}`, `\D`, `[\d]`, `[^\d]`, `[^\s]+`, `\bab\b`, `\Bb`, `[[:alpha:]]+`, `[[:space:]]`,
	`[[:^digit:]]`, `[[:word:]]`, `[[:punct:]]`, `[[:upper:]]`, `\pL+`, `\PL`, `\p{Greek}`, `(?i)kelvin`, `(?i)s`, `(?i)ß`, `(?i)[a-z]+`,
	`(?i)σ`, `(?s)a.b`, `a.b`, `(?m)^b`, `(?m)a$`, `a$`, `\Aa`, `b\z`, `\Qa.b\E`, `[^a]`, `[α-ω]`, `x{2,3}`, `(?U)a+`, `\x{212A}`,
	`[\x{10000}-\x{10FFFF}]`, `\v`, `\f`, `\t+`, `a|`, `(?:)`, `[\p{Lu}\d]`, `(?i)[k]`, `[^\x00-\x7f]`, `\x41`, `[\w-]+`, `\.`, `[.]`,
	`a\z`, `(?i)İ`, `(?i)ı`, `[[:blank:]]`, `\A\z`, `(?s).`, `.`, `[^\n]`, `\r?\n`, `(?i)ǅ`, `\b`, `^`, `$`,
}

func TestAdversarialRegexesAgreeWithVector(t *testing.T) {
	base := []string{"", "a", "ab", "a b", "a\nb", "a\r\nb", "x x", "  x", "kelvin", "KELVIN", "Kelvin", "ſ", "s", "S", "ß", "ẞ", "SS",
		"σ", "Σ", "ς", "é", "é", "١٢", "１２", "12", "a.b", "a-b_c", "İ", "ı", "i", "I", "ǅ", "Ǆ", "ǆ", "\t\t", "\v", "\f",
		" x", " x", "　", "😀", "\U0001F600a", "αβγ", "Ωmega", "A", "\x7f", "\u0085", " ", "_", "b", "ba", "aaa", "aa"}
	cases := append(append([]string(nil), base...), automaton.Near(base, 3, 11)...)
	disagree, total, refused := 0, 0, 0
	for _, expr := range auditPatterns {
		pat, err := Rust(expr)
		if err != nil {
			refused++
			t.Logf("dialect refuses %q (no rule would use it): %v", expr, err)
			continue
		}
		re := regexp.MustCompile(expr)
		got := vrlAll(t, pat, cases)
		for j, s := range cases {
			total++
			if want := re.MatchString(s); got[j] != want {
				disagree++
				t.Errorf("%q printed as %q on %q: vector %v, go %v", expr, pat, s, got[j], want)
				break
			}
		}
	}
	t.Logf("patterns=%d refused=%d checks=%d disagreements=%d", len(auditPatterns), refused, total, disagree)
}

// Negative control: untranslated patterns must disagree somewhere, or the harness proves nothing.
func TestUntranslatedPatternsDisagreeWithVector(t *testing.T) {
	cases := []string{"١٢", "é", " x", "ſ", "Kelvin", "a b", "ab"}
	n := 0
	for _, expr := range []string{`\d{2}`, `\w+`, `\s+x`, `(?i)s`, `\bab\b`, `[[:alpha:]]+`, `\S{2}`} {
		got := vrlAll(t, expr, cases)
		re := regexp.MustCompile(expr)
		for j, s := range cases {
			if got[j] != re.MatchString(s) {
				n++
			}
		}
	}
	if n == 0 {
		t.Fatal("the harness cannot detect dialect differences")
	}
	t.Logf("untranslated disagreements=%d", n)
}
