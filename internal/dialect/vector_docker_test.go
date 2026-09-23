//go:build docker

package dialect

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

const vectorImage = "timberio/vector:0.58.0-debian"

// vrlMatch evaluates match(s, pattern) in the real Vector VRL for every input.
func vrlMatch(t *testing.T, pattern string, inputs []string) []bool {
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
	cmd := exec.Command("docker", "run", "--rm", "-v", dir+":/w", vectorImage, "vrl", "-i", "/w/in.jsonl", "-p", "/w/p.vrl")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("vrl: %v\n%s\n%s", err, out, stderr.String())
	}
	var res []bool
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch strings.TrimSpace(l) {
		case "true":
			res = append(res, true)
		case "false":
			res = append(res, false)
		default:
			t.Fatalf("unexpected vrl output line %q\n%s", l, out)
		}
	}
	if len(res) != len(inputs) {
		t.Fatalf("vrl returned %d results for %d inputs", len(res), len(inputs))
	}
	return res
}

var unicodeTraps = []string{"١٢٣", "１２３", "a b", "a b", "K", "ſ", "é", "x́", "٣.٣.٣.٣", "10.0.0.1\n", "a\r\nb"}

func TestRustDialectAgreesWithVector(t *testing.T) {
	exprs := []string{
		`\AINFO GET /healthz 200 [0-9]{1,3}ms\z`,
		`\AWARN retrying connection to (?:\b(?:\d{1,3}\.){3}\d{1,3}\b) attempt (?:1|2|3|4|5)\z`,
		`\Asays "hi" \\ bye 'q'\z`,
		`(?i)kelvin`,
		`\A\w+\s\d+\z`,
		`\bword\b`,
		`^a.b$`,
		`\A(?:[^ ]{1,4})\z`,
	}
	for i, expr := range exprs {
		pat, err := Rust(expr)
		if err != nil {
			t.Fatal(err)
		}
		members, err := automaton.Members(expr, 40, uint64(i)+1)
		if err != nil {
			t.Fatal(err)
		}
		cases := append(append(members, automaton.Near(members, 4, uint64(i)+3)...), unicodeTraps...)
		for _, m := range members {
			for _, trap := range []string{"١", "１", " ", "K"} {
				cases = append(cases, strings.Replace(m, "1", trap, 1), strings.Replace(m, " ", trap, 1), strings.Replace(m, "k", trap, 1))
			}
		}
		got := vrlMatch(t, pat, cases)
		re := regexp.MustCompile(expr)
		for j, s := range cases {
			if want := re.MatchString(s); got[j] != want {
				t.Fatalf("%s (printed %s) on %q: vector %v, go %v", expr, pat, s, got[j], want)
			}
		}
		t.Logf("%s: %d strings agree", expr, len(cases))
	}
}

// The untranslated pattern really differs in Vector: this is why translation exists. Pinned so a
// change in the Rust crate's defaults is noticed.
func TestUntranslatedDigitsDifferInVector(t *testing.T) {
	got := vrlMatch(t, `\A\d+\z`, []string{"١٢٣"})
	if !got[0] {
		t.Fatal(`expected Rust's Unicode \d to match Arabic-Indic digits`)
	}
	if regexp.MustCompile(`\A\d+\z`).MatchString("١٢٣") {
		t.Fatal(`Go's \d must not match Arabic-Indic digits`)
	}
}
