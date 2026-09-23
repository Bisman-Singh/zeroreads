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

const fluentBitImage = "fluent/fluent-bit:5.1.2"

// fbMatch returns, for each input, whether Fluent Bit's grep filter keeps it for the pattern.
func fbMatch(t *testing.T, pattern string, inputs []string) []bool {
	t.Helper()
	dir := t.TempDir()
	cfg := "service:\n  flush: 1\n  log_level: error\npipeline:\n  inputs:\n    - name: stdin\n      tag: t\n  filters:\n    - name: grep\n      match: t\n      regex: s ${PAT}\n  outputs:\n    - name: stdout\n      match: t\n      format: json_lines\n"
	os.WriteFile(filepath.Join(dir, "fb.yaml"), []byte(cfg), 0o644)
	var in strings.Builder
	for i, s := range inputs {
		b, _ := json.Marshal(map[string]any{"s": s, "i": i})
		in.Write(b)
		in.WriteByte('\n')
	}
	cmd := exec.Command("docker", "run", "-i", "--rm", "-e", "PAT="+pattern, "-v", dir+":/w", fluentBitImage, "-c", "/w/fb.yaml")
	cmd.Stdin = strings.NewReader(in.String())
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("fluent-bit: %v\n%s", err, stderr.String())
	}
	kept := make([]bool, len(inputs))
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l == "" {
			continue
		}
		var rec struct {
			I int `json:"i"`
		}
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("output %q: %v", l, err)
		}
		kept[rec.I] = true
	}
	return kept
}

func TestOnigmoDialectAgreesWithFluentBit(t *testing.T) {
	exprs := []string{
		`\AINFO GET /healthz 200 [0-9]{1,3}ms\z`,
		`\AWARN retrying connection to (?:\b(?:\d{1,3}\.){3}\d{1,3}\b) attempt (?:1|2|3|4|5)\z`,
		`\Asays "hi" \\ bye 'q' $1 #x\z`,
		`(?i)kelvin`,
		`(?i)\Astrasse\z`,
		`\A\w+\s\d+\z`,
		`\bword\b`,
		`^a.b$`,
		`(?m)^a$`,
		`\A(?:[^ ]{1,4})\z`,
	}
	traps := append(append([]string(nil), unicodeTraps...), "straße", "STRASSE", "ſtrasse", "a\nb", "x\na\ny")
	for i, expr := range exprs {
		pat, err := Onigmo(expr)
		if err != nil {
			t.Fatal(err)
		}
		members, err := automaton.Members(expr, 40, uint64(i)+1)
		if err != nil {
			t.Fatal(err)
		}
		cases := append(append(members, automaton.Near(members, 4, uint64(i)+3)...), traps...)
		got := fbMatch(t, pat, cases)
		re := regexp.MustCompile(expr)
		for j, s := range cases {
			if want := re.MatchString(s); got[j] != want {
				t.Fatalf("%s (printed %s) on %q: fluent-bit %v, go %v", expr, pat, s, got[j], want)
			}
		}
		t.Logf("%s: %d strings agree", expr, len(cases))
	}
}

// Ruby's ^ and $ really are line anchors in Fluent Bit: why text anchors must be printed as \A \z.
func TestRubyAnchorsDifferInFluentBit(t *testing.T) {
	got := fbMatch(t, `^ab$`, []string{"x\nab"})
	if !got[0] {
		t.Fatal("expected Ruby ^ab$ to match across a newline")
	}
	if regexp.MustCompile(`^ab$`).MatchString("x\nab") {
		t.Fatal("Go ^ab$ must not match")
	}
}
