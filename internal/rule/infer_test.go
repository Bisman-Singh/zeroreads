package rule

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
	"github.com/Bisman-Singh/sievelog/internal/gen"
	"github.com/Bisman-Singh/sievelog/internal/templating"
)

var corpusMasks = []Mask{{Name: gen.IPMaskName, Pattern: gen.IPMaskPattern}}

// corpusLanguages templates a corpus run with the real drain processor and infers a language per
// (service, template) from the templated text of its lines.
func corpusLanguages(t *testing.T, seed uint64, n int) (map[string]Language, map[string][]string) {
	t.Helper()
	ctx := context.Background()
	recs, _, err := gen.Run(seed, n)
	if err != nil {
		t.Fatal(err)
	}
	cfg := templating.DefaultConfig()
	cfg.BodyField = "msg"
	cfg.MaskingRules = []templating.MaskRule{{Name: gen.IPMaskName, Pattern: gen.IPMaskPattern}}
	cfg.SeedTemplates = gen.SeedTemplates()
	e, err := templating.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)
	isJSON := map[string]bool{}
	for _, s := range gen.Corpus() {
		isJSON[s.Name] = s.JSON
	}
	in := make([]templating.Input, len(recs))
	for i, r := range recs {
		if isJSON[r.Service] {
			var m map[string]any
			if err := json.Unmarshal([]byte(r.Line), &m); err != nil {
				t.Fatal(err)
			}
			in[i] = templating.Input{Fields: m}
			continue
		}
		in[i] = templating.Input{Body: r.Line}
	}
	tmpl, err := e.Template(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	texts := map[string][]string{} // service|template -> templated texts
	for i, r := range recs {
		k := r.Service + "|" + tmpl[i]
		texts[k] = append(texts[k], r.Message)
	}
	langs := map[string]Language{}
	for k, s := range texts {
		tpl := strings.SplitN(k, "|", 2)[1]
		l, err := Infer(tpl, corpusMasks, s, DefaultOptions())
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		langs[k] = l
	}
	return langs, texts
}

func TestCorpusLanguagesCoverEveryLine(t *testing.T) {
	langs, texts := corpusLanguages(t, 11, 3000)
	for k, l := range langs {
		re := regexp.MustCompile(l.Regex)
		for _, s := range texts[k] {
			if !re.MatchString(s) {
				t.Fatalf("%s: %q not covered by %s", k, s, l.Regex)
			}
		}
		if l.Skipped != 0 {
			t.Fatalf("%s: %d lines skipped", k, l.Skipped)
		}
	}
}

// No two rules in the same service may overlap: a line removed by one is never claimed by another.
func TestCorpusLanguagesDisjoint(t *testing.T) {
	langs, _ := corpusLanguages(t, 11, 3000)
	var keys []string
	for k := range langs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, a := range keys {
		for _, b := range keys[i+1:] {
			if strings.SplitN(a, "|", 2)[0] != strings.SplitN(b, "|", 2)[0] {
				continue
			}
			w, found, err := automaton.Intersects(automaton.MustCompile(langs[a].Regex), automaton.MustCompile(langs[b].Regex), 0)
			if err != nil {
				t.Fatal(err)
			}
			if found {
				t.Fatalf("%s and %s overlap on %q", a, b, w)
			}
		}
	}
}

func TestCorpusGolden(t *testing.T) {
	langs, _ := corpusLanguages(t, 11, 3000)
	want := map[string]string{
		"checkout|INFO GET /healthz 200 <*>":                    `\AINFO GET /healthz 200 [0-9]{1,3}ms\z`,
		"checkout|INFO heartbeat ok":                            `\AINFO heartbeat ok\z`,
		"checkout|INFO request <*> status <*> took <*>":         `\AINFO request [0-9a-f]{16} status (?:200|201|404|503) took [0-9]{1,3}ms\z`,
		"checkout|WARN retrying connection to <ip> attempt <*>": `\AWARN retrying connection to (?:` + gen.IPMaskPattern + `) attempt (?:1|2|3|4|5)\z`,
		"checkout|ERROR payment <*> declined code <*>":          `\AERROR payment pay_[0-9]{6} declined code (?:card_expired|do_not_honor|insufficient_funds)\z`,
		"auth|INFO user <*> logged in":                          `\AINFO user (?:alice|bob|carol|dave|erin|frank) logged in\z`,
		"auth|INFO config placeholder <ip> unresolved for <*>":  `\AINFO config placeholder <ip> unresolved for (?:alice|bob|carol|dave|erin|frank)\z`,
		"orders|handled route in <*>":                           `\Ahandled route in [0-9]{1,3}ms\z`,
	}
	for k, w := range want {
		l, ok := langs[k]
		if !ok {
			t.Fatalf("no language for %s", k)
		}
		if l.Regex != w {
			t.Fatalf("%s:\n got %s\nwant %s", k, l.Regex, w)
		}
	}
}

// The traps the audits named, decided exactly.
func TestAuditTraps(t *testing.T) {
	langs, _ := corpusLanguages(t, 11, 3000)
	req := automaton.MustCompile(langs["checkout|INFO request <*> status <*> took <*>"].Regex)
	login := automaton.MustCompile(langs["auth|INFO user <*> logged in"].Regex)
	health := automaton.MustCompile(langs["checkout|INFO GET /healthz 200 <*>"].Regex)
	cases := []struct {
		name string
		a, b *automaton.Pattern
		want bool
	}{
		{"status 503 alert reads request lines", req, automaton.Literal("status 503"), true},
		{"status=503 cannot occur in request lines", req, automaton.Literal("status=503"), false},
		{"wide-matcher line is not a login line", login, automaton.Literal("INFO user admin failed MFA and was logged in"), false},
		{"heartbeat filter cannot select health lines", health, automaton.Literal("heartbeat"), false},
		{"healthz filter selects health lines", health, automaton.Literal("healthz"), true},
	}
	for _, c := range cases {
		_, found, err := automaton.Intersects(c.a, c.b, 0)
		if err != nil {
			t.Fatal(err)
		}
		if found != c.want {
			t.Fatalf("%s: got %v want %v", c.name, found, c.want)
		}
	}
}

func TestTooFewSamples(t *testing.T) {
	_, err := Infer("a <*>", nil, []string{"a 1", "a 2"}, DefaultOptions())
	if err == nil || !strings.Contains(err.Error(), "too few") {
		t.Fatalf("got %v", err)
	}
}

func TestMisalignedSamplesAreSkippedNotCovered(t *testing.T) {
	var s []string
	for i := 0; i < 30; i++ {
		s = append(s, "user alice logged in")
	}
	s = append(s, "user  alice logged in", " user alice logged in")
	l, err := Infer("user <*> logged in", nil, s, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if l.Skipped != 2 {
		t.Fatalf("skipped %d, want 2", l.Skipped)
	}
	re := regexp.MustCompile(l.Regex)
	if re.MatchString("user  alice logged in") || re.MatchString(" user alice logged in") {
		t.Fatal("misaligned lines must not be covered")
	}
}

func TestLongValuesStayValid(t *testing.T) {
	var s []string
	for i := 0; i < 25; i++ {
		s = append(s, "blob "+strings.Repeat("x", 1200+i))
	}
	l, err := Infer("blob <*>", nil, s, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(l.Regex, "[a-z]+") {
		t.Fatalf("got %s", l.Regex)
	}
}

func TestShapes(t *testing.T) {
	gen := func(f func(i int) string) []string {
		var out []string
		for i := 0; i < 40; i++ {
			out = append(out, f(i))
		}
		return out
	}
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{"hex ids", gen(func(i int) string {
			return []string{"0f2c314e", "e18578ef", "7a7e0edc", "1234abcd", "deadbeef", "00ff00ff", "abcdef01", "10203040", "a1b2c3d4", "ffffffff", "0000aaaa", "9f9f9f9f", "12ab34cd", "cafe0001", "beef0002", "f00d0003", "0a0b0c0d"}[i%17]
		}), `[0-9a-f]{8}`},
		{"prefixed numbers", gen(func(i int) string {
			return "ord-" + []string{"1000", "2345", "9999", "4321", "1111", "8888", "5050", "7070", "6060", "3030", "2020", "1212", "3434", "5656", "7878", "9090", "1357"}[i%17]
		}), `ord-[0-9]{4}`},
		{"durations", gen(func(i int) string {
			return []string{"1ms", "12ms", "123ms", "5ms", "77ms", "300ms", "2ms", "9ms", "10ms", "99ms", "101ms", "250ms", "3ms", "4ms", "6ms", "8ms", "11ms"}[i%17]
		}), `[0-9]{1,3}ms`},
	}
	for _, c := range cases {
		p, err := inferPosition("<*>", c.values, nil, DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		if p.Regex != c.want {
			t.Fatalf("%s: got %s want %s", c.name, p.Regex, c.want)
		}
	}
}
