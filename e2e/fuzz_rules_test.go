//go:build e2e

package e2e

// A soundness fuzz contributed by an external audit: real rules (corpus -> Drain -> rule.Infer), lines
// generated from each rule's whole language (not only lines seen in the corpus), random queries over
// every pipeline stage kind, checked against the real Loki.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
	"github.com/Bisman-Singh/sievelog/internal/gen"
	"github.com/Bisman-Singh/sievelog/internal/logql"
	"github.com/Bisman-Singh/sievelog/internal/rule"
	"github.com/Bisman-Singh/sievelog/internal/templating"
	"github.com/Bisman-Singh/sievelog/internal/usage"
)

type fzRule struct {
	svc   string
	re    *regexp.Regexp
	ur    usage.Rule
	lines []string
}

func fzBuildRules(t *testing.T, run string) []fzRule {
	recs, _, err := gen.Run(7, 6000)
	if err != nil {
		t.Fatal(err)
	}
	isJSON := map[string]bool{}
	for _, s := range gen.Corpus() {
		isJSON[s.Name] = s.JSON
	}
	var plain []gen.Record
	for _, r := range recs {
		if !isJSON[r.Service] {
			plain = append(plain, r)
		}
	}
	ctx := context.Background()
	cfg := templating.DefaultConfig()
	cfg.MaskingRules = []templating.MaskRule{{Name: gen.IPMaskName, Pattern: gen.IPMaskPattern}}
	cfg.SeedTemplates = gen.SeedTemplates()
	e, err := templating.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)
	in := make([]templating.Input, len(plain))
	for i, r := range plain {
		in[i] = templating.Input{Body: r.Line}
	}
	tmpl, err := e.Template(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	texts := map[string][]string{}
	var keys []string
	for i, r := range plain {
		k := r.Service + "\x00" + tmpl[i]
		if texts[k] == nil {
			keys = append(keys, k)
		}
		texts[k] = append(texts[k], r.Message)
	}
	var out []fzRule
	for i, k := range keys {
		parts := strings.SplitN(k, "\x00", 2)
		lang, err := rule.Infer(parts[1], []rule.Mask{{Name: gen.IPMaskName, Pattern: gen.IPMaskPattern}}, texts[k], rule.DefaultOptions())
		if err != nil {
			continue
		}
		re := regexp.MustCompile(lang.Regex)
		mem, err := automaton.Members(lang.Regex, 60, uint64(i)+1)
		if err != nil {
			t.Fatal(err)
		}
		seen := texts[k][:min(20, len(texts[k]))]
		for _, s := range automaton.Near(append(mem, seen...), 6, uint64(i)+9) {
			if re.MatchString(s) {
				mem = append(mem, s)
			}
		}
		mem = append(mem, seen...)
		svc := fmt.Sprintf("fz-%s-%d", run, i)
		out = append(out, fzRule{svc: svc, re: re, lines: fzDedupe(mem),
			ur: usage.Rule{ID: k, Scope: map[string]string{"service_name": svc}, Language: automaton.MustCompile(lang.Regex)}})
	}
	return out
}

func fzDedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] && utf8.ValidString(s) && strings.TrimSpace(s) != "" {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

type fzGen struct {
	r     *rand.Rand
	rules []fzRule
}

var fzTraps = []string{"K", "İ", "ſ", "ı", "ß", "ẞ", "Σ", "ς", "\u200b", "�", "\n", "\t", " ", "é", "É"}

func (g *fzGen) token(fr fzRule) string {
	switch g.r.IntN(10) {
	case 0:
		return fzTraps[g.r.IntN(len(fzTraps))]
	case 1:
		return string(rune('a'+g.r.IntN(26))) + string(rune('a'+g.r.IntN(26)))
	}
	s := []rune(fr.lines[g.r.IntN(len(fr.lines))])
	if len(s) == 0 {
		return "x"
	}
	i := g.r.IntN(len(s))
	j := i + 1 + g.r.IntN(min(10, len(s)-i))
	t := string(s[i:j])
	switch g.r.IntN(6) {
	case 0:
		t = strings.ToUpper(t)
	case 1:
		t = strings.ToLower(t)
	}
	return t
}

func (g *fzGen) regex(fr fzRule) string {
	s := regexp.QuoteMeta(g.token(fr))
	tok := func() string { return regexp.QuoteMeta(g.token(fr)) }
	// Shapes Loki 3.7.8 turns into substring filters with another meaning: a .* before an alternation,
	// empty and .* alternatives, two alternations after a literal, mixed case flags, and .+.
	switch g.r.IntN(26) {
	case 14:
		return s + ".*(" + tok() + "|" + tok() + ")"
	case 15:
		return "(" + s + "|" + tok() + "|)"
	case 16:
		return "(" + s + "|.*" + tok() + ")"
	case 17:
		return s + "(" + tok() + "|" + tok() + ")(" + tok() + "|" + tok() + ")"
	case 18:
		return ".+"
	case 19:
		r := []rune(g.token(fr))
		first := regexp.QuoteMeta(string(r[:1]))
		return "(?i:" + first + ")(?-i)" + regexp.QuoteMeta(string(r[1:])) + "|" + strings.ToUpper(first)
	case 20:
		return s + "(?:" + tok() + "|.*" + tok() + ")"
	case 21:
		return "(" + s + "|" + tok() + ")"
	}
	switch g.r.IntN(14) {
	case 0:
		return "(?i)" + s
	case 1:
		return "^" + s
	case 2:
		return s + "$"
	case 3:
		return regexp.MustCompile(`[0-9]`).ReplaceAllString(s, `\d`)
	case 4:
		return s + ".*" + regexp.QuoteMeta(g.token(fr))
	case 5:
		return "(?i)(" + s + "|" + regexp.QuoteMeta(g.token(fr)) + ")"
	case 6:
		return `\b` + s + `\b`
	case 7:
		return "(?s)" + s + ".+"
	case 8:
		return "[" + regexp.QuoteMeta(g.token(fr)) + "]{2,}"
	case 9:
		return "(?i).*" + s + ".*"
	case 10:
		return "(?m)^" + s
	case 11:
		return `[^\s]+` + s
	case 12:
		return "(?i:" + s + ")[a-z]?"
	}
	return s
}

func (g *fzGen) stage(fr fzRule) string {
	q := strconv.Quote
	switch g.r.IntN(20) {
	case 0, 1, 2:
		return "|= " + q(g.token(fr))
	case 3, 4, 5:
		return "!= " + q(g.token(fr))
	case 6, 7:
		return "|~ " + q(g.regex(fr))
	case 8, 9:
		return "!~ " + q(g.regex(fr))
	case 10:
		return "|= " + q(g.token(fr)) + " or " + q(g.token(fr))
	case 11:
		return "!= " + q(g.token(fr)) + " or " + q(g.token(fr))
	case 12:
		return "|~ " + q(g.regex(fr)) + " or " + q(g.regex(fr))
	case 13:
		return "!~ " + q(g.regex(fr)) + " or " + q(g.regex(fr))
	case 14:
		return `| logfmt | level=~"info|debug"`
	case 15:
		return `| line_format "{{.level}} x"`
	case 16:
		return `| unpack`
	case 17:
		return `| decolorize`
	case 18:
		return `| json | __error__=""`
	}
	return "|> " + q("<_>"+g.token(fr)+"<_>")
}

func (g *fzGen) query(fr fzRule) string {
	var sel string
	switch g.r.IntN(6) {
	case 0:
		other := g.rules[g.r.IntN(len(g.rules))].svc
		sel = `{service_name=~"` + regexp.QuoteMeta(fr.svc) + `|` + regexp.QuoteMeta(other) + `"}`
	case 1:
		sel = `{service_name=~"` + strings.ToUpper(fr.svc[:3]) + `(?i).*` + `"}`
	default:
		sel = `{service_name="` + fr.svc + `"}`
	}
	var b strings.Builder
	b.WriteString(sel)
	for n := g.r.IntN(4); n > 0; n-- {
		b.WriteString(" " + g.stage(fr))
	}
	return b.String()
}

type fzRow struct{ svc, ts, line string }

// fzPush stores lines and remembers each by timestamp, so a line rewritten by line_format or unpack
// in the response is still attributed to the stored line it came from.
func fzPush(t *testing.T, base, svc string, lines []string, into map[string]string) {
	now := time.Now().Add(-10 * time.Minute).UnixNano()
	var vals [][2]string
	for i, l := range lines {
		ts := strconv.FormatInt(now+int64(i)*1000, 10)
		vals = append(vals, [2]string{ts, l})
		into[svc+"|"+ts] = l
	}
	body, _ := json.Marshal(map[string]any{"streams": []any{map[string]any{"stream": map[string]string{"service_name": svc}, "values": vals}}})
	resp, err := http.Post(base+"/loki/api/v1/push", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode/100 != 2 {
		t.Fatalf("push: %v %v", err, resp)
	}
	resp.Body.Close()
}

func fzQuery(base, qs string) ([]fzRow, int) {
	v := url.Values{}
	v.Set("query", qs)
	v.Set("limit", "5000")
	v.Set("start", strconv.FormatInt(time.Now().Add(-2*time.Hour).UnixNano(), 10))
	v.Set("end", strconv.FormatInt(time.Now().UnixNano(), 10))
	resp, err := http.Get(base + "/loki/api/v1/query_range?" + v.Encode())
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	var r struct {
		Data struct {
			Result []struct {
				Stream map[string]string `json:"stream"`
				Values [][2]string       `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	var out []fzRow
	for _, s := range r.Data.Result {
		for _, v := range s.Values {
			out = append(out, fzRow{s.Stream["service_name"], v[0], v[1]})
		}
	}
	return out, resp.StatusCode
}

func TestFuzzRealRulesAgainstLoki(t *testing.T) {
	base := env(t, "LOKI_URL")
	nq := envInt("FUZZ_N", 3000)
	run := fmt.Sprint(time.Now().UnixNano() % 1e6)
	rules := fzBuildRules(t, run)
	total := 0
	stored := map[string]string{}
	for _, fr := range rules {
		fzPush(t, base, fr.svc, fr.lines, stored)
		total += len(fr.lines)
	}
	t.Logf("rules=%d language lines pushed=%d", len(rules), total)
	time.Sleep(3 * time.Second)
	byID := map[string]fzRule{}
	for _, fr := range rules {
		byID[fr.svc] = fr
	}
	g := &fzGen{r: rand.New(rand.NewPCG(42, 7)), rules: rules}
	var ok, rejected, notUsed, unsound, parseFail, returned int
	var counts readCounts
	for i := 0; i < nq; i++ {
		fr := rules[g.r.IntN(len(rules))]
		qs := g.query(fr)
		rows, status := fzQuery(base, qs)
		if status != 200 {
			rejected++
			continue
		}
		ok++
		parsed, perr := logql.Parse(qs)
		if perr != nil {
			parseFail++
			t.Logf("analyzer cannot parse a query Loki accepts (blocks everything, safe): %s: %v", qs, perr)
			continue
		}
		read := map[string]string{}
		for _, rw := range rows {
			orig, found := stored[rw.svc+"|"+rw.ts]
			if r, known := byID[rw.svc]; found && known && r.re.MatchString(orig) {
				read[rw.svc] = orig
			}
		}
		for svc, witness := range read {
			returned++
			used := false
			var why []string
			for _, sel := range parsed.Selections {
				v := usage.Evaluate(sel, byID[svc].ur)
				used = used || v.Used
				why = append(why, v.Reason)
			}
			if !used {
				unsound++
				t.Errorf("UNSOUND: %s\n  Loki returned %q (rule %s)\n  analyzer: %v", qs, witness, svc, why)
			}
		}
		var fv usage.Verdict
		for _, sel := range parsed.Selections {
			v := usage.Evaluate(sel, fr.ur)
			if !v.Used {
				notUsed++
			} else if !fv.Used || len(fv.Widened) > 0 && len(v.Widened) == 0 {
				fv = v
			}
		}
		if fv.Used {
			counts.add(fv, read[fr.svc] != "")
		}
	}
	t.Logf("over-blocking: %s", counts)
	t.Logf("queries accepted=%d rejected=%d parse-fallback=%d (rule,query) pairs with real reads=%d analyzer-not-used verdicts=%d UNSOUND=%d",
		ok, rejected, parseFail, returned, notUsed, unsound)
	if returned == 0 || notUsed == 0 {
		t.Fatalf("the fuzz has no teeth: %d real reads, %d not-used verdicts", returned, notUsed)
	}
}
