//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
	"github.com/Bisman-Singh/sievelog/internal/gen"
	"github.com/Bisman-Singh/sievelog/internal/logql"
	"github.com/Bisman-Singh/sievelog/internal/rule"
	"github.com/Bisman-Singh/sievelog/internal/usage"
)

// corpusRules infers one rule per (service, template) from the ground truth, exactly as the
// analyzer would, scoped by Loki's service_name label.
func corpusRules(t *testing.T, recs []gen.Record) []usage.Rule {
	t.Helper()
	offline := offlineTemplates(t, recs)
	isJSON := map[string]bool{}
	for _, s := range gen.Corpus() {
		isJSON[s.Name] = s.JSON
	}
	texts := map[string][]string{}
	idx := map[string]int{}
	for _, r := range recs {
		tpl := offline[r.Service][idx[r.Service]]
		idx[r.Service]++
		k := r.Service + "|" + tpl
		texts[k] = append(texts[k], r.Message)
	}
	var keys []string
	for k := range texts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []usage.Rule
	for _, k := range keys {
		parts := strings.SplitN(k, "|", 2)
		lang, err := rule.Infer(parts[1], []rule.Mask{{Name: gen.IPMaskName, Pattern: gen.IPMaskPattern}}, texts[k], rule.DefaultOptions())
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		out = append(out, usage.Rule{
			ID:         k,
			Scope:      map[string]string{"service_name": parts[0]},
			Language:   automaton.MustCompile(lang.Regex),
			Structured: isJSON[parts[0]],
		})
	}
	return out
}

type lokiLine struct {
	service string
	ts      string
	line    string
}

// lokiQuery runs a log query over the last hour and returns every line with its service.
// status is the HTTP status; Loki answers 400 for queries it cannot parse.
func lokiQuery(t *testing.T, base, q string) ([]lokiLine, int) {
	t.Helper()
	v := url.Values{}
	v.Set("query", q)
	v.Set("limit", "200000")
	v.Set("direction", "forward")
	v.Set("start", strconv.FormatInt(time.Now().Add(-time.Hour).UnixNano(), 10))
	v.Set("end", strconv.FormatInt(time.Now().Add(time.Minute).UnixNano(), 10))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/loki/api/v1/query_range?"+v.Encode(), nil)
	req.Header.Set("X-Query-Tags", "Source=sievelog-e2e")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var out struct {
		Data struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Stream map[string]string `json:"stream"`
				Values [][2]string       `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	if out.Data.ResultType != "streams" {
		t.Fatalf("%s: result type %s", q, out.Data.ResultType)
	}
	var lines []lokiLine
	for _, r := range out.Data.Result {
		for _, v := range r.Values {
			lines = append(lines, lokiLine{service: r.Stream["service_name"], ts: v[0], line: v[1]})
		}
	}
	return lines, resp.StatusCode
}

// rulesRead maps lines Loki returned to the rules whose language contains the ORIGINAL line.
// Returned text may be rewritten (line_format), so each line is identified by stream and timestamp
// in the baseline read of every stored line.
func rulesRead(t *testing.T, rules []usage.Rule, lines []lokiLine, original map[string][]string) map[string]bool {
	t.Helper()
	read := map[string]bool{}
	for _, ret := range lines {
		origs, ok := original[ret.service+"|"+ret.ts]
		if !ok {
			t.Fatalf("returned line %+v has no baseline original", ret)
		}
		for _, o := range origs {
			l := lokiLine{service: ret.service, line: o}
			markRead(t, rules, l, read)
		}
	}
	return read
}

func markRead(t *testing.T, rules []usage.Rule, l lokiLine, read map[string]bool) {
	t.Helper()
	{
		text := l.line
		for _, r := range rules {
			if r.Scope["service_name"] != l.service {
				continue
			}
			if r.Structured {
				var m map[string]any
				if err := json.Unmarshal([]byte(l.line), &m); err != nil {
					t.Fatalf("structured line %q: %v", l.line, err)
				}
				text, _ = m["msg"].(string)
			}
			if r.Language.Regexp().MatchString(text) {
				read[r.ID] = true
			}
		}
	}
}

// predicted returns the rules the analyzer says the query reads. A query it cannot parse reads
// everything, which is how the product treats it.
func predicted(q string, rules []usage.Rule) (map[string]bool, bool) {
	out := map[string]bool{}
	pq, err := logql.Parse(q)
	if err != nil {
		for _, r := range rules {
			out[r.ID] = true
		}
		return out, false
	}
	for _, sel := range pq.Selections {
		for _, r := range rules {
			if usage.Evaluate(sel, r).Used {
				out[r.ID] = true
			}
		}
	}
	return out, true
}

// queryGen builds random log queries from real corpus text.
type queryGen struct {
	r     *rand.Rand
	lines []gen.Record
}

func quote(s string) string { return strconv.Quote(s) }

func (g *queryGen) substring() string {
	rec := g.lines[g.r.IntN(len(g.lines))]
	s := rec.Message
	if rec.Service == "orders" && g.r.IntN(3) == 0 {
		s = rec.Line // raw JSON text, including fields outside msg
	}
	if s == "" {
		return "x"
	}
	i := g.r.IntN(len(s))
	j := i + 1 + g.r.IntN(min(12, len(s)-i))
	return s[i:j]
}

func (g *queryGen) token() string {
	switch g.r.IntN(6) {
	case 0:
		return []string{"status 503", "status=503", "healthz", "heartbeat", "logged in", "failed MFA", "cache hit", "<ip>", "10.", "ms", "ERROR", "error", "INFO user", "ord-", "pay_"}[g.r.IntN(15)]
	case 1:
		return fmt.Sprintf("%c%c", 'a'+rune(g.r.IntN(26)), 'a'+rune(g.r.IntN(26)))
	default:
		return g.substring()
	}
}

func (g *queryGen) regex() string {
	s := regexp.QuoteMeta(g.token())
	switch g.r.IntN(8) {
	case 0:
		return "(?i)" + strings.ToUpper(s)
	case 1:
		return "^" + s
	case 2:
		return s + "$"
	case 3:
		return strings.ReplaceAll(s, "0", "[0-9]")
	case 4:
		return s + ".*" + regexp.QuoteMeta(g.token())
	case 5:
		return "(" + s + "|" + regexp.QuoteMeta(g.token()) + ")"
	case 6:
		return `\b` + s
	}
	return s
}

func (g *queryGen) stage() string {
	switch g.r.IntN(14) {
	case 0, 1, 2:
		return "|= " + quote(g.token())
	case 3, 4:
		return "!= " + quote(g.token())
	case 5:
		return "|~ " + quote(g.regex())
	case 6:
		return "!~ " + quote(g.regex())
	case 7:
		return "|= " + quote(g.token()) + " or " + quote(g.token())
	case 8:
		return "!= " + quote(g.token()) + " or " + quote(g.token())
	case 9:
		return "|> " + quote("<_>"+g.token()+"<_>")
	case 10:
		return `| json | status="503"`
	case 11:
		return `| logfmt | level="error"`
	case 12:
		return `| line_format "{{.status}}"`
	}
	return "|~ " + quote(g.regex()) + " or " + quote(g.regex())
}

func (g *queryGen) selector() string {
	svcs := []string{"checkout", "auth", "orders"}
	switch g.r.IntN(6) {
	case 0:
		return `{service_name=~"` + svcs[g.r.IntN(3)] + `|` + svcs[g.r.IntN(3)] + `"}`
	case 1:
		return `{service_name!="` + svcs[g.r.IntN(3)] + `", k8s_container_name=~".+"}`
	case 2:
		return `{k8s_container_name="` + svcs[g.r.IntN(3)] + `"}`
	}
	return `{service_name="` + svcs[g.r.IntN(3)] + `"}`
}

func (g *queryGen) query() string {
	var b strings.Builder
	b.WriteString(g.selector())
	for n := g.r.IntN(4); n > 0; n-- {
		b.WriteString(" " + g.stage())
	}
	return b.String()
}

// The analyzer must never call a rule unused when Loki actually returns lines of that rule.
func TestUsageSoundAgainstLoki(t *testing.T) {
	base := env(t, "LOKI_URL")
	recs, _ := groundTruth(t)
	rules := corpusRules(t, recs)

	// Wait until Loki has every line, and keep that read as the baseline of original lines.
	deadline := time.Now().Add(90 * time.Second)
	original := map[string][]string{}
	for {
		all, _ := lokiQuery(t, base, `{service_name=~".+"}`)
		if len(all) == len(recs) {
			for _, l := range all {
				k := l.service + "|" + l.ts
				original[k] = append(original[k], l.line)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Loki has %d lines, want %d", len(all), len(recs))
		}
		time.Sleep(2 * time.Second)
	}

	g := &queryGen{r: rand.New(rand.NewPCG(99, 7)), lines: recs}
	n := 800
	if s := strings.TrimSpace(getenvDefault("E2E_QUERIES", "")); s != "" {
		n, _ = strconv.Atoi(s)
	}
	var sound, parseFallback, lokiRejected, readSomething, preciseNotUsed int
	for i := 0; i < n; i++ {
		q := g.query()
		lines, status := lokiQuery(t, base, q)
		pred, parsed := predicted(q, rules)
		if status != http.StatusOK {
			lokiRejected++
			if parsed {
				t.Logf("Loki rejected (status %d) a query the analyzer parsed: %s", status, q)
			}
			continue
		}
		if !parsed {
			parseFallback++
			t.Errorf("analyzer could not parse a query Loki accepts: %s", q)
		}
		actual := rulesRead(t, rules, lines, original)
		if len(actual) > 0 {
			readSomething++
		}
		for id := range actual {
			if !pred[id] {
				t.Fatalf("UNSOUND: %s\n  Loki returned lines of %s, analyzer says unused", q, id)
			}
		}
		for _, r := range rules {
			if !pred[r.ID] {
				preciseNotUsed++
			}
		}
		sound++
	}
	t.Logf("queries=%d sound=%d loki_rejected=%d parse_fallback=%d with_rule_lines=%d proven_unused_pairs=%d",
		n, sound, lokiRejected, parseFallback, readSomething, preciseNotUsed)
	if readSomething < n/4 {
		t.Fatalf("generator too weak: only %d queries returned rule lines", readSomething)
	}
	if preciseNotUsed == 0 {
		t.Fatal("analyzer never proved a rule unused; the test would pass for an analyzer that says used for everything")
	}
}

func getenvDefault(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}
