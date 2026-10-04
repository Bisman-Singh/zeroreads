package app

import (
	"strings"
	"testing"
	"unicode"

	"github.com/Bisman-Singh/zeroreads/internal/analyze"
)

// hostile is text a dashboard, query or log line can carry: workflow commands after a newline, terminal
// escapes, Unicode line and direction controls, backtick runs, Markdown headings and HTML.
var hostile = []string{
	"{service_name=\"checkout\"} != `\n::error title=zeroreads verify::All enforced rules are still safe\n<!--\x1b[2K`",
	"a``b```c",
	"`",
	"``x``",
	"x\r\n## Rules\n- forged",
	"\u2028::warning::x",
	"\u202eevil",
	`<a href="https://example.invalid/">Enforce now</a>`,
	"\xff\xfe",
}

func TestPrintableKeepsTextOnOneLine(t *testing.T) {
	for _, s := range hostile {
		for _, r := range Printable(s) {
			if !unicode.IsPrint(r) {
				t.Fatalf("Printable(%q) keeps %U", s, r)
			}
		}
	}
	plain := `{service_name="checkout"} |~ "GET /healthz \d+ms" (e.g. "a b")`
	if got := Printable(plain); got != plain {
		t.Fatalf("printable text changed: %q", got)
	}
}

func TestCodeCannotBeClosedByItsContent(t *testing.T) {
	if got := Code(""); got != "` `" {
		t.Fatalf("Code of nothing is %q", got)
	}
	for _, s := range hostile {
		c := Code(s)
		k := len(c) - len(strings.TrimLeft(c, "`"))
		inner := c[k : len(c)-k]
		if !strings.HasSuffix(c, strings.Repeat("`", k)) || strings.Contains(inner, strings.Repeat("`", k)) {
			t.Fatalf("Code(%q) = %q can be closed early", s, c)
		}
		if len(inner) >= 2 && strings.HasPrefix(inner, " ") && strings.HasSuffix(inner, " ") && strings.TrimSpace(inner) != "" {
			inner = inner[1 : len(inner)-1]
		}
		if inner != Printable(s) {
			t.Fatalf("Code(%q) shows %q", s, inner)
		}
	}
}

// outsideCode is a Markdown line without its code spans, found as CommonMark finds them: a run of
// backticks is closed by the next run of the same length; an unclosed run stays as text.
func outsideCode(line string) string {
	var out strings.Builder
	for i := 0; i < len(line); {
		if line[i] != '`' {
			out.WriteByte(line[i])
			i++
			continue
		}
		k := i
		for k < len(line) && line[k] == '`' {
			k++
		}
		fence, end := line[i:k], -1
		for j := k; j < len(line); {
			if line[j] != '`' {
				j++
				continue
			}
			e := j
			for e < len(line) && line[e] == '`' {
				e++
			}
			if line[j:e] == fence {
				end = e
				break
			}
			j = e
		}
		if end < 0 {
			out.WriteString(fence)
			i = k
			continue
		}
		i = end
	}
	return out.String()
}

// shape is what a Markdown page is made of, its line count and each line's kind, with the text of
// every code span left out.
func shape(md string) []string {
	var out []string
	for _, l := range strings.Split(md, "\n") {
		rest := outsideCode(l)
		for _, bad := range []string{"`", "<", "::", "\r"} {
			if strings.Contains(rest, bad) {
				out = append(out, "UNSAFE "+l)
			}
		}
		kind := "text"
		for _, p := range []string{"### ", "## ", "# ", "    - ", "  - ", "- "} {
			if strings.HasPrefix(l, p) {
				kind = p
				break
			}
		}
		out = append(out, kind)
	}
	return out
}

func reportWith(text []string) *Report {
	return &Report{
		Recommendations: []analyze.Recommendation{{
			ID:        "r-1",
			Candidate: analyze.Candidate{Service: text[4], Template: text[0], Language: text[1]},
			Action:    "none",
			Readers:   []analyze.Reader{{Source: "grafana", Origin: text[4], Expr: text[0], Witness: text[3], Widened: []string{text[5]}}},
			Blockers:  []string{text[0], text[7]},
			Rewrites:  []analyze.Rewrite{{Source: "grafana", Origin: text[6], Old: text[2], New: text[3]}},
		}},
		Gaps:    []analyze.Gap{{Key: text[2], Source: "grafana", Origin: text[6], Reason: text[7]}},
		Notes:   []string{text[4]},
		Skipped: []Skipped{{Service: text[0], Template: text[1], Reason: text[8]}},
	}
}

func TestReportCannotBeRewrittenByWhatItQuotes(t *testing.T) {
	plain := make([]string, len(hostile))
	for i := range plain {
		plain[i] = "x"
	}
	want, got := shape(Markdown(reportWith(plain))), shape(Markdown(reportWith(hostile)))
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("hostile text changed the report's structure:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestStepSummaryCannotBeRewrittenByAReason(t *testing.T) {
	plain := make([]string, len(hostile))
	for i := range plain {
		plain[i] = "x"
	}
	res := func(reasons []string) *VerifyResult {
		return &VerifyResult{Violations: []Violation{{RuleID: "r-1", Reasons: reasons}}}
	}
	want, got := shape(StepSummary(res(plain), 2)), shape(StepSummary(res(hostile), 2))
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("a hostile reason changed the summary's structure:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
