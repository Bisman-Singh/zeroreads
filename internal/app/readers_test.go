package app

import (
	"strings"
	"testing"
	"time"

	"github.com/Bisman-Singh/zeroreads/internal/analyze"
)

// The report says how many readers are exact and what was assumed for the rest: each kind counts a
// reader once, however many of its stages share that kind.
func TestReaderSummaryCountsAssumptions(t *testing.T) {
	recs := []analyze.Recommendation{
		{ID: "a", Action: "none", Candidate: analyze.Candidate{Service: "s", Template: "t"}, Readers: []analyze.Reader{
			{Source: "grafana", Origin: "o", Expr: "exact", Witness: "w"},
			{Source: "grafana", Origin: "o", Expr: "two kinds", Widened: []string{`label filter level = "x"`, `line filter |= "z" after the line is rewritten`}},
		}},
		{ID: "b", Action: "none", Candidate: analyze.Candidate{Service: "s", Template: "u"}, Readers: []analyze.Reader{
			{Source: "loki-querylog", Origin: "o", Expr: "broken", Widened: []string{"query does not parse"}},
			{Source: "grafana", Origin: "o", Expr: "one kind twice", Widened: []string{`label filter a = "1"`, `label filter b = "2"`}},
			{Source: "grafana", Origin: "o", Expr: "variable", Widened: []string{`stream matcher service_name="$svc" uses a template variable`}},
		}},
	}
	s := summarizeReaders(recs)
	want := []Assumption{{"label filter", 2}, {"line filter after line_format, decolorize or unpack", 1}, {"query does not parse", 1}, {"template variable", 1}}
	if s.Readers != 5 || s.Exact != 1 || len(s.Assumptions) != len(want) {
		t.Fatalf("%+v", s)
	}
	for i, a := range want {
		if s.Assumptions[i] != a {
			t.Fatalf("assumption %d: %+v, want %+v", i, s.Assumptions[i], a)
		}
	}
	md := Markdown(&Report{GeneratedAt: time.Unix(0, 0), Recommendations: recs, Readers: s})
	for _, w := range []string{
		"5 readers across all rules. 1 read the rule's lines exactly",
		"4 are assumed to read more than they may",
		"- label filter: 2\n",
		"`two kinds` (assumed: `label filter level = \"x\"; line filter |= \"z\" after the line is rewritten`)",
	} {
		if !strings.Contains(md, w) {
			t.Fatalf("report.md lacks %q:\n%s", w, md)
		}
	}
	if strings.Contains(md, "`exact` (assumed") {
		t.Fatalf("an exact reader must not carry assumptions:\n%s", md)
	}
}
