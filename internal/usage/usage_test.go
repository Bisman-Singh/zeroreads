package usage

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Bisman-Singh/zeroreads/internal/automaton"
	"github.com/Bisman-Singh/zeroreads/internal/logql"
)

// Rules shaped like the corpus languages.
var (
	health = Rule{ID: "health", Scope: map[string]string{"service_name": "checkout"},
		Language: automaton.MustCompile(`\AINFO GET /healthz 200 [0-9]{1,3}ms\z`)}
	request = Rule{ID: "request", Scope: map[string]string{"service_name": "checkout"},
		Language: automaton.MustCompile(`\AINFO request [0-9a-f]{16} status (?:200|201|404|503) took [0-9]{1,3}ms\z`)}
	login = Rule{ID: "login", Scope: map[string]string{"service_name": "auth"},
		Language: automaton.MustCompile(`\AINFO user (?:alice|bob|carol|dave|erin|frank) logged in\z`)}
	route = Rule{ID: "route", Scope: map[string]string{"service_name": "orders"}, Structured: true,
		Language: automaton.MustCompile(`\Ahandled route in [0-9]{1,3}ms\z`)}
)

func verdict(t *testing.T, q string, r Rule) Verdict {
	t.Helper()
	pq, err := logql.Parse(q)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	var out Verdict
	for _, sel := range pq.Selections {
		v := Evaluate(sel, r)
		if v.Used {
			if v.Witness != "" && !r.Language.Regexp().MatchString(v.Witness) {
				t.Fatalf("%s: witness %q is not in the rule's language", q, v.Witness)
			}
			return v
		}
		out = v
	}
	return out
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		q    string
		r    Rule
		used bool
	}{
		// Stream scope.
		{`{service_name="checkout"}`, health, true},
		{`{service_name="auth"}`, health, false},
		{`{service_name=~"check.*"}`, health, true},
		{`{service_name=~"check"}`, health, false}, // label regexes are anchored
		{`{service_name!="checkout", k8s_container_name=~".+"}`, health, false},
		{`{service_name!~"auth|orders", k8s_container_name=~".+"}`, health, true},
		{`{namespace="prod"}`, health, true}, // not a scope label: cannot exclude
		{`{service_name="$svc"}`, health, true},
		{`{service_name=~"(?i)CHECKOUT"}`, health, true}, // not modelled: cannot exclude
		// Positive filters.
		{`{service_name="checkout"} |= "healthz"`, health, true},
		{`{service_name="checkout"} |= "heartbeat"`, health, false},
		{`{service_name="checkout"} |= "status 503"`, request, true},
		{`{service_name="checkout"} |= "status=503"`, request, false},
		{`{service_name="checkout"} |= "status 500"`, request, false},
		{`{service_name="checkout"} |~ "status 5[0-9]{2}"`, request, true},
		{`{service_name="checkout"} |~ "took [0-9]{4}ms"`, request, false},
		{`{service_name="checkout"} |= "x" or "healthz"`, health, true},
		{`{service_name="checkout"} |= "x" or "y"`, health, false},
		{`{service_name="checkout"} |= "GET" |= "POST"`, health, false},
		// Negative filters.
		{`{service_name="checkout"} != "healthz"`, health, false},
		{`{service_name="checkout"} != "200 1"`, health, true},
		{`{service_name="checkout"} !~ "^INFO"`, health, false},
		{`{service_name="checkout"} != "x" or "healthz"`, health, false},
		{`{service_name="checkout"} != "x" or "y"`, health, true},
		// Case-insensitive: Go (?i) and Loki's ToLower comparison.
		{`{service_name="checkout"} |~ "(?i)HEALTHZ"`, health, true},
		{`{service_name="checkout"} |~ "(?i)heartbeat"`, health, false},
		{`{service_name="checkout"} !~ "(?i)healthz"`, health, true}, // not modelled: cannot exclude
		// Not modelled positive filters widen to everything.
		{`{service_name="checkout"} |> "<_> nomatch <_>"`, health, true},
		{`{service_name="checkout"} |= ip("10.0.0.0/8")`, health, true},
		{`{service_name="checkout"} |= "$search"`, health, true},
		// Rewrites stop filter evaluation.
		{`{service_name="checkout"} | line_format "x" |= "heartbeat"`, health, true},
		{`{service_name="checkout"} |= "heartbeat" | line_format "x"`, health, false},
		// Label filters and parsers cannot exclude.
		{`{service_name="checkout"} | logfmt | level="nothing"`, health, true},
		// Metric queries select the same lines and count them.
		{`sum(count_over_time({service_name="checkout"} |= "healthz" [5m]))`, health, true},
		{`absent_over_time({service_name="checkout"} |= "healthz" [5m])`, health, true},
		// Structured streams: any line filter reads every line.
		{`{service_name="orders"} |= "nothing like this"`, route, true},
		{`{service_name="orders"}`, route, true},
		{`{service_name="checkout"} |= "x"`, route, false},
		// Sibling templates: a filter for the long line cannot select short lines.
		{`{service_name="auth"} |= "failed MFA"`, login, false},
		{`{service_name="auth"} |= "logged in"`, login, true},
	}
	for _, c := range cases {
		v := verdict(t, c.q, c.r)
		if v.Used != c.used {
			t.Fatalf("%s on %s: used=%v (%s), want %v", c.q, c.r.ID, v.Used, v.Reason, c.used)
		}
	}
}

func TestCountingFlag(t *testing.T) {
	if v := verdict(t, `rate({service_name="checkout"}[1m])`, health); !v.Used || !v.Counting {
		t.Fatalf("rate: %+v", v)
	}
	if v := verdict(t, `{service_name="checkout"}`, health); !v.Used || v.Counting {
		t.Fatalf("log query: %+v", v)
	}
}

// A "used" verdict names every assumption behind it, and only an exact one names none: its witness is
// then a line the query really selects. A "not used" verdict is a proof and never carries any.
func TestWidenedNamesEveryAssumption(t *testing.T) {
	cases := []struct {
		q    string
		r    Rule
		want string // a phrase of the assumption, "" when the verdict must be exact
	}{
		{`{service_name="checkout"}`, health, ""},
		{`{service_name="checkout"} |= "healthz"`, health, ""},
		{`{service_name="checkout"} != "200 1"`, health, ""},
		{`{service_name=~"check.*"} |~ "GET /health[a-z]+"`, health, ""},
		{`{service_name="checkout", namespace="prod"} |= "healthz"`, health, ""}, // the rule covers every stream of its service
		{`{namespace="prod"} |= "healthz"`, health, "names no scope label (service_name)"},
		{`sum(count_over_time({service_name="checkout"} |= "healthz" [5m]))`, health, ""},
		{`{service_name="$svc"}`, health, `stream matcher service_name="$svc" uses a template variable`},
		{`{service_name=~"(?i)CHECKOUT"}`, health, "is not evaluated exactly"},
		{`{service_name="checkout"} |= "$search"`, health, "uses a template variable"},
		{`{service_name="checkout"} |> "<_> nomatch <_>"`, health, "pattern filter"},
		{`{service_name="checkout"} |= ip("10.0.0.0/8")`, health, "ip filter"},
		{`{service_name="checkout"} !~ "(?i)healthz"`, health, "case-insensitive negative regex"},
		{`{service_name="checkout"} |~ "(?i)HEALTHZ"`, health, "case-insensitive filter"},
		{`{service_name="checkout"} | line_format "x" |= "heartbeat"`, health, "after the line is rewritten"},
		{`{service_name="checkout"} | logfmt | level="nothing"`, health, `label filter level = "nothing"`},
		{`{service_name="orders"} |= "nothing like this"`, route, "structured records"},
		{`{$label_name=~"$label_value", service_name="checkout"} |= "healthz"`, health, "uses a template variable as its label name"},
	}
	for _, c := range cases {
		v := verdict(t, c.q, c.r)
		if !v.Used {
			t.Fatalf("%s: not used (%s)", c.q, v.Reason)
		}
		got := strings.Join(v.Widened, "; ")
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Fatalf("%s: widened %q, want %q", c.q, got, c.want)
		}
	}
	for _, q := range []string{
		`{service_name="checkout"} |= "heartbeat" | logfmt | level="x"`,
		`{service_name="checkout"} |= "heartbeat" |> "<_>"`,
		`{service_name="$svc"} |= "heartbeat"`,
	} {
		if v := verdict(t, q, health); v.Used || len(v.Widened) > 0 {
			t.Fatalf("%s: a proof must carry no assumptions: %+v", q, v)
		}
	}
}

// Assumptions is what a verdict would assume whatever the rule, so query coverage can be measured
// without rules: the same phrases a used verdict carries.
func TestAssumptionsWithoutARule(t *testing.T) {
	cases := map[string]string{
		`{service_name="checkout"} |= "x" != "y"`:                            "",
		`{service_name=~"check.*", pod="p"} |~ "a[0-9]+"`:                    "",
		`{service_name="$svc"} |= "x"`:                                       "uses a template variable",
		`{app="x"} |= "y"`:                                                   "names no scope label (service_name)",
		`{service_name="a"} | json | status >= 500`:                          "label filter status >= 500",
		`{service_name="a"} |= "$q"`:                                         "uses a template variable",
		`{service_name="a"} |~ "(?i)err"`:                                    "case-insensitive filter",
		`{service_name="a"} | line_format "{{.msg}}" |= "timeout"`:           "after the line is rewritten",
		`sum by (level) (count_over_time({service_name="a"} |> "<_>" [1m]))`: "pattern filter",
		`{$l=~"$v", service_name="a"}`:                                       "as its label name",
	}
	for q, want := range cases {
		pq, err := logql.Parse(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		got := strings.Join(Assumptions(pq.Selections[0], []string{"service_name"}), "; ")
		if want == "" && got != "" || want != "" && !strings.Contains(got, want) {
			t.Fatalf("%s: %q, want %q", q, got, want)
		}
	}
}

// Loki evaluates simplified case-insensitive literals with unicode.ToLower, which matches runes Go's
// (?i) does not: U+0130 lowercases to 'i'. A rule containing it must count as read by (?i)i.
func TestLokiLowerSemantics(t *testing.T) {
	r := Rule{ID: "dotted", Scope: map[string]string{"service_name": "x"},
		Language: automaton.MustCompile(`\A\x{130}\z`)}
	if regexp.MustCompile(`(?i)i`).MatchString("İ") {
		t.Fatal("precondition: Go (?i)i does not match U+0130")
	}
	if v := verdict(t, `{service_name="x"} |~ "(?i)i"`, r); !v.Used {
		t.Fatalf("(?i)i must count as reading U+0130 under Loki semantics: %+v", v)
	}
}

func TestReasonsMentionIgnored(t *testing.T) {
	v := verdict(t, `{service_name="checkout"} |> "<_>" |= "healthz"`, health)
	if !v.Used || !strings.Contains(v.Reason, "not modelled") {
		t.Fatalf("%+v", v)
	}
}

// unpack replaces the line with the packed _entry value, like line_format: a filter after it sees a
// different text, so it cannot exclude the rule's lines. Found by an external review against Loki.
func TestUnpackRewritesTheLine(t *testing.T) {
	packed := Rule{ID: "packed", Scope: map[string]string{"service_name": "checkout"},
		Language: automaton.MustCompile(`\A\{"_entry":"hello","x":"1"\}\z`)}
	for _, q := range []string{
		`{service_name="checkout"} | unpack != "_entry"`,
		`{service_name="checkout"} | unpack |= "hello"`,
		`{service_name="checkout"} | unpack !~ "x"`,
		`sum(count_over_time({service_name="checkout"} | unpack != "_entry" [5m]))`,
	} {
		if v := verdict(t, q, packed); !v.Used {
			t.Fatalf("%s: %s", q, v.Reason)
		}
	}
	// A filter before unpack still sees the original line.
	if v := verdict(t, `{service_name="checkout"} != "_entry" | unpack`, packed); v.Used {
		t.Fatalf("a filter before unpack excludes the packed line: %s", v.Reason)
	}
}

// Each of these keeps the rule's line in Loki 3.7.8, which turns the regex into substring filters
// that mean something else, so none may be decided as not reading it. The controls are shapes whose
// substring filters mean the same, and stay exact.
func TestRegexesLokiTurnsIntoSubstringFilters(t *testing.T) {
	rule := func(line string) Rule {
		return Rule{ID: "r", Scope: map[string]string{"service_name": "checkout"}, Language: automaton.MustCompile(`\A` + regexp.QuoteMeta(line) + `\z`)}
	}
	for _, c := range []struct{ query, line string }{
		{`{service_name="checkout"} !~ "GET.*(healthz|readyz)"`, "GET /healthz 200 3ms"},
		{`sum(count_over_time({service_name="checkout"} !~ "GET.*(healthz|readyz)" [5m]))`, "GET /healthz 200 3ms"},
		{`{service_name="checkout"} !~ "healthz|readyz|"`, "cache refreshed in 12ms"},
		{`{service_name="checkout"} !~ "probe(?:ok|.*passed)"`, "probe kube passed"},
		{`{service_name="checkout"} |~ "user(Created|Deleted)(Event|Command)"`, "userCreated id=42"},
		{`{service_name="checkout"} |~ "(?i:k)(?-i)ey=[0-9]+|K"`, "kafka lag"},
		{`{service_name="checkout"} |~ ".+"`, "\n"},
	} {
		if v := verdict(t, c.query, rule(c.line)); !v.Used {
			t.Errorf("%s decided as not reading %q: %s", c.query, c.line, v.Reason)
		}
	}
	for _, c := range []struct {
		query, line string
		used        bool
	}{
		{`{service_name="checkout"} |~ "healthz"`, "GET /readyz", false},
		{`{service_name="checkout"} |~ ".*healthz.*"`, "GET /readyz", false},
		{`{service_name="checkout"} |~ "healthz|readyz"`, "GET /livez", false},
		{`{service_name="checkout"} !~ "healthz|readyz"`, "GET /readyz", false},
		{`{service_name="checkout"} !~ "(healthz)"`, "GET /healthz", false},
		{`{service_name="checkout"} !~ "GET /[a-z]+z"`, "GET /readyz", false},
	} {
		v := verdict(t, c.query, rule(c.line))
		if v.Used != c.used || len(v.Widened) > 0 {
			t.Errorf("%s on %q: used %v (want %v), widened %v", c.query, c.line, v.Used, c.used, v.Widened)
		}
	}
}

// Loki matches a stream matcher's regex with a dot that also matches a newline, so a scope value with a
// newline in it is selected by check.+.
func TestStreamMatcherDotMatchesNewline(t *testing.T) {
	r := Rule{ID: "r", Scope: map[string]string{"service_name": "check\nout"}, Language: automaton.MustCompile(`\Ahello\z`)}
	if v := verdict(t, `{service_name=~"check.+"}`, r); !v.Used {
		t.Fatalf("decided as not reading: %s", v.Reason)
	}
	if v := verdict(t, `{service_name=~".+", service_name!~"check.+"}`, r); v.Used {
		t.Fatalf("a negated matcher that excludes the value reads it: %s", v.Reason)
	}
}

// After a variable stage, which may rewrite the line, a line filter excludes nothing; variable matchers
// only narrow, so the rest of the selector still decides; neither lets a rollup cover the query.
func TestVariablesGrafanaFillsIn(t *testing.T) {
	r := Rule{ID: "r", Scope: map[string]string{"service_name": "checkout"}, Language: automaton.MustCompile(`\Ahello\z`)}
	if v := verdict(t, `{service_name="checkout"} | $parser |= "zzz"`, r); !v.Used {
		t.Fatalf("a line filter after a variable stage excluded the rule: %s", v.Reason)
	}
	if v := verdict(t, `{$adhoc, service_name="checkout"} |= "zzz"`, r); v.Used {
		t.Fatalf("variable matchers made a filter that excludes the rule read it: %s", v.Reason)
	}
	if v := verdict(t, `{$adhoc, service_name="checkout"}`, r); !v.Used || len(v.Widened) == 0 {
		t.Fatalf("variable matchers must read as an assumption: %+v", v)
	}
	q, _ := logql.Parse(`sum(count_over_time({$adhoc, service_name="checkout"}[5m]))`)
	if Covers(q.Selections[0], r) {
		t.Fatal("a query with variable matchers covers every line of the rule")
	}
}
