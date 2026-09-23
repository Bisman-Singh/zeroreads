package usage

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
	"github.com/Bisman-Singh/sievelog/internal/logql"
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
		{`{service_name!="checkout"}`, health, false},
		{`{service_name!~"auth|orders"}`, health, true},
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
