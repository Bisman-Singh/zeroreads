package logql

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Every stage that can narrow a selection without being modelled is named, so a verdict can say what
// it assumed. The rollup-marker filter is modelled (NoRollups) and parsers narrow nothing.
func TestUnmodelledStages(t *testing.T) {
	q, err := Parse(`{a="b"} |= "x" | json | level="info" | line_format "y" |= "z" | sievelog_rule=""`)
	if err != nil {
		t.Fatal(err)
	}
	sel := q.Selections[0]
	want := `label filter level = "info"|line filter |= "z" after the line is rewritten`
	if got := strings.Join(sel.Unmodelled, "|"); got != want || !sel.NoRollups || len(sel.Stages) != 1 {
		t.Fatalf("unmodelled %q (want %q), no rollups %v, stages %d", got, want, sel.NoRollups, len(sel.Stages))
	}
	q, err = Parse(`sum(count_over_time({a="b"} |= "x" | logfmt [5m]))`)
	if err != nil {
		t.Fatal(err)
	}
	if u := q.Selections[0].Unmodelled; len(u) != 0 {
		t.Fatalf("a parser alone narrows nothing: %q", u)
	}
}

// summary renders a parsed query compactly so tests can compare it with an expected string.
func summary(q *Query) string {
	var parts []string
	for _, s := range q.Selections {
		var b strings.Builder
		for i, m := range s.Matchers {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, "%s%s%q", m.Name, m.Op, m.Value)
		}
		b.WriteString(" |")
		for _, st := range s.Stages {
			if st.Negative {
				b.WriteString(" NOT")
			}
			var alts []string
			for _, a := range st.Alternatives {
				alts = append(alts, a.Kind+":"+a.Value)
			}
			b.WriteString(" [" + strings.Join(alts, " or ") + "]")
		}
		if s.Counting {
			b.WriteString(" #count")
		}
		if s.Rewritten {
			b.WriteString(" #rewritten")
		}
		parts = append(parts, b.String())
	}
	return strings.Join(parts, " ;; ")
}

func TestParse(t *testing.T) {
	cases := []struct{ q, want string }{
		{`{service_name="checkout"}`, `service_name="checkout" |`},
		{`{a="b", c!="d", e=~"f.*", g!~"h"}`, `a="b",c!="d",e=~"f.*",g!~"h" |`},
		{`{a="b"} |= "x" != "y" |~ "z+" !~ "w"`, `a="b" | [contains:x] NOT [contains:y] [regex:z+] NOT [regex:w]`},
		{`{a="b"} |= "x" or "y" or "z"`, `a="b" | [contains:x or contains:y or contains:z]`},
		{`{a="b"} != "x" or "y"`, `a="b" | NOT [contains:x or contains:y]`},
		{`{a="b"} |> "<_> error <_>" !> "debug <_>"`, `a="b" | [pattern:<_> error <_>] NOT [pattern:debug <_>]`},
		{`{a="b"} |= ip("10.0.0.0/8")`, `a="b" | [ip:10.0.0.0/8]`},
		{`{a="b"} | json | level="error" |= "x"`, `a="b" | [contains:x]`},
		{`{a="b"} | logfmt --strict --keep-empty | status >= 500 and duration > 1s or bytes < 10KB`, `a="b" |`},
		{`{a="b"} | json first="a.b", second | line_format "{{.x}}" |= "after"`, `a="b" | #rewritten`},
		{`{a="b"} |= "before" | decolorize |= "after"`, `a="b" | [contains:before] #rewritten`},
		{`{a="b"} | regexp "(?P<x>\\w+)" | pattern "<ip> <_>"`, `a="b" |`},
		{`{a="b"} | unpack`, `a="b" | #rewritten`}, // unpack replaces the line with _entry
		{`{a="b"} |= "x" | unpack != "y"`, `a="b" | [contains:x] #rewritten`},
		{`{a="b"} | label_format x=y, z="{{.w}}" | drop a, b="c" | keep d`, `a="b" |`},
		{`{a="b"} | level="error" status="500"`, `a="b" |`},
		{`{a="b"} | (a="x" or b!="y"), c=~"z"`, `a="b" |`},
		{`{a="b"} | addr = ip("10.0.0.1")`, `a="b" |`},
		{"{a=`raw\\n`} |= `x\\d`", `a="raw\\n" | [contains:x\d]`},
		{`{a='single'} |= 'q'`, `a="single" | [contains:q]`},
		{"{a=\"b\"} # comment\n |= \"x\"", `a="b" | [contains:x]`},
		{`count_over_time({a="b"} |= "x" [5m])`, `a="b" | [contains:x] #count`},
		{`count_over_time({a="b"}[5m] offset 1h |= "x")`, `a="b" | [contains:x] #count`},
		{`rate(({a="b"} |= "x")[1m])`, `a="b" | [contains:x] #count`},
		{`absent_over_time({a="b"}[10m])`, `a="b" | #count`},
		{`sum by (x) (rate({a="b"} | json | unwrap bytes(size) | __error__="" [1m]))`, `a="b" | #count`},
		{`quantile_over_time(0.99, {a="b"} | logfmt | unwrap duration [5m]) by (host)`, `a="b" | #count`},
		{`topk(10, sum(count_over_time({a="b"}[1h])) by (c))`, `a="b" | #count`},
		{`sum(rate({a="b"}[1m])) / sum(rate({a="b"} |= "error"[1m])) > bool 0.1`, `a="b" | #count ;; a="b" | [contains:error] #count`},
		{`sum(rate({a="b"}[1m])) / on(x) group_left(y) sum(rate({c="d"}[1m]))`, `a="b" | #count ;; c="d" | #count`},
		{`label_replace(rate({a="b"}[1m]), "dst", "$1", "src", "(.*)")`, `a="b" | #count`},
		{`sum(rate({a="b"}[1m])) or vector(0)`, `a="b" | #count`},
		{`-sum(rate({a="b"}[1m])) ^ 2 ^ 3`, `a="b" | #count`},
		{`variants(count_over_time({a="b"}[1m]), bytes_over_time({a="b"}[1m])) of ({a="b"} |= "x" [1m])`, `a="b" | #count ;; a="b" | #count ;; a="b" | [contains:x] #count`},
		{`sort_desc(sum by (a) (count_over_time({a="b"}[5m])))`, `a="b" | #count`},
		{`{a="b"} | json | duration > -1s`, `a="b" |`},
		{`{a!="b", c=~".+"}`, `a!="b",c=~".+" |`},
		{`{a="", c="d"}`, `a="",c="d" |`},
	}
	for _, c := range cases {
		q, err := Parse(c.q)
		if err != nil {
			t.Fatalf("%s: %v", c.q, err)
		}
		if got := summary(q); got != c.want {
			t.Fatalf("%s:\n got %s\nwant %s", c.q, got, c.want)
		}
	}
}

// Queries Loki rejects must not parse, so a malformed query is never analysed as if it were valid.
func TestParseRejects(t *testing.T) {
	for _, q := range []string{
		``,
		`{a="b"`,
		`{a=b}`,
		`{a="b"} |= x`,
		`{a="b"}[5m]`,
		`count_over_time({a="b"})`,
		`{a="b"} | unwrap x`,
		`{a="b"} |= "unterminated`,
		`{a="b"} | line_format`,
		`{a="b"} $var`,
		`sum(rate({a="b"}[1m]) by (x)`,
		"{a=\"b\"} |= \"\xff\"",
		`{a="b"} | logfmt --bogus`,
		`rate(({a="b"} |= "x"[1m])`,
		`{a!="b"}`,
		`{a=~".*"}`,
		`{a=""}`,
		`{a!~"x", b!="y"}`,
	} {
		if _, err := Parse(q); err == nil {
			t.Fatalf("%q parsed, want error", q)
		}
	}
}

func TestLexNumbers(t *testing.T) {
	for _, c := range []struct {
		in   string
		kind tokKind
	}{
		{"5m", tDuration}, {"1h30m", tDuration}, {"100ms", tDuration}, {"1.5s", tDuration}, {"2d", tDuration},
		{"10KB", tBytes}, {"1.5MiB", tBytes}, {"20B", tBytes},
		{"42", tNumber}, {"0.99", tNumber}, {"1e3", tNumber},
	} {
		toks, err := lex(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if toks[0].kind != c.kind || toks[0].text != c.in {
			t.Fatalf("%s: got kind %d text %q", c.in, toks[0].kind, toks[0].text)
		}
	}
}

func TestCanonical(t *testing.T) {
	same := [][2]string{
		{`sum(count_over_time({a="b"} |= "x" [5m])) > 100`, `(sum(count_over_time({a="b"} |= "x"[5m])) > 100)`}, // ruler form
		{`sum(count_over_time({a="b"} |= "x" [1h]))`, `sum(count_over_time({a="b"} |= "x"[1h] offset 2h0m0s))`}, // a time split
		{"{a=`b`} |~ `x.y`", `{a="b"} |~ "x.y"`},
		{`{a="b"}`, `  { a = "b" }  `},
	}
	for _, p := range same {
		if Canonical(p[0]) != Canonical(p[1]) {
			t.Fatalf("%q and %q should be one query: %q vs %q", p[0], p[1], Canonical(p[0]), Canonical(p[1]))
		}
	}
	different := [][2]string{
		{`sum(count_over_time({a="b"}[5m]))`, `sum(count_over_time({a="b"}[1h]))`},
		{`{a="b"} |= "x"`, `{a="b"} |= "X"`},
		{`{a="b"} |= "offset"`, `{a="b"}`},
	}
	for _, p := range different {
		if Canonical(p[0]) == Canonical(p[1]) {
			t.Fatalf("%q and %q must stay different", p[0], p[1])
		}
	}
}

// Query text comes from anyone who can save a dashboard. Found by the v1 audit: Canonical stripped
// parentheses in quadratic time (5 s for 50,000 levels) and nothing bounded the text.
func TestParseIsBounded(t *testing.T) {
	half := MaxQueryBytes/2 - 16
	for name, q := range map[string]string{
		"parentheses":      strings.Repeat("(", half) + `{a="b"}` + strings.Repeat(")", half),
		"aggregation":      "sum" + strings.Repeat("(", half-2) + `count_over_time({a="b"}[5m])` + strings.Repeat(")", half-2),
		"unary":            strings.Repeat("-", MaxQueryBytes-8) + `1`,
		"label filters":    `{a="b"} | ` + strings.Repeat("(", half/2) + `x="1"` + strings.Repeat(")", half/2),
		"alternatives":     `{a="b"} |= "x"` + strings.Repeat(` or "x"`, MaxQueryBytes/8),
		"binary operators": strings.Repeat(`count_over_time({a="b"}[1m]) + `, MaxQueryBytes/40) + `1`,
	} {
		if len(q) > MaxQueryBytes {
			q = q[:MaxQueryBytes]
		}
		start := time.Now()
		Parse(q)
		Canonical(q)
		// Quadratic stripping took 5.2 s at 50,000 levels, so about 34 s at this size; linear takes well
		// under a second. The bound sits between, wide enough for a loaded machine.
		if d := time.Since(start); d > 15*time.Second {
			t.Fatalf("%s: %d bytes took %v", name, len(q), d)
		}
	}
	if _, err := Parse(`{a="b"}` + strings.Repeat(" ", MaxQueryBytes)); err == nil {
		t.Fatal("a query longer than the bound parsed")
	}
	if got := Canonical(`((({a="b"})))`); got != `{ a = "b" }` {
		t.Fatalf("canonical %q", got)
	}
	if got := Canonical(`({a="b"}) or ({c="d"})`); got != `( { a = "b" } ) or ( { c = "d" } )` {
		t.Fatalf("canonical %q", got)
	}
}
