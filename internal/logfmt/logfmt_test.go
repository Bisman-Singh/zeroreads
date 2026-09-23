package logfmt

import "testing"

func TestParseLokiQueryLine(t *testing.T) {
	line := `level=info ts=2026-09-23T18:24:30.996061957Z caller=metrics.go:285 component=frontend org_id=fake query="sum(count_over_time({service_name=\"checkout\"} |= \"healthz\" [5m]))" query_type=metric empty= flag`
	m, err := Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"level": "info", "ts": "2026-09-23T18:24:30.996061957Z", "caller": "metrics.go:285", "component": "frontend",
		"org_id": "fake", "query": `sum(count_over_time({service_name="checkout"} |= "healthz" [5m]))`,
		"query_type": "metric", "empty": "", "flag": "",
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("%s = %q, want %q", k, m[k], v)
		}
	}
	if len(m) != len(want) {
		t.Fatalf("got %d keys, want %d: %v", len(m), len(want), m)
	}
}

func TestParseEscapes(t *testing.T) {
	m, err := Parse(`q="a\\b \"c\" é\n"`)
	if err != nil {
		t.Fatal(err)
	}
	if m["q"] != "a\\b \"c\" é\n" {
		t.Fatalf("got %q", m["q"])
	}
}

func TestParseErrors(t *testing.T) {
	for _, l := range []string{`a="unterminated`, `a="x"junk`, `"k"=v`, `=v`} {
		if _, err := Parse(l); err == nil {
			t.Fatalf("%q parsed, want error", l)
		}
	}
}
