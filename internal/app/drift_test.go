package app

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTemplateLanguage(t *testing.T) {
	c := &Config{}
	c.Drain.MaskingRules = append(c.Drain.MaskingRules, struct {
		Name    string `yaml:"name"`
		Pattern string `yaml:"pattern"`
	}{"ip", `\d+\.\d+\.\d+\.\d+`})
	re := regexp.MustCompile(c.templateLanguage("GET <*> from <ip> took <*> (a.b) <other> ip=<ip>,port"))
	for s, want := range map[string]bool{
		"GET /x from 10.0.0.1 took 5ms (a.b) <other> ip=1.2.3.4,port":          true,
		"GET /x from literal <ip> text took 5ms (a.b) <other> ip=1.2.3.4,port": true, // a mask may span spaces
		"GET /x y from 10.0.0.1 took 5ms (a.b) <other> ip=1.2.3.4,port":        false,
		"GET /x from 10.0.0.1 took 5ms (aXb) <other> ip=1.2.3.4,port":          false, // literals are quoted
		"GET /x from 10.0.0.1 took 5ms (a.b) <other> ip=,port":                 false,
		"GET /x from 10.0.0.1 took 5ms (a.b) other ip=1.2.3.4,port":            false,
		"xGET /x from 10.0.0.1 took 5ms (a.b) <other> ip=1.2.3.4,port":         false,
	} {
		if re.MatchString(s) != want {
			t.Fatalf("%q: got %v", s, !want)
		}
	}
}

func TestDiffPaths(t *testing.T) {
	var d []string
	diffPaths("", map[string]any{"a": map[string]any{"b": 1, "c": []any{"x"}}, "k": 1},
		map[string]any{"a": map[string]any{"b": 2, "c": []any{"x"}, "extra": 1}}, &d)
	got := strings.Join(d, "|")
	if got != "a.b: differs|a.extra: not in the emitted config|k: missing from the deployed config" {
		t.Fatal(got)
	}
}

func TestDrainConfigHash(t *testing.T) {
	a := &Config{}
	b := &Config{}
	if a.DrainConfigHash() != b.DrainConfigHash() {
		t.Fatal("same config, different hash")
	}
	b.Drain.SeedTemplates = []string{"x <*>"}
	if a.DrainConfigHash() == b.DrainConfigHash() {
		t.Fatal("seed change not reflected")
	}
}

func TestSplitAndFirstMask(t *testing.T) {
	start, end := time.Unix(0, 0), time.Unix(0, 1000)
	ws := split(start, end, 3)
	if len(ws) != 3 || !ws[0].Start.Equal(start) || !ws[2].End.Equal(end) || !ws[0].End.Equal(ws[1].Start) || !ws[1].End.Equal(ws[2].Start) {
		t.Fatalf("%+v", ws)
	}
	masks := map[string]bool{"<ip>": true, "<ipv6>": true, "<num>": true}
	for tok, want := range map[string][2]any{"a=<ipv6>": {2, "<ipv6>"}, "<num>/<ip>": {0, "<num>"}, "plain": {-1, ""}} {
		if at, name := firstMask(tok, masks); at != want[0] || name != want[1] {
			t.Fatalf("%s: %d %s", tok, at, name)
		}
	}
}
