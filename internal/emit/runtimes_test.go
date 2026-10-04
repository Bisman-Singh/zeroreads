package emit

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Structural checks of the Vector and Fluent Bit emitters that need no engine; the docker tests
// check the emitted configurations against the real engines.

const vectorUnit = `
sources:
  in: {type: stdin}
transforms:
  prep: {type: remap, inputs: [in], source: ".x = 1"}
sinks:
  out: {type: console, inputs: [prep], encoding: {codec: json}}
  side: {type: console, inputs: [in], encoding: {codec: json}}
`

func vtarget() VectorTarget {
	return VectorTarget{After: "prep", ScopePath: ".service", TextPath: ".message", FieldPaths: map[string]string{"orders": ".body.msg"},
		MeasureSink: map[string]any{"type": "blackhole"}}
}

func TestVectorWiring(t *testing.T) {
	for _, mode := range []Mode{Shadow, Enforce} {
		out, err := Vector([][]byte{[]byte(vectorUnit)}, vtarget(), testRules, mode)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Transforms map[string]map[string]any `yaml:"transforms"`
			Sinks      map[string]map[string]any `yaml:"sinks"`
		}
		if err := yaml.Unmarshal(out, &cfg); err != nil {
			t.Fatal(err)
		}
		in := func(m map[string]any) string {
			var s []string
			for _, x := range m["inputs"].([]any) {
				s = append(s, x.(string))
			}
			return strings.Join(s, ",")
		}
		if in(cfg.Sinks["side"]) != "in" {
			t.Fatalf("%s: a sink not downstream of prep was rewired: %v", mode, cfg.Sinks["side"])
		}
		if _, ok := cfg.Sinks[vSink]; !ok {
			t.Fatalf("%s: no measurement sink", mode)
		}
		_, enforcing := cfg.Transforms[vEnforce]
		if enforcing != (mode == Enforce) {
			t.Fatalf("%s: enforce transform present=%v", mode, enforcing)
		}
		if mode == Enforce {
			if in(cfg.Sinks["out"]) != vClean {
				t.Fatalf("enforce: out reads %s, want %s", in(cfg.Sinks["out"]), vClean)
			}
			src := cfg.Transforms[vEnforce]["source"].(string)
			for _, r := range testRules {
				if !strings.Contains(src, `"`+r.ID+`"`) && r.Action != "dedupe" {
					t.Fatalf("enforce source misses %s", r.ID)
				}
			}
			if _, ok := cfg.Transforms[vReduce]; !ok {
				t.Fatal("dedupe rule without a reduce")
			}
		} else if in(cfg.Sinks["out"]) != "prep" {
			t.Fatalf("shadow must not change what out reads: %s", in(cfg.Sinks["out"]))
		}
	}
}

func TestVectorRefusals(t *testing.T) {
	cases := map[string]func() error{
		"no measure sink": func() error {
			tg := vtarget()
			tg.MeasureSink = nil
			_, err := Vector([][]byte{[]byte(vectorUnit)}, tg, testRules, Enforce)
			return err
		},
		"unknown after": func() error {
			tg := vtarget()
			tg.After = "nope"
			_, err := Vector([][]byte{[]byte(vectorUnit)}, tg, testRules, Enforce)
			return err
		},
		"structured without path": func() error {
			tg := vtarget()
			tg.FieldPaths = nil
			_, err := Vector([][]byte{[]byte(vectorUnit)}, tg, testRules, Enforce)
			return err
		},
		"name taken": func() error {
			_, err := Vector([][]byte{[]byte(vectorUnit + "  " + vSink + ": {type: blackhole, inputs: [in]}\n")}, vtarget(), testRules, Enforce)
			return err
		},
		"unknown action": func() error {
			_, err := Vector([][]byte{[]byte(vectorUnit)}, vtarget(), []Rule{{ID: "r-x", ScopeAttr: "s", ScopeValue: "a", Language: `\Ax\z`, Action: "teleport"}}, Enforce)
			return err
		},
		"overlapping rules": func() error {
			_, err := Vector([][]byte{[]byte(vectorUnit)}, vtarget(), []Rule{
				{ID: "r-a", ScopeValue: "s", Language: `\Ax+\z`, Action: "drop"}, {ID: "r-b", ScopeValue: "s", Language: `\Axx\z`, Action: "drop"}}, Enforce)
			return err
		},
	}
	for name, f := range cases {
		if f() == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

const fluentBitUnit = `
pipeline:
  inputs:
    - {name: stdin, tag: app}
  filters:
    - {name: modify, match: app, alias: prep, add: x 1}
  outputs:
    - {name: stdout, match: app}
    - {name: stdout, match: zeroreads.metrics}
`

func fbTarget() FluentBitTarget {
	return FluentBitTarget{Match: "app", After: "prep", ScopeKey: "service", TextKey: []string{"text"},
		FieldKeys: map[string][]string{"orders": {"body", "msg"}}, MetricsTag: "zeroreads.metrics"}
}

func TestFluentBitWiring(t *testing.T) {
	rules := fbRules()
	for _, mode := range []Mode{Shadow, Enforce} {
		out, err := FluentBit([][]byte{[]byte(fluentBitUnit)}, fbTarget(), rules, mode)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Pipeline struct {
				Filters []map[string]any `yaml:"filters"`
			} `yaml:"pipeline"`
		}
		if err := yaml.Unmarshal(out, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Pipeline.Filters[0]["alias"] != "prep" {
			t.Fatalf("%s: zeroreads filters must run after prep: %v", mode, cfg.Pipeline.Filters[0])
		}
		text := string(out)
		if !strings.Contains(text, "log_to_metrics") {
			t.Fatalf("%s: no measurement", mode)
		}
		enforcing := strings.Contains(text, "grep") || strings.Contains(text, "zeroreads_sample")
		if enforcing != (mode == Enforce) {
			t.Fatalf("%s: enforcement present=%v\n%s", mode, enforcing, text)
		}
		// Fluent Bit splits "regex: KEY PATTERN" on whitespace: the pattern must hold none.
		for _, line := range strings.Split(text, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && (k == "regex" || k == "exclude") && len(strings.Fields(v)) != 2 {
				t.Fatalf("a regex argument does not split into key and pattern: %s", line)
			}
		}
	}
	for name, f := range map[string]func() error{
		"dedupe": func() error {
			_, err := FluentBit([][]byte{[]byte(fluentBitUnit)}, fbTarget(), testRules, Enforce)
			return err
		},
		"no alias": func() error {
			tg := fbTarget()
			tg.After = "nope"
			_, err := FluentBit([][]byte{[]byte(fluentBitUnit)}, tg, rules, Enforce)
			return err
		},
		"no metrics tag": func() error {
			tg := fbTarget()
			tg.MetricsTag = ""
			_, err := FluentBit([][]byte{[]byte(fluentBitUnit)}, tg, rules, Enforce)
			return err
		},
		"structured without keys": func() error {
			tg := fbTarget()
			tg.FieldKeys = nil
			_, err := FluentBit([][]byte{[]byte(fluentBitUnit)}, tg, rules, Enforce)
			return err
		},
	} {
		if f() == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// fbRules is testRules without dedupe, which Fluent Bit cannot do.
func fbRules() []Rule {
	var out []Rule
	for _, r := range testRules {
		if r.Action != "dedupe" {
			out = append(out, r)
		}
	}
	return out
}

func TestVRLString(t *testing.T) {
	for in, want := range map[string]string{
		`checkout`:       `"checkout"`,
		`a"b\c`:          `"a\"b\\c"`,
		`svc${SECRET}`:   `"svc\u{24}\{SECRET}"`,
		`$HOME`:          `"\u{24}HOME"`,
		`a{{ x }}b`:      `"a\{\{ x }}b"`,
		"tab\tnew\nline": `"tab\u{9}new\u{a}line"`,
		"café ☕":         `"caf\u{e9} \u{2615}"`,
	} {
		if got := vrlString(in); got != want {
			t.Fatalf("%q: %s, want %s", in, got, want)
		}
	}
}

func TestFluentBitRefusesCounts(t *testing.T) {
	for _, action := range []string{"dedupe", "rollup"} {
		_, err := FluentBit([][]byte{[]byte(fluentBitUnit)}, fbTarget(), []Rule{{ID: "r-x", ScopeValue: "a", Language: `\Ax\z`, Action: action}}, Enforce)
		if err == nil || !strings.Contains(err.Error(), "cannot enforce "+action) {
			t.Fatalf("%s: %v", action, err)
		}
		if _, err := FluentBit([][]byte{[]byte(fluentBitUnit)}, fbTarget(), []Rule{{ID: "r-x", ScopeValue: "a", Language: `\Ax\z`, Action: action}}, Shadow); err != nil {
			t.Fatalf("%s in shadow mode only measures: %v", action, err)
		}
	}
}

func TestFluentBitFindsCapitalisedAlias(t *testing.T) {
	cfg := strings.ReplaceAll(fluentBitUnit, "{name: modify, match: app, alias: prep, add: x 1}", "{Name: modify, Match: app, Alias: prep, Add: x 1}")
	out, err := FluentBit([][]byte{[]byte(cfg)}, fbTarget(), fbRules(), Shadow)
	if err != nil {
		t.Fatal(err)
	}
	if i, j := strings.Index(string(out), "Alias: prep"), strings.Index(string(out), "zeroreads_tag_"); i < 0 || j < i {
		t.Fatalf("rules are not wired after the capitalised alias:\n%s", out)
	}
}
