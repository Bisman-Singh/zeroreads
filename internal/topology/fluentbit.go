package topology

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Bisman-Singh/zeroreads/internal/automaton"
)

// FluentBitConfig is a merged Fluent Bit YAML configuration.
type FluentBitConfig struct {
	Filters []map[string]any
	Outputs []map[string]any
}

// LoadFluentBit merges Fluent Bit YAML files (later files win; lists are replaced).
func LoadFluentBit(files ...[]byte) (*FluentBitConfig, error) {
	merged, err := MergeFiles("fluent bit", files)
	if err != nil {
		return nil, err
	}
	p := asMap(merged["pipeline"])
	c := &FluentBitConfig{}
	for _, x := range asList(p["filters"]) {
		c.Filters = append(c.Filters, lowerKeys(asMap(x)))
	}
	for _, x := range asList(p["outputs"]) {
		c.Outputs = append(c.Outputs, lowerKeys(asMap(x)))
	}
	return c, nil
}

// lowerKeys lower-cases a plugin's property names: Fluent Bit reads them case-insensitively, so
// Match and match are the same property.
func lowerKeys(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}
	return out
}

func asList(v any) []any { l, _ := v.([]any); return l }

// ID names a Fluent Bit plugin instance: its alias, else name#index.
func ID(m map[string]any, i int) string {
	if a, ok := m["alias"].(string); ok && a != "" {
		return a
	}
	return fmt.Sprintf("%v#%d", m["name"], i)
}

// tagMatcher returns the plugin's tag language as an anchored RE2 pattern. ok is false when it cannot
// be modelled, in which case callers must assume it matches every tag.
func tagMatcher(m map[string]any) (string, bool) {
	if re, ok := m["match_regex"].(string); ok && re != "" {
		if _, err := regexp.Compile(re); err != nil {
			return "", false
		}
		return re, true
	}
	if g, ok := m["match"].(string); ok && g != "" {
		return automaton.Glob(g), true
	}
	return "", true // no match: the plugin receives nothing
}

// intersects reports whether two tag languages can share a tag; "" is a plugin that receives none.
func intersects(a, b string) bool { return b != "" && automaton.Overlap(a, b) }

// OutputsReceiving returns the outputs that can receive a record carrying exactly tag; an output
// whose tag matching cannot be modelled is assumed to receive it.
func (c *FluentBitConfig) OutputsReceiving(tag string) []string {
	exact := automaton.Glob(tag)
	var out []string
	for i, o := range c.Outputs {
		if re, ok := tagMatcher(o); !ok || intersects(exact, re) {
			out = append(out, ID(o, i))
		}
	}
	sort.Strings(out)
	return out
}

// GlobMatches reports whether a Fluent Bit Match glob matches tag.
func GlobMatches(glob, tag string) bool {
	return automaton.Overlap(automaton.Glob(glob), automaton.Glob(tag))
}

// FluentBitDownstream returns the outputs that can receive records tagged by match after the filter
// aliased after, and the filters after that point that re-emit (rewrite_tag) or count
// (log_to_metrics) those records.
func (c *FluentBitConfig) FluentBitDownstream(match, after string) (outputs map[string]string, derived []string, err error) {
	start := 0
	if after != "" {
		start = -1
		for i, f := range c.Filters {
			if f["alias"] == after {
				start = i + 1
			}
		}
		if start < 0 {
			return nil, nil, fmt.Errorf("topology: no filter with alias %s", after)
		}
	}
	tags := automaton.Glob(match)
	for i, f := range c.Filters[start:] {
		name, _ := f["name"].(string)
		if !strings.EqualFold(name, "rewrite_tag") && !strings.EqualFold(name, "log_to_metrics") {
			continue
		}
		re, ok := tagMatcher(f)
		if !ok || intersects(tags, re) {
			derived = append(derived, ID(f, start+i))
		}
	}
	outputs = map[string]string{}
	for i, o := range c.Outputs {
		re, ok := tagMatcher(o)
		if !ok || intersects(tags, re) {
			outputs[ID(o, i)] = fmt.Sprint(o["name"])
		}
	}
	sort.Strings(derived)
	return outputs, derived, nil
}
