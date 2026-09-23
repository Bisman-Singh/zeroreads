package topology

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
)

// FluentBitConfig is a merged Fluent Bit YAML configuration.
type FluentBitConfig struct {
	Filters []map[string]any
	Outputs []map[string]any
}

// LoadFluentBit merges Fluent Bit YAML files (later files win; lists are replaced).
func LoadFluentBit(files ...[]byte) (*FluentBitConfig, error) {
	merged := map[string]any{}
	for i, f := range files {
		var m map[string]any
		if err := yaml.Unmarshal(f, &m); err != nil {
			return nil, fmt.Errorf("topology: fluent bit file %d: %w", i, err)
		}
		merged = mergeMaps(merged, m)
	}
	p := asMap(merged["pipeline"])
	c := &FluentBitConfig{}
	for _, x := range asList(p["filters"]) {
		c.Filters = append(c.Filters, asMap(x))
	}
	for _, x := range asList(p["outputs"]) {
		c.Outputs = append(c.Outputs, asMap(x))
	}
	return c, nil
}

func asList(v any) []any { l, _ := v.([]any); return l }

// ID names a Fluent Bit plugin instance: its alias, else name#index.
func ID(m map[string]any, i int) string {
	if a, ok := m["alias"].(string); ok && a != "" {
		return a
	}
	return fmt.Sprintf("%v#%d", m["name"], i)
}

// globRegex turns a Fluent Bit tag wildcard pattern into an anchored RE2 pattern.
func globRegex(g string) string {
	var b strings.Builder
	b.WriteString(`\A`)
	for _, r := range g {
		if r == '*' {
			b.WriteString(`.*`)
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	b.WriteString(`\z`)
	return b.String()
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
		return globRegex(g), true
	}
	return "", true // no match: the plugin receives nothing
}

func intersects(a, b string) bool {
	if b == "" {
		return false
	}
	pa, err1 := automaton.Compile(a)
	pb, err2 := automaton.Compile(b)
	if err1 != nil || err2 != nil {
		return true
	}
	_, found, err := automaton.Intersects(pa, pb, 0)
	return err != nil || found
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
	tags := globRegex(match)
	for i, f := range c.Filters[start:] {
		name, _ := f["name"].(string)
		if name != "rewrite_tag" && name != "log_to_metrics" {
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
