package topology

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// VectorConfig is a merged Vector configuration.
type VectorConfig struct {
	Sources    map[string]map[string]any
	Transforms map[string]map[string]any
	Sinks      map[string]map[string]any
}

// LoadVector merges Vector YAML files (later files win).
func LoadVector(files ...[]byte) (*VectorConfig, error) {
	merged := map[string]any{}
	for i, f := range files {
		var m map[string]any
		if err := yaml.Unmarshal(f, &m); err != nil {
			return nil, fmt.Errorf("topology: vector file %d: %w", i, err)
		}
		merged = mergeMaps(merged, m)
	}
	c := &VectorConfig{Sources: section(merged, "sources"), Transforms: section(merged, "transforms"), Sinks: section(merged, "sinks")}
	for id, t := range c.Transforms {
		if _, err := c.inputs(t); err != nil {
			return nil, fmt.Errorf("topology: transform %s: %w", id, err)
		}
	}
	for id, s := range c.Sinks {
		if _, err := c.inputs(s); err != nil {
			return nil, fmt.Errorf("topology: sink %s: %w", id, err)
		}
	}
	return c, nil
}

func section(m map[string]any, k string) map[string]map[string]any {
	out := map[string]map[string]any{}
	for id, v := range asMap(m[k]) {
		out[id] = asMap(v)
	}
	return out
}

func (c *VectorConfig) inputs(comp map[string]any) ([]string, error) {
	return stringList(comp["inputs"])
}

// consumes reports whether an input reference selects component id: exact, a named output of it
// ("id.output"), or a glob pattern matching either.
func consumes(ref, id string) bool {
	if ref == id || strings.HasPrefix(ref, id+".") {
		return true
	}
	if strings.ContainsAny(ref, "*?[") {
		if ok, _ := path.Match(ref, id); ok {
			return true
		}
		base := strings.SplitN(ref, ".", 2)[0]
		if ok, _ := path.Match(base, id); ok {
			return true
		}
	}
	return false
}

// Consumers lists the transforms and sinks that take id as an input.
func (c *VectorConfig) Consumers(id string) (transforms, sinks []string) {
	for tid, t := range c.Transforms {
		in, _ := c.inputs(t)
		for _, ref := range in {
			if consumes(ref, id) {
				transforms = append(transforms, tid)
				break
			}
		}
	}
	for sid, s := range c.Sinks {
		in, _ := c.inputs(s)
		for _, ref := range in {
			if consumes(ref, id) {
				sinks = append(sinks, sid)
				break
			}
		}
	}
	sort.Strings(transforms)
	sort.Strings(sinks)
	return transforms, sinks
}

// VectorDownstream returns every sink reachable from component id, with a path to each, and the
// log_to_metric transforms on the way (they turn logs into metrics: counting consumers).
func (c *VectorConfig) VectorDownstream(id string) (map[string][]string, []string, error) {
	if _, ok := c.Sources[id]; !ok {
		if _, ok := c.Transforms[id]; !ok {
			return nil, nil, fmt.Errorf("topology: vector component %s not found", id)
		}
	}
	sinks := map[string][]string{}
	var derived []string
	seen := map[string]bool{}
	var walk func(from string, pathSoFar []string)
	walk = func(from string, pathSoFar []string) {
		if seen[from] {
			return
		}
		seen[from] = true
		ts, ss := c.Consumers(from)
		for _, s := range ss {
			if _, dup := sinks[s]; !dup {
				sinks[s] = append(append([]string(nil), pathSoFar...), from+"->"+s)
			}
		}
		for _, t := range ts {
			if typ, _ := c.Transforms[t]["type"].(string); typ == "log_to_metric" && !contains(derived, t) {
				derived = append(derived, t)
			}
			walk(t, append(append([]string(nil), pathSoFar...), from+"->"+t))
		}
	}
	walk(id, nil)
	sort.Strings(derived)
	return sinks, derived, nil
}
