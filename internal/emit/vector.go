package emit

import (
	"fmt"
	"math/big"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Bisman-Singh/sievelog/internal/dialect"
	"github.com/Bisman-Singh/sievelog/internal/topology"
)

// VectorTarget is where in a Vector configuration rules are enforced.
type VectorTarget struct {
	After      string            // component whose output the rules act on
	ScopePath  string            // VRL path of the scope value, e.g. .service
	TextPath   string            // VRL path of the templated text for plain logs, e.g. .message
	FieldPaths map[string]string // service -> VRL path of the templated field for structured logs
	GroupBy    []string          // extra reduce keys for dedupe, e.g. kubernetes.pod_name
	// MeasureSink is a complete sink definition (type and options) that receives the per-rule metrics.
	MeasureSink map[string]any
	DedupeMS    int
}

// Vector component names this package adds.
const (
	vTag        = "sievelog_tag"
	vMeasure    = "sievelog_measure"
	vMeasureAgg = "sievelog_measure_aggregate"
	vSink       = "sievelog_metrics"
	vEnforce    = "sievelog_enforce"
	vRoute      = "sievelog_route"
	vReduce     = "sievelog_dedupe"
	vClean      = "sievelog_clean"
)

// VectorSampleThreshold is the integer below which the first 15 hex digits of the SHA-256 of a
// line's sample key must fall for the line to be kept.
func VectorSampleThreshold(keep int) int64 {
	span := new(big.Int).Lsh(big.NewInt(1), 60) // 15 hex digits
	k := new(big.Int).Mul(span, big.NewInt(int64(keep)))
	return k.Div(k, big.NewInt(100)).Int64()
}

// vrlString quotes s as a VRL string literal. Only printable ASCII is accepted: VRL's escapes differ
// from Go's, and scope values and rule IDs never need more.
func vrlString(s string) string {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			panic(fmt.Sprintf("emit: %q is not printable ASCII", s))
		}
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func checkVRLSafe(rules []Rule) error {
	for _, r := range rules {
		for _, s := range []string{r.ID, r.ScopeValue} {
			for _, c := range s {
				if c < 0x20 || c > 0x7e {
					return fmt.Errorf("emit: %q contains characters Vector output does not support", s)
				}
			}
		}
	}
	return nil
}

func (t VectorTarget) textPath(r Rule) (string, error) {
	if r.Field == "" {
		return t.TextPath, nil
	}
	p, ok := t.FieldPaths[r.ScopeValue]
	if !ok {
		return "", fmt.Errorf("emit: no vector field path for structured service %s", r.ScopeValue)
	}
	return p, nil
}

// Vector returns the user's Vector configuration with the rules wired in after t.After. Shadow mode
// adds only the tagging and measurement branch; enforce mode also rewires every consumer of
// t.After to read from the enforcement chain.
func Vector(files [][]byte, t VectorTarget, rules []Rule, mode Mode) ([]byte, error) {
	if err := CheckDisjoint(rules); err != nil {
		return nil, err
	}
	if err := checkVRLSafe(rules); err != nil {
		return nil, err
	}
	if t.ScopePath == "" || t.TextPath == "" || t.MeasureSink == nil {
		return nil, fmt.Errorf("emit: vector target needs scope path, text path and a measure sink")
	}
	topo, err := topology.LoadVector(files...)
	if err != nil {
		return nil, err
	}
	if _, ok := topo.Transforms[t.After]; !ok {
		if _, ok := topo.Sources[t.After]; !ok {
			return nil, fmt.Errorf("emit: vector component %s not found", t.After)
		}
	}
	cfg := map[string]any{}
	for i, f := range files {
		var m map[string]any
		if err := yaml.Unmarshal(f, &m); err != nil {
			return nil, fmt.Errorf("emit: vector file %d: %w", i, err)
		}
		cfg = merge(cfg, m)
	}
	transforms, sinks := child(cfg, "transforms"), child(cfg, "sinks")
	for _, n := range []string{vTag, vMeasure, vMeasureAgg, vEnforce, vRoute, vReduce, vClean} {
		if _, taken := transforms[n]; taken {
			return nil, fmt.Errorf("emit: transform %s already exists", n)
		}
	}
	if _, taken := sinks[vSink]; taken {
		return nil, fmt.Errorf("emit: sink %s already exists", vSink)
	}

	// Tag: exactly one rule per matching event (rules are disjoint), plus its byte length.
	var tag strings.Builder
	first := true
	for _, r := range rules {
		path, err := t.textPath(r)
		if err != nil {
			return nil, err
		}
		pat, err := dialect.Rust(r.Language)
		if err != nil {
			return nil, err
		}
		kw := "} else if"
		if first {
			kw = "if"
			first = false
		}
		fmt.Fprintf(&tag, "%s %s == %s && is_string(%s) && match(string!(%s), r'%s') {\n  .sievelog_rule = %s\n  .sievelog_bytes = length(string!(%s))\n",
			kw, t.ScopePath, vrlString(r.ScopeValue), path, path, pat, vrlString(r.ID), path)
		if r.Action == "aggregate" && mode == Enforce {
			tag.WriteString("  .sievelog_aggregate = 1\n")
		}
	}
	if !first {
		tag.WriteString("}\n")
	}
	transforms[vTag] = map[string]any{"type": "remap", "inputs": []any{t.After}, "source": tag.String()}
	metrics := []any{
		map[string]any{"type": "counter", "field": "sievelog_rule", "name": "sievelog_rule_lines", "tags": map[string]any{"rule": "{{ sievelog_rule }}"}},
		map[string]any{"type": "counter", "field": "sievelog_bytes", "name": "sievelog_rule_bytes", "increment_by_value": true, "tags": map[string]any{"rule": "{{ sievelog_rule }}"}},
	}
	// One log_to_metric per field set: when any metric of a log_to_metric fails for an event (a missing
	// field), Vector emits none of that transform's metrics for it.
	transforms[vMeasure] = map[string]any{"type": "log_to_metric", "inputs": []any{vTag}, "metrics": metrics}
	measureInputs := []any{vMeasure}
	if mode == Enforce {
		transforms[vMeasureAgg] = map[string]any{"type": "log_to_metric", "inputs": []any{vTag}, "metrics": []any{
			map[string]any{"type": "counter", "field": "sievelog_aggregate", "name": "sievelog_aggregate_lines", "tags": map[string]any{"rule": "{{ sievelog_rule }}"}}}}
		measureInputs = append(measureInputs, vMeasureAgg)
	}
	ms := map[string]any{}
	for k, v := range t.MeasureSink {
		ms[k] = v
	}
	ms["inputs"] = measureInputs
	sinks[vSink] = ms
	if mode != Enforce {
		return yaml.Marshal(cfg)
	}

	// Enforce: drop and sample by rule, then dedupe constant rules with a count, then clean up.
	var enf strings.Builder
	var dedupe []string
	for _, r := range rules {
		path, _ := t.textPath(r)
		switch r.Action {
		case "drop", "aggregate":
			fmt.Fprintf(&enf, "if .sievelog_rule == %s { abort }\n", vrlString(r.ID))
		case "sample":
			fmt.Fprintf(&enf, "if .sievelog_rule == %s {\n  sievelog_key = string!(%s) + \"|\" + to_string(to_unix_timestamp(timestamp!(.timestamp), unit: \"nanoseconds\"))\n  if parse_int!(slice!(sha2(sievelog_key, variant: \"SHA-256\"), 0, 15), base: 16) >= %d { abort }\n}\n",
				vrlString(r.ID), path, VectorSampleThreshold(r.Keep))
		case "dedupe":
			fmt.Fprintf(&enf, "if .sievelog_rule == %s { .sievelog_count = 1 }\n", vrlString(r.ID))
			dedupe = append(dedupe, r.ID)
		default:
			return nil, fmt.Errorf("emit: rule %s: unknown action %q", r.ID, r.Action)
		}
	}
	transforms[vEnforce] = map[string]any{"type": "remap", "inputs": []any{vTag}, "source": enf.String(), "drop_on_abort": true}
	cleanInputs := []any{vEnforce}
	if len(dedupe) > 0 {
		var conds []string
		for _, id := range dedupe {
			conds = append(conds, ".sievelog_rule == "+vrlString(id))
		}
		transforms[vRoute] = map[string]any{"type": "route", "inputs": []any{vEnforce}, "route": map[string]any{"dedupe": strings.Join(conds, " || ")}}
		groupBy := []any{"sievelog_rule", strings.TrimPrefix(t.ScopePath, ".")}
		for _, g := range t.GroupBy {
			groupBy = append(groupBy, g)
		}
		ms := t.DedupeMS
		if ms == 0 {
			ms = 10000
		}
		transforms[vReduce] = map[string]any{"type": "reduce", "inputs": []any{vRoute + ".dedupe"}, "group_by": groupBy,
			"expire_after_ms": ms, "merge_strategies": map[string]any{"sievelog_count": "sum"}}
		cleanInputs = []any{vRoute + "._unmatched", vReduce}
	}
	transforms[vClean] = map[string]any{"type": "remap", "inputs": cleanInputs, "source": "del(.sievelog_rule)\ndel(.sievelog_bytes)\ndel(.sievelog_aggregate)\n"}

	// Rewire every original consumer of t.After to read from the enforcement chain.
	ours := map[string]bool{vTag: true, vMeasure: true, vMeasureAgg: true, vEnforce: true, vRoute: true, vReduce: true, vClean: true, vSink: true}
	rewire := func(section map[string]any) error {
		ids := make([]string, 0, len(section))
		for id := range section {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if ours[id] {
				continue
			}
			comp, _ := section[id].(map[string]any)
			in, _ := comp["inputs"].([]any)
			changed := false
			for i, ref := range in {
				s, _ := ref.(string)
				if s == t.After {
					in[i] = vClean
					changed = true
					continue
				}
				if strings.HasPrefix(s, t.After+".") || strings.ContainsAny(s, "*?[") {
					return fmt.Errorf("emit: %s reads %s through %q; rewrite it to read %s directly before enforcing", id, t.After, s, t.After)
				}
			}
			if changed {
				comp["inputs"] = in
			}
		}
		return nil
	}
	if err := rewire(transforms); err != nil {
		return nil, err
	}
	if err := rewire(sinks); err != nil {
		return nil, err
	}
	return yaml.Marshal(cfg)
}
