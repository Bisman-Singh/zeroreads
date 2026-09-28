package emit

import (
	"fmt"
	"maps"
	"math/big"
	"slices"
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
	// SeverityPaths are VRL paths of level fields; an event at warning or above in any of them, or
	// with severity_number >= 13 (OTLP WARN), never matches a rule. They are checked in addition to
	// the default level fields at the top level and beside every structured field.
	SeverityPaths []string
	GroupBy       []string // extra reduce keys for dedupe, e.g. kubernetes.pod_name
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

// vrlString quotes s as a VRL string literal that means s exactly. VRL reads {{ ... }} in a string
// as a template, and Vector expands $NAME and ${NAME} anywhere in its configuration when
// interpolation is on, where $$ is its escape but stays $$ when it is off. So { is escaped, and $
// and every character outside printable ASCII are written as \u{...}, which VRL decodes after
// interpolation in both cases.
func vrlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\' || r == '"' || r == '{':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '$' || r < 0x20 || r > 0x7e:
			fmt.Fprintf(&b, `\u{%x}`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (t VectorTarget) severityPaths() []string {
	parents := []string{""}
	for _, svc := range slices.Sorted(maps.Keys(t.FieldPaths)) {
		if fp := t.FieldPaths[svc]; strings.LastIndex(fp, ".") > 0 {
			parents = append(parents, fp[:strings.LastIndex(fp, ".")])
		}
	}
	var defaults []string
	for _, parent := range parents {
		for _, k := range defaultSeverityKeys() {
			defaults = append(defaults, parent+"."+vrlField(k))
		}
	}
	return withDefaults(defaults, t.SeverityPaths, sameString)
}

// vrlField quotes a field name for a VRL path when it is not a plain identifier.
func vrlField(k string) string {
	for _, r := range k {
		if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return vrlString(k)
		}
	}
	return k
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
	if err := CheckRules(rules); err != nil {
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
	cfg, err := topology.MergeFiles("vector", files)
	if err != nil {
		return nil, err
	}
	transforms, sinks := child(cfg, "transforms"), child(cfg, "sinks")
	if err := vectorNamesFree(transforms, sinks); err != nil {
		return nil, err
	}
	tag, err := t.tagProgram(rules, mode)
	if err != nil {
		return nil, err
	}
	transforms[vTag] = map[string]any{"type": "remap", "inputs": []any{t.After}, "source": tag}
	t.addMeasurement(transforms, sinks, mode)
	if mode != Enforce {
		return yaml.Marshal(cfg)
	}
	enforce, dedupe, err := t.enforceProgram(rules)
	if err != nil {
		return nil, err
	}
	transforms[vEnforce] = map[string]any{"type": "remap", "inputs": []any{vTag}, "source": enforce, "drop_on_abort": true}
	cleanInputs := []any{vEnforce}
	if len(dedupe) > 0 {
		cleanInputs = t.addDedupe(transforms, dedupe)
	}
	transforms[vClean] = map[string]any{"type": "remap", "inputs": cleanInputs, "source": "del(.sievelog_rule)\ndel(.sievelog_bytes)\ndel(.sievelog_aggregate)\n"}
	// Rewire every original consumer of t.After to read from the enforcement chain.
	for _, section := range []map[string]any{transforms, sinks} {
		if err := rewireConsumers(section, t.After); err != nil {
			return nil, err
		}
	}
	return yaml.Marshal(cfg)
}

// vectorOwn are the components Vector adds; the user's configuration must not have them already.
var vectorOwn = map[string]bool{vTag: true, vMeasure: true, vMeasureAgg: true, vEnforce: true, vRoute: true, vReduce: true, vClean: true, vSink: true}

func vectorNamesFree(transforms, sinks map[string]any) error {
	for _, n := range []string{vTag, vMeasure, vMeasureAgg, vEnforce, vRoute, vReduce, vClean} {
		if _, taken := transforms[n]; taken {
			return fmt.Errorf("emit: transform %s already exists", n)
		}
	}
	if _, taken := sinks[vSink]; taken {
		return fmt.Errorf("emit: sink %s already exists", vSink)
	}
	return nil
}

// tagProgram is the VRL that tags each event with at most one rule (rules are disjoint) and its byte
// length. An event whose level says warning or worse is never tagged, so it is neither measured nor
// removed.
func (t VectorTarget) tagProgram(rules []Rule, mode Mode) (string, error) {
	severe, err := dialect.Rust(SeverePattern)
	if err != nil {
		return "", err
	}
	var tag strings.Builder
	tag.WriteString("sievelog_severe = is_integer(.severity_number) && int!(.severity_number) >= 13\n")
	for _, p := range t.severityPaths() {
		fmt.Fprintf(&tag, "if is_string(%s) && match(string!(%s), r'%s') { sievelog_severe = true }\n", p, p, severe)
	}
	tag.WriteString("if !sievelog_severe {\n")
	for i, r := range rules {
		path, err := t.textPath(r)
		if err != nil {
			return "", err
		}
		pat, err := dialect.Rust(r.Language)
		if err != nil {
			return "", err
		}
		kw := "} else if"
		if i == 0 {
			kw = "if"
		}
		fmt.Fprintf(&tag, "%s %s == %s && is_string(%s) && match(string!(%s), r'%s') {\n  .sievelog_rule = %s\n  .sievelog_bytes = length(string!(%s))\n",
			kw, t.ScopePath, vrlString(r.ScopeValue), path, path, pat, vrlString(r.ID), path)
		if r.Action == "aggregate" && mode == Enforce {
			tag.WriteString("  .sievelog_aggregate = 1\n")
		}
	}
	if len(rules) > 0 {
		tag.WriteString("}\n")
	}
	tag.WriteString("}\n")
	return tag.String(), nil
}

// addMeasurement adds the per-rule counters and the sink that receives them.
func (t VectorTarget) addMeasurement(transforms, sinks map[string]any, mode Mode) {
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
	measureSink := map[string]any{}
	for k, v := range t.MeasureSink {
		measureSink[k] = v
	}
	measureSink["inputs"] = measureInputs
	sinks[vSink] = measureSink
}

// enforceProgram is the VRL that drops and samples by rule and marks dedupe rules for the reduce
// transform; dedupe lists those rules.
func (t VectorTarget) enforceProgram(rules []Rule) (program string, dedupe []string, err error) {
	var enf strings.Builder
	for _, r := range rules {
		path, _ := t.textPath(r) // resolved without error by tagProgram
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
			return "", nil, fmt.Errorf("emit: rule %s: Vector cannot enforce %s; re-run analyze for runtime vector", r.ID, r.Action)
		}
	}
	return enf.String(), dedupe, nil
}

// addDedupe routes dedupe rules' events through a reduce that collapses identical lines with a
// count, and returns the inputs of the clean-up step.
func (t VectorTarget) addDedupe(transforms map[string]any, dedupe []string) []any {
	var conds []string
	for _, id := range dedupe {
		conds = append(conds, ".sievelog_rule == "+vrlString(id))
	}
	transforms[vRoute] = map[string]any{"type": "route", "inputs": []any{vEnforce}, "route": map[string]any{"dedupe": strings.Join(conds, " || ")}}
	groupBy := []any{"sievelog_rule", strings.TrimPrefix(t.ScopePath, ".")}
	for _, g := range t.GroupBy {
		groupBy = append(groupBy, g)
	}
	expireMS := t.DedupeMS
	if expireMS == 0 {
		expireMS = 10000
	}
	transforms[vReduce] = map[string]any{"type": "reduce", "inputs": []any{vRoute + ".dedupe"}, "group_by": groupBy,
		"expire_after_ms": expireMS, "merge_strategies": map[string]any{"sievelog_count": "sum"}}
	return []any{vRoute + "._unmatched", vReduce}
}

// rewireConsumers points every user component that reads after at the end of the enforcement chain.
// A consumer reading after through a named output or a glob cannot be rewired safely.
func rewireConsumers(section map[string]any, after string) error {
	for _, id := range slices.Sorted(maps.Keys(section)) {
		if vectorOwn[id] {
			continue
		}
		comp, _ := section[id].(map[string]any)
		in, _ := comp["inputs"].([]any)
		changed := false
		for i, ref := range in {
			s, _ := ref.(string)
			if s == after {
				in[i] = vClean
				changed = true
				continue
			}
			if strings.HasPrefix(s, after+".") || strings.ContainsAny(s, "*?[") {
				return fmt.Errorf("emit: %s reads %s through %q; rewrite it to read %s directly before enforcing", id, after, s, after)
			}
		}
		if changed {
			comp["inputs"] = in
		}
	}
	return nil
}
