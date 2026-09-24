// Package emit turns decided rules into configuration for the runtime that enforces them.
package emit

import (
	"fmt"
	"math/big"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
)

// Rule is one decided rule, ready to enforce.
type Rule struct {
	ID         string
	ScopeAttr  string // resource attribute, e.g. service.name
	ScopeValue string // e.g. checkout
	Language   string // anchored RE2 over the body, or over Field of a map body
	Field      string // "" for plain bodies
	Action     string // aggregate | dedupe | sample | drop
	Keep       int    // percent kept, for sample
}

// Target is where in the user's collector config rules are enforced.
type Target struct {
	Pipeline string // e.g. logs
	After    string // processor ID after which rules apply; "" means before all processors
	// MeasureExporters receive the per-rule measurement metrics. They must exist in the config.
	MeasureExporters []string
	// AggregateExporters receive the counters that replace aggregated lines. Required when any
	// rule aggregates; they must exist in the config.
	AggregateExporters []string
	// DedupeInterval is the logdedup interval, e.g. 10s.
	DedupeInterval string
	// SeverityKeys are log attributes (and, for structured records, body fields) that carry a level
	// such as "error". Records at warning or above there, or in severity_number or severity_text,
	// never match a rule. Nil means DefaultSeverityKeys.
	SeverityKeys []string
}

// DefaultSeverityKeys are the level fields checked when none are configured.
var DefaultSeverityKeys = []string{"level", "severity", "lvl", "loglevel", "log.level"}

// SeverePattern matches a level of warning or above, case-insensitively, in any common spelling
// (warn, warning, error, err, fatal, critical, crit, alert, emerg, emergency, panic, severe).
const SeverePattern = `(?i)\A\s*(?:warn|err|fatal|crit|alert|emerg|panic|severe)`

// GuardedCondition is Condition plus the runtime severity guard: whatever analysis concluded, a
// record at warning or above is never measured as removable and never removed.
func (r Rule) GuardedCondition(keys []string) string {
	if keys == nil {
		keys = DefaultSeverityKeys
	}
	g := []string{r.Condition(), "log.severity_number < SEVERITY_NUMBER_WARN", "not IsMatch(log.severity_text, " + ottlString(SeverePattern) + ")"}
	for _, k := range keys {
		g = append(g, "not IsMatch(log.attributes["+ottlString(k)+"], "+ottlString(SeverePattern)+")")
		if r.Field != "" {
			g = append(g, "not IsMatch(log.body["+ottlString(k)+"], "+ottlString(SeverePattern)+")")
		}
	}
	return strings.Join(g, " and ")
}

// Mode selects shadow (measure only) or enforce (measure and act).
type Mode string

const (
	Shadow  Mode = "shadow"
	Enforce Mode = "enforce"
)

// Component and pipeline names this package adds.
const (
	nameForward  = "forward/sievelog"
	nameEnforceF = "forward/sievelog_enforce"
	pipeEnforce  = "logs/sievelog_enforce"
	nameMeasure  = "signal_to_metrics/sievelog"
	nameFilter   = "filter/sievelog"
	nameDedupe   = "logdedup/sievelog"
	nameRollup   = "transform/sievelog_rollup"
	pipeOut      = "logs/sievelog"
	pipeMetrics  = "metrics/sievelog"
	RuleAttr     = "sievelog.rule"
	DedupCounter = "sievelog.dedup_count"
)

// MeasureLines and MeasureBytes name the per-rule measurement metrics.
func MeasureLines(id string) string { return "sievelog.rule.lines." + id }
func MeasureBytes(id string) string { return "sievelog.rule.bytes." + id }

// RollupMarker is the body of a rolled-up rule's records: one per dedupe interval, carrying the
// number of lines it replaces in DedupCounter and the rule in RuleAttr.
func RollupMarker(id string) string { return "sievelog rollup " + id }

// AggregateLines names the counter that replaces an aggregated rule's lines.
func AggregateLines(id string) string { return "sievelog.aggregate.lines." + id }

// ottlString quotes s as an OTTL string literal.
func ottlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func (r Rule) target() string {
	if r.Field == "" {
		return "log.body"
	}
	return "log.body[" + ottlString(r.Field) + "]"
}

// Condition is the OTTL condition that selects exactly the rule's lines. Field rules first check the
// body is a map, so a plain body never reaches the index expression.
func (r Rule) Condition() string {
	guard := ""
	if r.Field != "" {
		guard = "IsMap(log.body) and "
	}
	return fmt.Sprintf(`resource.attributes[%s] == %s and %sIsMatch(%s, %s)`,
		ottlString(r.ScopeAttr), ottlString(r.ScopeValue), guard, r.target(), ottlString(r.Language))
}

// SampleThreshold returns T, 64 lowercase hex digits, such that a line is kept exactly when the
// SHA-256 hex digest of its sample key sorts below T: keep percent of all digests do.
func SampleThreshold(keep int) string {
	span := new(big.Int).Lsh(big.NewInt(1), 256)
	k := new(big.Int).Mul(span, big.NewInt(int64(keep)))
	k.Div(k, big.NewInt(100))
	return fmt.Sprintf("%064x", k)
}

// SampleKey is the OTTL expression whose digest decides sampling: the templated text and the
// timestamp, so identical lines are sampled independently.
func (r Rule) SampleKey() string {
	return fmt.Sprintf(`SHA256(Concat([%s, String(log.time_unix_nano)], "|"))`, r.target())
}

// sampleDrop is the condition under which a sample rule drops a line. A record without a timestamp
// is keyed by its observed time instead, which is also the time Loki stores for it, so identical
// untimed lines are still sampled independently and every decision can be recomputed.
func (r Rule) sampleDrop(guarded string) string {
	th := ottlString(SampleThreshold(r.Keep))
	observed := strings.Replace(r.SampleKey(), "log.time_unix_nano", "log.observed_time_unix_nano", 1)
	return fmt.Sprintf("%s and ((log.time_unix_nano != 0 and %s >= %s) or (log.time_unix_nano == 0 and %s >= %s))",
		guarded, r.SampleKey(), th, observed, th)
}

// CheckDisjoint proves no two rules in the same scope and field can match the same line.
func CheckDisjoint(rules []Rule) error {
	for i := range rules {
		for j := i + 1; j < len(rules); j++ {
			a, b := rules[i], rules[j]
			if a.ScopeAttr != b.ScopeAttr || a.ScopeValue != b.ScopeValue || a.Field != b.Field {
				continue
			}
			pa, err := automaton.Compile(a.Language)
			if err != nil {
				return fmt.Errorf("emit: %s: %w", a.ID, err)
			}
			pb, err := automaton.Compile(b.Language)
			if err != nil {
				return fmt.Errorf("emit: %s: %w", b.ID, err)
			}
			w, found, err := automaton.Intersects(pa, pb, 0)
			if err != nil {
				return fmt.Errorf("emit: cannot prove %s and %s disjoint: %w", a.ID, b.ID, err)
			}
			if found {
				return fmt.Errorf("emit: rules %s and %s overlap on %q", a.ID, b.ID, w)
			}
		}
	}
	return nil
}

// Collector returns the user's configuration (merged in order, later files winning) with the rules
// wired in. The target pipeline is split after Target.After with a forward connector: the first
// half keeps the processors up to that point and feeds the measurement connector and the second
// half, which holds the remaining processors, the enforcement processors and the original
// exporters.
func Collector(files [][]byte, t Target, rules []Rule, mode Mode) ([]byte, error) {
	if err := CheckDisjoint(rules); err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	for i, f := range files {
		var m map[string]any
		if err := yaml.Unmarshal(f, &m); err != nil {
			return nil, fmt.Errorf("emit: file %d: %w", i, err)
		}
		cfg = merge(cfg, m)
	}
	service := child(cfg, "service")
	pipelines := child(service, "pipelines")
	praw, ok := pipelines[t.Pipeline].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("emit: no pipeline %s", t.Pipeline)
	}
	if !strings.HasPrefix(t.Pipeline, "logs") {
		return nil, fmt.Errorf("emit: pipeline %s is not a logs pipeline", t.Pipeline)
	}
	for _, name := range []string{pipeOut, pipeMetrics, pipeEnforce} {
		if _, taken := pipelines[name]; taken {
			return nil, fmt.Errorf("emit: pipeline %s already exists", name)
		}
	}
	connectors, processors, exporters := child(cfg, "connectors"), child(cfg, "processors"), child(cfg, "exporters")
	for _, n := range []string{nameForward, nameMeasure, nameEnforceF} {
		if _, taken := connectors[n]; taken {
			return nil, fmt.Errorf("emit: connector %s already exists", n)
		}
	}
	for _, n := range []string{nameFilter, nameDedupe, nameRollup} {
		if _, taken := processors[n]; taken {
			return nil, fmt.Errorf("emit: processor %s already exists", n)
		}
	}
	needAgg := false
	for _, r := range rules {
		if r.Action == "aggregate" {
			needAgg = true
		}
		switch r.Action {
		case "aggregate", "dedupe", "sample", "drop":
		case "rollup":
			if r.Field != "" {
				return nil, fmt.Errorf("emit: rule %s: rollup applies to plain lines only", r.ID)
			}
		default:
			return nil, fmt.Errorf("emit: rule %s: unknown action %q", r.ID, r.Action)
		}
		if r.Action == "sample" && (r.Keep <= 0 || r.Keep >= 100) {
			return nil, fmt.Errorf("emit: rule %s: sample keep must be 1..99, got %d", r.ID, r.Keep)
		}
	}
	if needAgg && len(t.AggregateExporters) == 0 {
		return nil, fmt.Errorf("emit: rules aggregate but no aggregate exporter is configured")
	}
	if len(t.MeasureExporters) == 0 {
		return nil, fmt.Errorf("emit: no measurement exporter is configured")
	}
	for _, e := range append(append([]string(nil), t.MeasureExporters...), t.AggregateExporters...) {
		if _, ok := exporters[e]; !ok {
			return nil, fmt.Errorf("emit: exporter %s does not exist", e)
		}
	}

	procs, _ := praw["processors"].([]any)
	split := 0
	if t.After != "" {
		split = -1
		for i, p := range procs {
			if p == t.After {
				split = i + 1
			}
		}
		if split < 0 {
			return nil, fmt.Errorf("emit: pipeline %s has no processor %s", t.Pipeline, t.After)
		}
	}
	head := append([]any(nil), procs[:split]...)
	tail := append([]any(nil), procs[split:]...)
	origExporters, _ := praw["exporters"].([]any)
	if len(origExporters) == 0 {
		return nil, fmt.Errorf("emit: pipeline %s has no exporters", t.Pipeline)
	}

	// Measurement: per rule, lines and bytes before any enforcement; aggregate counters too.
	var metrics []any
	for _, r := range rules {
		cond := []any{r.GuardedCondition(t.SeverityKeys)}
		attrs := []any{map[string]any{"key": RuleAttr, "default_value": r.ID}}
		metrics = append(metrics,
			map[string]any{"name": MeasureLines(r.ID), "description": "lines matching rule " + r.ID, "conditions": cond, "attributes": attrs,
				"sum": map[string]any{"value": "1", "monotonic": true}},
			map[string]any{"name": MeasureBytes(r.ID), "description": "bytes of the templated text matching rule " + r.ID, "conditions": cond, "attributes": attrs,
				"sum": map[string]any{"value": "Len(" + r.target() + ")", "monotonic": true}},
		)
		if r.Action == "aggregate" && mode == Enforce {
			metrics = append(metrics, map[string]any{"name": AggregateLines(r.ID), "description": "lines replaced by this counter, rule " + r.ID,
				"conditions": cond, "attributes": attrs, "sum": map[string]any{"value": "1", "monotonic": true}})
		}
	}
	connectors[nameForward] = map[string]any{}
	connectors[nameEnforceF] = map[string]any{}
	// error_mode ignore: a record an expression cannot evaluate is skipped for measurement, never
	// failing the batch of real logs this connector sits beside.
	connectors[nameMeasure] = map[string]any{"error_mode": "ignore", "logs": metrics}

	enforceProcs := []any{}
	if mode == Enforce {
		var drops []any
		var dedupes []any
		var rollups []any
		for _, r := range rules {
			switch r.Action {
			case "aggregate", "drop":
				drops = append(drops, r.GuardedCondition(t.SeverityKeys))
			case "sample":
				drops = append(drops, r.sampleDrop(r.GuardedCondition(t.SeverityKeys)))
			case "dedupe":
				dedupes = append(dedupes, r.GuardedCondition(t.SeverityKeys))
			case "rollup":
				// The record keeps its resource (so its stream) and loses everything that would split
				// the count: attributes are replaced by the rule, the body by the marker. The body is
				// set last because the condition reads it.
				cond := r.GuardedCondition(t.SeverityKeys)
				rollups = append(rollups,
					"keep_keys(log.attributes, []) where "+cond,
					fmt.Sprintf("set(log.attributes[%s], %s) where %s", ottlString(RuleAttr), ottlString(r.ID), cond),
					fmt.Sprintf("set(log.body, %s) where %s", ottlString(RollupMarker(r.ID)), cond))
				dedupes = append(dedupes, fmt.Sprintf("log.attributes[%s] == %s", ottlString(RuleAttr), ottlString(r.ID)))
			}
		}
		if len(rollups) > 0 {
			processors[nameRollup] = map[string]any{"error_mode": "ignore",
				"log_statements": []any{map[string]any{"context": "log", "statements": rollups}}}
			enforceProcs = append(enforceProcs, nameRollup)
		}
		if len(dedupes) > 0 {
			interval := t.DedupeInterval
			if interval == "" {
				interval = "10s"
			}
			processors[nameDedupe] = map[string]any{"interval": interval, "conditions": dedupes, "log_count_attribute": DedupCounter}
			enforceProcs = append(enforceProcs, nameDedupe)
		}
		if len(drops) > 0 {
			processors[nameFilter] = map[string]any{"error_mode": "ignore", "log_conditions": drops}
			enforceProcs = append(enforceProcs, nameFilter)
		}
	}
	// The user's processors after t.After run first; measurement then sees exactly the records
	// enforcement sees, so shadow numbers are what enforce removes.
	praw["processors"] = head
	praw["exporters"] = []any{nameForward}
	pipelines[t.Pipeline] = praw
	pipelines[pipeOut] = map[string]any{"receivers": []any{nameForward}, "processors": tail, "exporters": []any{nameEnforceF, nameMeasure}}
	pipelines[pipeEnforce] = map[string]any{"receivers": []any{nameEnforceF}, "processors": enforceProcs, "exporters": origExporters}
	var mexp []any
	for _, e := range dedupStrings(append(append([]string(nil), t.MeasureExporters...), t.AggregateExporters...)) {
		mexp = append(mexp, e)
	}
	pipelines[pipeMetrics] = map[string]any{"receivers": []any{nameMeasure}, "exporters": mexp}
	return yaml.Marshal(cfg)
}

func dedupStrings(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func child(m map[string]any, k string) map[string]any {
	c, ok := m[k].(map[string]any)
	if !ok {
		c = map[string]any{}
		m[k] = c
	}
	return c
}

func merge(dst, src map[string]any) map[string]any {
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				dst[k] = merge(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
	return dst
}
