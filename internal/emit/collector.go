// Package emit turns decided rules into configuration for the runtime that enforces them.
package emit

import (
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
	"github.com/Bisman-Singh/sievelog/internal/topology"
)

// Rule is one decided rule, ready to enforce.
type Rule struct {
	ID         string
	ScopeAttr  string // resource attribute, e.g. service.name
	ScopeValue string // e.g. checkout
	Language   string // anchored RE2 over the body, or over Field of a map body
	Field      string // "" for plain bodies
	Action     string // archive | aggregate | dedupe | sample | drop | rollup
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
	// ArchiveExporters receive archived rules' lines instead of the pipeline's exporters. Required
	// when any rule archives; they must exist in the config and not be the pipeline's own exporters.
	ArchiveExporters []string
	// DedupeInterval is the logdedup interval, e.g. 10s.
	DedupeInterval string
	// SeverityKeys are log attributes (and, for structured records, body fields) that carry a level
	// such as "error". Records at warning or above there, or in severity_number or severity_text,
	// never match a rule. They are checked in addition to the default level fields.
	SeverityKeys []string
}

// defaultSeverityKeys are the level fields always checked.
func defaultSeverityKeys() []string {
	return []string{"level", "severity", "lvl", "loglevel", "log.level"}
}

// withDefaults returns defaults followed by the configured entries not among them. Configured level
// fields only ever add to the guard: an empty or partial list must never switch it off.
func withDefaults[T any](defaults, configured []T, key func(T) string) []T {
	seen := map[string]bool{}
	var out []T
	for _, x := range append(append([]T(nil), defaults...), configured...) {
		if k := key(x); !seen[k] {
			seen[k] = true
			out = append(out, x)
		}
	}
	return out
}

func sameString(s string) string { return s }

// SeverePattern matches a level of warning or above, case-insensitively, in any common spelling
// (warn, warning, error, err, fatal, critical, crit, alert, emerg, emergency, panic, severe).
const SeverePattern = `(?i)\A\s*(?:warn|err|fatal|crit|alert|emerg|panic|severe)`

// GuardedCondition is Condition plus the runtime severity guard: whatever analysis concluded, a
// record at warning or above is never measured as removable and never removed.
func (r Rule) GuardedCondition(keys []string) string {
	keys = withDefaults(defaultSeverityKeys(), keys, sameString)
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
	nameForward        = "forward/sievelog"
	nameEnforceForward = "forward/sievelog_enforce"
	pipeEnforce        = "logs/sievelog_enforce"
	nameMeasure        = "signal_to_metrics/sievelog"
	nameFilter         = "filter/sievelog"
	nameDedupe         = "logdedup/sievelog"
	nameRollup         = "transform/sievelog_rollup"
	pipeSplit          = "logs/sievelog"
	pipeMetrics        = "metrics/sievelog"
	nameArchiveMark    = "transform/sievelog_archive"
	nameArchiveForward = "forward/sievelog_archive"
	nameArchiveFilter  = "filter/sievelog_archive"
	pipeArchive        = "logs/sievelog_archive"
	RuleAttr           = "sievelog.rule"
	// ArchiveAttr carries, on an archived record, the rule that archived it.
	ArchiveAttr  = "sievelog.archive"
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

// ottlString quotes s as an OTTL string literal inside the Collector's configuration. The Collector
// expands ${...} in every configuration string before OTTL parses it, and $$ is its escape, so a
// service named "a${env:X}" would otherwise read the environment variable X.
func ottlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `$$`).Replace(s) + `"`
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

// validID matches the rule IDs emitters accept. IDs become component, metric and alias names, YAML
// keys, Lua table keys and regex literals, so only characters that need no escaping in any of them
// are allowed.
var validID = regexp.MustCompile(`\Ar-[a-z0-9-]{1,64}\z`)

// CheckRules rejects rules no emitter can write safely: an unsafe or repeated ID, an unknown
// action, a sample share outside 1..99, a rollup of structured records, a language that does not
// compile, or two rules in one scope whose languages overlap (a line must match at most one rule).
func CheckRules(rules []Rule) error {
	seen := map[string]bool{}
	languages := make([]*automaton.Pattern, len(rules))
	for i, r := range rules {
		if !validID.MatchString(r.ID) {
			return fmt.Errorf("emit: rule ID %q is not r- followed by lowercase letters, digits and dashes", r.ID)
		}
		if seen[r.ID] {
			return fmt.Errorf("emit: rule %s appears twice", r.ID)
		}
		seen[r.ID] = true
		switch r.Action {
		case "archive", "aggregate", "dedupe", "drop":
		case "sample":
			if r.Keep <= 0 || r.Keep >= 100 {
				return fmt.Errorf("emit: rule %s: sample keep must be 1..99, got %d", r.ID, r.Keep)
			}
		case "rollup":
			if r.Field != "" {
				return fmt.Errorf("emit: rule %s: rollup applies to plain lines only", r.ID)
			}
		default:
			return fmt.Errorf("emit: rule %s: unknown action %q", r.ID, r.Action)
		}
		p, err := automaton.Compile(r.Language)
		if err != nil {
			return fmt.Errorf("emit: rule %s: language: %w", r.ID, err)
		}
		languages[i] = p
	}
	return checkDisjoint(rules, languages)
}

// checkDisjoint proves no two rules in the same scope and field can match the same line.
func checkDisjoint(rules []Rule, languages []*automaton.Pattern) error {
	for i := range rules {
		for j := i + 1; j < len(rules); j++ {
			a, b := rules[i], rules[j]
			if a.ScopeAttr != b.ScopeAttr || a.ScopeValue != b.ScopeValue || a.Field != b.Field {
				continue
			}
			w, found, err := automaton.Intersects(languages[i], languages[j], 0)
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
	if err := CheckRules(rules); err != nil {
		return nil, err
	}
	cfg, err := topology.MergeFiles("collector", files)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		// Nothing to measure or enforce, which analysis often concludes: the configuration stays
		// exactly the user's. An empty measurement step would stop the Collector from starting at all.
		return yaml.Marshal(cfg)
	}
	pipelines := child(child(cfg, "service"), "pipelines")
	pipeline, ok := pipelines[t.Pipeline].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("emit: no pipeline %s", t.Pipeline)
	}
	if !strings.HasPrefix(t.Pipeline, "logs") {
		return nil, fmt.Errorf("emit: pipeline %s is not a logs pipeline", t.Pipeline)
	}
	connectors, processors, exporters := child(cfg, "connectors"), child(cfg, "processors"), child(cfg, "exporters")
	if err := collectorNamesFree(pipelines, connectors, processors); err != nil {
		return nil, err
	}
	if err := t.checkExporters(rules, exporters); err != nil {
		return nil, err
	}
	head, tail, err := t.splitAt(pipeline)
	if err != nil {
		return nil, err
	}
	origExporters, _ := pipeline["exporters"].([]any)
	if len(origExporters) == 0 {
		return nil, fmt.Errorf("emit: pipeline %s has no exporters", t.Pipeline)
	}
	connectors[nameForward] = map[string]any{}
	connectors[nameEnforceForward] = map[string]any{}
	// error_mode ignore: a record an expression cannot evaluate is skipped for measurement, never
	// failing the batch of real logs this connector sits beside.
	connectors[nameMeasure] = map[string]any{"error_mode": "ignore", "logs": t.measurementMetrics(rules, mode)}
	enforceProcs := []any{}
	if mode == Enforce {
		enforceProcs = t.addEnforcement(rules, processors)
	}
	// The user's processors after t.After run first; measurement then sees exactly the records
	// enforcement sees, so shadow numbers are what enforce removes.
	pipeline["processors"] = head
	pipeline["exporters"] = []any{nameForward}
	pipelines[t.Pipeline] = pipeline
	pipelines[pipeSplit] = map[string]any{"receivers": []any{nameForward}, "processors": tail, "exporters": []any{nameEnforceForward, nameMeasure}}
	pipelines[pipeEnforce] = map[string]any{"receivers": []any{nameEnforceForward}, "processors": enforceProcs, "exporters": origExporters}
	if mode == Enforce {
		if err := t.addArchive(rules, pipelines, connectors, processors, origExporters); err != nil {
			return nil, err
		}
	}
	var measureExporters []any
	for _, e := range dedupStrings(append(append([]string(nil), t.MeasureExporters...), t.AggregateExporters...)) {
		measureExporters = append(measureExporters, e)
	}
	pipelines[pipeMetrics] = map[string]any{"receivers": []any{nameMeasure}, "exporters": measureExporters}
	return yaml.Marshal(cfg)
}

func collectorNamesFree(pipelines, connectors, processors map[string]any) error {
	for _, name := range []string{pipeSplit, pipeMetrics, pipeEnforce, pipeArchive} {
		if _, taken := pipelines[name]; taken {
			return fmt.Errorf("emit: pipeline %s already exists", name)
		}
	}
	for _, n := range []string{nameForward, nameMeasure, nameEnforceForward, nameArchiveForward} {
		if _, taken := connectors[n]; taken {
			return fmt.Errorf("emit: connector %s already exists", n)
		}
	}
	for _, n := range []string{nameFilter, nameDedupe, nameRollup, nameArchiveMark, nameArchiveFilter} {
		if _, taken := processors[n]; taken {
			return fmt.Errorf("emit: processor %s already exists", n)
		}
	}
	return nil
}

// checkExporters requires a measurement exporter, an aggregate exporter when a rule aggregates, an
// archive exporter when a rule archives, and every named exporter to exist.
func (t Target) checkExporters(rules []Rule, exporters map[string]any) error {
	if slices.ContainsFunc(rules, func(r Rule) bool { return r.Action == "aggregate" }) && len(t.AggregateExporters) == 0 {
		return fmt.Errorf("emit: rules aggregate but no aggregate exporter is configured")
	}
	if slices.ContainsFunc(rules, func(r Rule) bool { return r.Action == "archive" }) && len(t.ArchiveExporters) == 0 {
		return fmt.Errorf("emit: rules archive but no archive exporter is configured")
	}
	if len(t.MeasureExporters) == 0 {
		return fmt.Errorf("emit: no measurement exporter is configured")
	}
	for _, e := range slices.Concat(t.MeasureExporters, t.AggregateExporters, t.ArchiveExporters) {
		if _, ok := exporters[e]; !ok {
			return fmt.Errorf("emit: exporter %s does not exist", e)
		}
	}
	for _, e := range slices.Concat(t.MeasureExporters, t.AggregateExporters) {
		if keepsTotals(e) {
			return fmt.Errorf("emit: exporter %s keeps running totals, and the per-rule counts arrive as deltas, one per "+
				"batch, that it would restart its totals on: its numbers would be wrong. Use an exporter that accepts "+
				"delta temporality: OTLP to a backend that does, or file", e)
		}
	}
	return nil
}

// keepsTotals reports an exporter that turns delta sums into running totals by itself. signal_to_metrics
// stamps each batch's delta with the time the batch began and no start time, so such an exporter
// restarts its total at nearly every batch (found on a real Collector: 4 where 60 lines were
// measured), and delta_to_cumulative drops the batches that arrive out of order.
func keepsTotals(exporter string) bool {
	typ, _, _ := strings.Cut(exporter, "/")
	return typ == "prometheus" || typ == "prometheus_remote_write" || typ == "prometheusremotewrite"
}

// splitAt splits the pipeline's processors after t.After (before all of them when it is empty).
func (t Target) splitAt(pipeline map[string]any) (head, tail []any, err error) {
	procs, _ := pipeline["processors"].([]any)
	split := 0
	if t.After != "" {
		for i, p := range procs {
			if p == t.After {
				split = i + 1
			}
		}
		if split == 0 {
			return nil, nil, fmt.Errorf("emit: pipeline %s has no processor %s", t.Pipeline, t.After)
		}
	}
	return append([]any(nil), procs[:split]...), append([]any(nil), procs[split:]...), nil
}

// measurementMetrics count, per rule, the lines and bytes enforcement acts on, and in enforce mode
// the lines an aggregate rule replaces.
func (t Target) measurementMetrics(rules []Rule, mode Mode) []any {
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
	return metrics
}

// addArchive sends archived rules' lines to the archive exporters instead of the pipeline's own.
// The split pipeline marks each such record with the rule that archives it, in a transform whose
// errors skip the record: a record whose condition cannot be evaluated is neither archived nor
// removed, as it is not measured. The enforce pipeline drops marked records; a pipeline beside it
// keeps only them and exports them to the archive.
func (t Target) addArchive(rules []Rule, pipelines, connectors, processors map[string]any, origExporters []any) error {
	var marks []any
	for _, r := range rules {
		if r.Action == "archive" {
			marks = append(marks, fmt.Sprintf("set(log.attributes[%s], %s) where %s", ottlString(ArchiveAttr), ottlString(r.ID), r.GuardedCondition(t.SeverityKeys)))
		}
	}
	if len(marks) == 0 {
		return nil
	}
	var archive []any
	for _, e := range t.ArchiveExporters {
		if slices.Contains(origExporters, any(e)) {
			return fmt.Errorf("emit: archive exporter %s is one of pipeline %s's exporters; archived lines would still reach it", e, t.Pipeline)
		}
		archive = append(archive, e)
	}
	processors[nameArchiveMark] = map[string]any{"error_mode": "ignore",
		"log_statements": []any{map[string]any{"context": "log", "statements": marks}}}
	processors[nameArchiveFilter] = map[string]any{"error_mode": "ignore",
		"log_conditions": []any{fmt.Sprintf("log.attributes[%s] == nil", ottlString(ArchiveAttr))}}
	connectors[nameArchiveForward] = map[string]any{}
	split := pipelines[pipeSplit].(map[string]any)
	split["processors"] = append(split["processors"].([]any), nameArchiveMark)
	split["exporters"] = append(split["exporters"].([]any), nameArchiveForward)
	pipelines[pipeArchive] = map[string]any{"receivers": []any{nameArchiveForward}, "processors": []any{nameArchiveFilter}, "exporters": archive}
	return nil
}

// addEnforcement adds the rollup, dedupe and filter processors the rules need, and returns their
// names in the order they run.
func (t Target) addEnforcement(rules []Rule, processors map[string]any) []any {
	var drops, dedupes, rollups []any
	for _, r := range rules {
		cond := r.GuardedCondition(t.SeverityKeys)
		switch r.Action {
		case "archive":
			drops = append(drops, fmt.Sprintf("log.attributes[%s] == %s", ottlString(ArchiveAttr), ottlString(r.ID)))
		case "aggregate", "drop":
			drops = append(drops, cond)
		case "sample":
			drops = append(drops, r.sampleDrop(cond))
		case "dedupe":
			dedupes = append(dedupes, cond)
		case "rollup":
			// The record keeps its resource (so its stream) and loses everything that would split
			// the count: attributes are replaced by the rule, the body by the marker. The body is
			// set last because the condition reads it.
			rollups = append(rollups,
				"keep_keys(log.attributes, []) where "+cond,
				fmt.Sprintf("set(log.attributes[%s], %s) where %s", ottlString(RuleAttr), ottlString(r.ID), cond),
				fmt.Sprintf("set(log.body, %s) where %s", ottlString(RollupMarker(r.ID)), cond))
			dedupes = append(dedupes, fmt.Sprintf("log.attributes[%s] == %s", ottlString(RuleAttr), ottlString(r.ID)))
		}
	}
	procs := []any{}
	if len(rollups) > 0 {
		processors[nameRollup] = map[string]any{"error_mode": "ignore",
			"log_statements": []any{map[string]any{"context": "log", "statements": rollups}}}
		procs = append(procs, nameRollup)
	}
	if len(dedupes) > 0 {
		interval := t.DedupeInterval
		if interval == "" {
			interval = "10s"
		}
		processors[nameDedupe] = map[string]any{"interval": interval, "conditions": dedupes, "log_count_attribute": DedupCounter}
		procs = append(procs, nameDedupe)
	}
	if len(drops) > 0 {
		processors[nameFilter] = map[string]any{"error_mode": "ignore", "log_conditions": drops}
		procs = append(procs, nameFilter)
	}
	return procs
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
