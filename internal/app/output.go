package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/analyze"
	"github.com/Bisman-Singh/sievelog/internal/automaton"
	"github.com/Bisman-Singh/sievelog/internal/emit"
	"github.com/Bisman-Singh/sievelog/internal/logql"
	"github.com/Bisman-Singh/sievelog/internal/rewrite"
	"github.com/Bisman-Singh/sievelog/internal/templating"
	"github.com/Bisman-Singh/sievelog/internal/usage"
)

// RulesFile is the set of rules an analysis decided to enforce.
type RulesFile struct {
	GeneratedAt  time.Time `json:"generated_at"`
	DrainVersion string    `json:"drain_version"`
	// DrainConfigHash covers the drain version, masking rules and seed templates the rules were made
	// under; verify invalidates every rule when it changes.
	DrainConfigHash string         `json:"drain_config_hash"`
	LokiLabel       string         `json:"loki_label"`
	Rules           []EnforcedRule `json:"rules"`
	// RewritesAppliedAt is when `sievelog rewrite -apply` rewrote the stored queries. Executions of
	// an original query before it are history, not readers.
	RewritesAppliedAt time.Time `json:"rewrites_applied_at,omitzero"`
}

// EnforcedRule is one rule to enforce, with what it was decided on.
type EnforcedRule struct {
	emit.Rule
	Service            string  `json:"service"`
	Template           string  `json:"template"`
	RemovedBytesPerDay float64 `json:"removed_bytes_per_day"`
	// Rewrites are the stored queries that must be rewritten for a rollup to keep their numbers.
	Rewrites []analyze.Rewrite `json:"rewrites,omitempty"`
}

// WriteReport writes report.json, report.md and rules.json into dir.
func WriteReport(dir string, c *Config, rep *Report) error {
	if err := os.MkdirAll(dir, outputDir); err != nil {
		return err
	}
	if err := WriteJSON(filepath.Join(dir, "report.json"), rep, SharedFile); err != nil {
		return err
	}
	rf := RulesFile{GeneratedAt: rep.GeneratedAt, DrainVersion: rep.DrainVersion, DrainConfigHash: c.DrainConfigHash(), LokiLabel: c.Scope.LokiLabel}
	for _, r := range rep.Recommendations {
		if r.Action == "none" {
			continue
		}
		rf.Rules = append(rf.Rules, EnforcedRule{
			Rule: emit.Rule{ID: r.ID, ScopeAttr: c.Scope.OTelAttribute, ScopeValue: r.Candidate.Service, Language: r.Candidate.Language,
				Field: r.Candidate.Field, Action: r.Action, Keep: r.Keep},
			Service: r.Candidate.Service, Template: r.Candidate.Template, RemovedBytesPerDay: r.RemovedBytesPerDay, Rewrites: r.Rewrites,
		})
	}
	if err := WriteJSON(filepath.Join(dir, "rules.json"), rf, SharedFile); err != nil {
		return err
	}
	return WriteFile(filepath.Join(dir, "report.md"), []byte(Markdown(rep)), SharedFile)
}

// SaveRules writes rules.json.
func SaveRules(path string, rf *RulesFile) error { return WriteJSON(path, rf, SharedFile) }

// LoadRules reads rules.json and refuses anything analyze would not have written: unknown fields,
// trailing data, a rule no emitter can write safely, a rule whose ID does not match its service,
// field and language (a hand-edited rule would otherwise keep the verdict of another), or a rewrite
// that does not parse.
func LoadRules(path string) (*RulesFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var rf RulesFile
	if err := dec.Decode(&rf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: data after the rules", path)
	}
	if err := rf.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &rf, nil
}

func (rf *RulesFile) validate() error {
	if rf.DrainVersion == "" || rf.DrainConfigHash == "" {
		return fmt.Errorf("no drain version or configuration hash: not a rules file written by analyze")
	}
	if !labelName.MatchString(rf.LokiLabel) {
		return fmt.Errorf("loki_label %q is not a label name", rf.LokiLabel)
	}
	if err := emit.CheckRules(rf.emitRules()); err != nil {
		return err
	}
	for _, r := range rf.Rules {
		if r.Service != r.ScopeValue {
			return fmt.Errorf("rule %s: service %q and scope value %q differ", r.ID, r.Service, r.ScopeValue)
		}
		if id := (analyze.Candidate{Service: r.Service, Field: r.Field, Language: r.Language}).ID(); id != r.ID {
			return fmt.Errorf("rule %s: its service, field and language belong to rule %s; re-run analyze instead of editing rules", r.ID, id)
		}
		if len(r.Rewrites) > 0 && r.Action != "rollup" {
			return fmt.Errorf("rule %s: only a rollup carries rewrites", r.ID)
		}
		for _, rw := range r.Rewrites {
			switch rw.Store {
			case "", "grafana", "loki-ruler":
			default:
				return fmt.Errorf("rule %s: unknown rewrite store %q", r.ID, rw.Store)
			}
			if _, err := logql.Parse(rw.New); err != nil {
				return fmt.Errorf("rule %s: rewritten query does not parse: %w", r.ID, err)
			}
		}
	}
	return nil
}

// emitRules are the rules as the emitters take them.
func (rf *RulesFile) emitRules() []emit.Rule {
	out := make([]emit.Rule, len(rf.Rules))
	for i, r := range rf.Rules {
		out[i] = r.Rule
	}
	return out
}

func humanBytes(b float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for b >= 1000 && i < len(units)-1 {
		b /= 1000
		i++
	}
	return fmt.Sprintf("%.1f %s", b, units[i])
}

// Markdown renders the report for people.
func Markdown(rep *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# sievelog report\n\nGenerated %s. Discovery window %s, evidence window %s, drain %s.\n\n",
		rep.GeneratedAt.Format(time.RFC3339), rep.Window, rep.EvidenceWindow, rep.DrainVersion)
	acted := 0
	for _, r := range rep.Recommendations {
		if r.Action != "none" {
			acted++
		}
	}
	fmt.Fprintf(&b, "%d rules decided, %d act. Removes %s/day", len(rep.Recommendations), acted, humanBytes(rep.RemovedPerDay))
	if p := rep.Pricing; p.Set() {
		fmt.Fprintf(&b, ", about %.2f %s a month at your prices (%g %s per GB, %g %s per million lines)",
			rep.MonthlyCost, p.Currency, p.PerGB, p.Currency, p.PerMillionLines, p.Currency)
	}
	b.WriteString(".\n\n## Evidence\n\n")
	fmt.Fprintf(&b, "- Query log: %s; %d distinct queries from %d lines, oldest %s\n", rep.Evidence.QueryLogLive, rep.Evidence.QueryLogQueries, rep.Evidence.QueryLogLines, rep.Evidence.QueryLogOldest.Format(time.RFC3339))
	fmt.Fprintf(&b, "- Loki ruler: %d rules\n- Grafana: %d stored queries against this Loki\n", rep.Evidence.RulerRules, rep.Evidence.GrafanaQueries)
	if rep.Evidence.OpenSearchAuditLines > 0 || rep.Evidence.OpenSearchUses > 0 {
		fmt.Fprintf(&b, "- OpenSearch: %d audit entries read, %d requests and stored queries that may read documents\n", rep.Evidence.OpenSearchAuditLines, rep.Evidence.OpenSearchUses)
	}
	for _, s := range rep.Evidence.Sinks {
		fmt.Fprintf(&b, "- Sink %s\n", s)
	}
	if len(rep.Gaps) > 0 {
		b.WriteString("\n## Evidence gaps\n\nEach blocks every rule until fixed or acknowledged in `policy.acknowledge`.\n\n")
		for _, g := range rep.Gaps {
			fmt.Fprintf(&b, "- `%s` (%s %s): %s\n", g.Key, g.Source, g.Origin, g.Reason)
		}
	}
	if s := rep.Readers; s.Readers > 0 {
		fmt.Fprintf(&b, "\n## Readers\n\n%d readers across all rules. %d read the rule's lines exactly (each shows a line it reads). %d are assumed to read more than they may, because part of the query is not modelled; each of those can block a rule that is in fact safe:\n\n",
			s.Readers, s.Exact, s.Readers-s.Exact)
		for _, a := range s.Assumptions {
			fmt.Fprintf(&b, "- %s: %d\n", a.Kind, a.Readers)
		}
	}
	b.WriteString("\n## Rules\n\n")
	for _, r := range rep.Recommendations {
		fmt.Fprintf(&b, "### %s `%s` (%s)\n\n", r.ID, r.Candidate.Template, r.Candidate.Service)
		fmt.Fprintf(&b, "- Action: **%s**", r.Action)
		if r.Action == "sample" {
			fmt.Fprintf(&b, " (keep %d%%)", r.Keep)
		}
		fmt.Fprintf(&b, "\n- Language: `%s`\n- Volume: %.0f lines, %s over %s\n", r.Candidate.Language, r.Candidate.Lines, humanBytes(r.Candidate.Bytes), r.Candidate.Window)
		if r.RemovedBytesPerDay > 0 {
			bound := ""
			if r.UpperBound {
				bound = " (upper bound until shadow mode measures it)"
			}
			fmt.Fprintf(&b, "- Removes %s/day%s\n", humanBytes(r.RemovedBytesPerDay), bound)
		}
		for _, bl := range r.Blockers {
			fmt.Fprintf(&b, "- Blocked: %s\n", bl)
		}
		if len(r.Rewrites) > 0 {
			b.WriteString("- Rewrites (apply with `sievelog rewrite -apply` before or with enforcing; each returns the same numbers before, during and after the switch):\n")
			for _, rw := range r.Rewrites {
				fmt.Fprintf(&b, "  - %s %s\n    - from `%s`\n    - to `%s`\n", rw.Source, rw.Origin, rw.Old, rw.New)
			}
		}
		for _, rd := range r.Readers {
			kind := "reads"
			if rd.Counting {
				kind = "counts"
			}
			fmt.Fprintf(&b, "  - %s %s: `%s`", rd.Source, rd.Origin, rd.Expr)
			if rd.Witness != "" {
				fmt.Fprintf(&b, " %s e.g. `%s`", kind, rd.Witness)
			}
			if len(rd.Widened) > 0 {
				fmt.Fprintf(&b, " (assumed: %s)", strings.Join(rd.Widened, "; "))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if len(rep.Skipped) > 0 {
		b.WriteString("## Templates without a rule\n\n")
		for _, s := range rep.Skipped {
			fmt.Fprintf(&b, "- %s `%s`: %s\n", s.Service, s.Template, s.Reason)
		}
	}
	for _, n := range rep.Notes {
		fmt.Fprintf(&b, "\nNote: %s\n", n)
	}
	return b.String()
}

// EmitCollector writes the collector configuration for the rules in the given mode.
func EmitCollector(c *Config, rf *RulesFile, mode emit.Mode) ([]byte, error) {
	files, err := readFiles(c.Collector.ConfigFiles)
	if err != nil {
		return nil, err
	}
	rules := rf.emitRules()
	return emit.Collector(files, emit.Target{Pipeline: c.Collector.Pipeline, After: c.Collector.After,
		MeasureExporters: c.Collector.MeasureExporters, AggregateExporters: c.Collector.AggregateExporters,
		DedupeInterval: c.Collector.DedupeInterval, SeverityKeys: c.Collector.SeverityKeys}, rules, mode)
}

// Violation is why an enforced rule is no longer safe.
type Violation struct {
	RuleID  string   `json:"rule_id"`
	Reasons []string `json:"reasons"`
}

// VerifyResult is the outcome of re-checking enforced rules against fresh evidence.
type VerifyResult struct {
	CheckedAt  time.Time   `json:"checked_at"`
	Violations []Violation `json:"violations"`
	// Keep is the rules file with every violating rule removed: enforce it to revert.
	Keep *RulesFile `json:"keep"`
	// Drift is, per rule, the template traffic the rule no longer covers. It never fails verify.
	Drift []RuleDrift `json:"drift,omitempty"`
	// DeployedMode and DeployedDiffs compare the deployed pipeline config with the emitted one.
	DeployedMode  string   `json:"deployed_mode,omitempty"`
	DeployedDiffs []string `json:"deployed_diffs,omitempty"`
}

// VerifyOptions adds optional checks to Verify.
type VerifyOptions struct {
	Drift    bool   // measure per-rule template drift
	Deployed []byte // the pipeline config actually deployed; nil skips the comparison
}

// Verify re-reads every evidence source, the topology and the drain version, and reports enforced
// rules that are no longer safe.
func Verify(ctx context.Context, c *Config, rf *RulesFile, now time.Time, opt VerifyOptions) (*VerifyResult, error) {
	rep := &Report{}
	queries, scoped, gaps := c.evidence(ctx, now, rf.services(), rep)
	topoGaps, err := c.topologyGaps(rep)
	if err != nil {
		return nil, err
	}
	res := &VerifyResult{CheckedAt: now.UTC(),
		Keep: &RulesFile{GeneratedAt: rf.GeneratedAt, DrainVersion: rf.DrainVersion, DrainConfigHash: rf.DrainConfigHash, LokiLabel: rf.LokiLabel,
			RewritesAppliedAt: rf.RewritesAppliedAt}}
	forEveryRule := c.unacknowledged(append(gaps, topoGaps...))
	forEveryRule = append(forEveryRule, c.drainChanges(rf)...)
	if opt.Deployed != nil {
		if res.DeployedMode, res.DeployedDiffs, err = DeployedDiff(c, rf, opt.Deployed); err != nil {
			return nil, err
		}
		for _, d := range res.DeployedDiffs {
			forEveryRule = append(forEveryRule, "the deployed pipeline config is not what emit produces for these rules ("+res.DeployedMode+" mode): "+d)
		}
	}
	if opt.Drift {
		if res.Drift, err = c.Drift(ctx, rf, now); err != nil {
			return nil, err
		}
	}
	parsed := parseQueries(queries)
	languages := make(map[string]string, len(rf.Rules))
	for _, r := range rf.Rules {
		languages[r.ID] = r.Language
	}
	for _, r := range rf.Rules {
		reasons, err := rf.readersOf(r, parsed, scoped, languages)
		if err != nil {
			return nil, err
		}
		reasons = append(append([]string(nil), forEveryRule...), reasons...)
		if len(reasons) > 0 {
			sort.Strings(reasons)
			res.Violations = append(res.Violations, Violation{RuleID: r.ID, Reasons: reasons})
			continue
		}
		res.Keep.Rules = append(res.Keep.Rules, r)
	}
	return res, nil
}

// services are the rules' services, in first-seen order.
func (rf *RulesFile) services() []string {
	var out []string
	for _, r := range rf.Rules {
		if !slices.Contains(out, r.Service) {
			out = append(out, r.Service)
		}
	}
	return out
}

// unacknowledged is every gap the policy does not accept, as a reason that fails every rule.
func (c *Config) unacknowledged(gaps []analyze.Gap) []string {
	var out []string
	for _, g := range gaps {
		if !slices.Contains(c.Policy.Acknowledge, g.Key) {
			out = append(out, fmt.Sprintf("evidence gap %q: %s", g.Key, g.Reason))
		}
	}
	return out
}

// drainChanges are the reasons templates made for the rules may no longer match: another drain
// version, or other masking rules or seed templates.
func (c *Config) drainChanges(rf *RulesFile) []string {
	var out []string
	switch v, err := templating.DrainVersion(); {
	case err != nil:
		out = append(out, "this binary cannot tell which drain it embeds ("+err.Error()+"), so the rules' templates cannot be trusted")
	case v != rf.DrainVersion:
		out = append(out, fmt.Sprintf("rules were made with drain %s, this binary embeds %s", rf.DrainVersion, v))
	}
	if c.DrainConfigHash() != rf.DrainConfigHash {
		out = append(out, "the drain version, masking rules or seed templates changed since the rules were made; re-analyse")
	}
	return out
}

// parsedQuery is a usage query parsed once; err is set when it does not parse.
type parsedQuery struct {
	analyze.UsageQuery
	query *logql.Query
	err   error
}

func parseQueries(queries []analyze.UsageQuery) []parsedQuery {
	out := make([]parsedQuery, len(queries))
	for i, q := range queries {
		out[i].UsageQuery = q
		out[i].query, out[i].err = logql.Parse(q.Expr)
	}
	return out
}

// readersOf is why rule r is no longer safe to enforce: every query that reads its lines (a query
// that does not parse reads everything), every query that would count or show its rollup records,
// and every other store's reader of its service.
func (rf *RulesFile) readersOf(r EnforcedRule, queries []parsedQuery, scoped []analyze.ScopedReader, languages map[string]string) ([]string, error) {
	lang, err := automaton.Compile(r.Language)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", r.ID, err)
	}
	ur := usage.Rule{ID: r.ID, Scope: map[string]string{rf.LokiLabel: r.Service}, Language: lang, Structured: r.Field != ""}
	replaced := map[string]bool{} // original queries this rule's rewrites replaced
	for _, rw := range r.Rewrites {
		replaced[logql.Canonical(rw.Old)] = true
	}
	var reasons []string
	for _, p := range queries {
		if p.err != nil {
			reasons = append(reasons, fmt.Sprintf("%s %s does not parse; treated as reading every line", p.Source, p.Origin))
			continue
		}
		// An original query executed only before its rewrite was applied is history.
		if p.Source == "loki-querylog" && replaced[logql.Canonical(p.Expr)] && !rf.RewritesAppliedAt.IsZero() && p.Last.Before(rf.RewritesAppliedAt) {
			continue
		}
		if why, ok := readsRule(p, r, ur, languages); ok {
			reasons = append(reasons, why)
		}
	}
	for _, sr := range scoped {
		if sr.Service == r.Service {
			reasons = append(reasons, fmt.Sprintf("%s %s may read these lines: %s", sr.Source, sr.Origin, sr.Reason))
		}
	}
	return reasons, nil
}

// readsRule reports whether a parsed query reads rule r's lines or, for a rollup, its records; a
// rollup's own compensated raw-line term is not a reader.
func readsRule(p parsedQuery, r EnforcedRule, ur usage.Rule, languages map[string]string) (string, bool) {
	for _, sel := range p.query.Selections {
		if r.Action == "rollup" && rewrite.Compensated(p.query, sel, r.ID, languages) {
			continue
		}
		if r.Action == "rollup" && rewrite.ReadsRollups(sel, r.ID, ur.Scope) {
			return fmt.Sprintf("%s %s would count or show this rule's rollup records: %s", p.Source, p.Origin, p.Expr), true
		}
		if v := usage.Evaluate(sel, ur); v.Used {
			msg := fmt.Sprintf("%s %s reads these lines: %s (e.g. %q)", p.Source, p.Origin, p.Expr, v.Witness)
			if len(v.Widened) > 0 {
				msg += " (assumed: " + strings.Join(v.Widened, "; ") + ")"
			}
			return msg, true
		}
	}
	return "", false
}

// EmitPolicies writes the rules as Telemetry Policies, each verified against policy-go; rules the
// format cannot express, or that the engine would apply differently, are returned with reasons.
func EmitPolicies(rf *RulesFile, scratch string) ([]byte, []emit.PolicySkip, error) {
	rules := rf.emitRules()
	return emit.Policies(rules, scratch)
}

// EmitVector writes the Vector configuration for the rules in the given mode.
func EmitVector(c *Config, rf *RulesFile, mode emit.Mode) ([]byte, error) {
	files, err := readFiles(c.Vector.ConfigFiles)
	if err != nil {
		return nil, err
	}
	rules := rf.emitRules()
	v := c.Vector
	return emit.Vector(files, emit.VectorTarget{After: v.After, ScopePath: v.ScopePath, TextPath: v.TextPath, FieldPaths: v.FieldPaths,
		GroupBy: v.GroupBy, MeasureSink: v.MeasureSink, DedupeMS: v.DedupeMS, SeverityPaths: v.SeverityPaths}, rules, mode)
}

// EmitFluentBit writes the Fluent Bit YAML configuration for the rules in the given mode.
func EmitFluentBit(c *Config, rf *RulesFile, mode emit.Mode) ([]byte, error) {
	files, err := readFiles(c.FluentBit.ConfigFiles)
	if err != nil {
		return nil, err
	}
	rules := rf.emitRules()
	f := c.FluentBit
	return emit.FluentBit(files, emit.FluentBitTarget{Match: f.Match, After: f.After, ScopeKey: f.ScopeKey, TextKey: f.TextKey,
		FieldKeys: f.FieldKeys, MetricsTag: f.MetricsTag, SeverityKeys: f.SeverityKeys}, rules, mode)
}
