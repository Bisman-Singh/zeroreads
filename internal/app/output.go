package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	if rep.Pricing.PerGB > 0 || rep.Pricing.PerMillion > 0 {
		fmt.Fprintf(&b, ", about $%.2f/month at %s prices (%s, %s)", rep.MonthlyUSD, rep.Pricing.Backend, rep.Pricing.Source, rep.Pricing.AsOf)
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
	var files [][]byte
	for _, f := range c.Collector.ConfigFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		files = append(files, b)
	}
	var rules []emit.Rule
	for _, r := range rf.Rules {
		rules = append(rules, r.Rule)
	}
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
	var services []string
	seen := map[string]bool{}
	for _, r := range rf.Rules {
		if !seen[r.Service] {
			seen[r.Service] = true
			services = append(services, r.Service)
		}
	}
	queries, scoped, gaps := c.evidence(ctx, now, services, rep)
	tg, err := c.topologyGaps(rep)
	if err != nil {
		return nil, err
	}
	gaps = append(gaps, tg...)
	ack := map[string]bool{}
	for _, k := range c.Policy.Acknowledge {
		ack[k] = true
	}
	var global []string
	for _, g := range gaps {
		if !ack[g.Key] {
			global = append(global, fmt.Sprintf("evidence gap %q: %s", g.Key, g.Reason))
		}
	}
	switch v, err := templating.DrainVersion(); {
	case err != nil:
		global = append(global, "this binary cannot tell which drain it embeds ("+err.Error()+"), so the rules' templates cannot be trusted")
	case v != rf.DrainVersion:
		global = append(global, fmt.Sprintf("rules were made with drain %s, this binary embeds %s", rf.DrainVersion, v))
	}
	if h := c.DrainConfigHash(); h != rf.DrainConfigHash {
		global = append(global, "the drain version, masking rules or seed templates changed since the rules were made; re-analyse")
	}
	var deployedMode string
	var deployedDiffs []string
	if opt.Deployed != nil {
		var err error
		deployedMode, deployedDiffs, err = DeployedDiff(c, rf, opt.Deployed)
		if err != nil {
			return nil, err
		}
		for _, d := range deployedDiffs {
			global = append(global, "the deployed pipeline config is not what emit produces for these rules ("+deployedMode+" mode): "+d)
		}
	}
	type parsed struct {
		q      analyze.UsageQuery
		parsed *logql.Query
		sel    []logql.Selection
		err    error
	}
	var pqs []parsed
	for _, q := range queries {
		p, err := logql.Parse(q.Expr)
		if err != nil {
			pqs = append(pqs, parsed{q: q, err: err})
			continue
		}
		pqs = append(pqs, parsed{q: q, parsed: p, sel: p.Selections})
	}
	res := &VerifyResult{CheckedAt: now.UTC(), DeployedMode: deployedMode, DeployedDiffs: deployedDiffs,
		Keep: &RulesFile{GeneratedAt: rf.GeneratedAt, DrainVersion: rf.DrainVersion, DrainConfigHash: rf.DrainConfigHash, LokiLabel: rf.LokiLabel,
			RewritesAppliedAt: rf.RewritesAppliedAt}}
	if opt.Drift {
		d, err := c.Drift(ctx, rf, now)
		if err != nil {
			return nil, err
		}
		res.Drift = d
	}
	languages := make(map[string]string, len(rf.Rules))
	for _, r := range rf.Rules {
		languages[r.ID] = r.Language
	}
	for _, r := range rf.Rules {
		reasons := append([]string(nil), global...)
		lang, err := automaton.Compile(r.Language)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		ur := usage.Rule{ID: r.ID, Scope: map[string]string{rf.LokiLabel: r.Service}, Language: lang, Structured: r.Field != ""}
		replaced := map[string]bool{} // original queries this rule's rewrites replaced
		for _, rw := range r.Rewrites {
			replaced[logql.Canonical(rw.Old)] = true
		}
		for _, p := range pqs {
			if p.err != nil {
				reasons = append(reasons, fmt.Sprintf("%s %s does not parse; treated as reading every line", p.q.Source, p.q.Origin))
				continue
			}
			// An original query executed only before its rewrite was applied is history.
			if p.q.Source == "loki-querylog" && replaced[logql.Canonical(p.q.Expr)] && !rf.RewritesAppliedAt.IsZero() && p.q.Last.Before(rf.RewritesAppliedAt) {
				continue
			}
			for _, sel := range p.sel {
				if r.Action == "rollup" && rewrite.Compensated(p.parsed, sel, r.ID, languages) {
					continue
				}
				if r.Action == "rollup" && rewrite.ReadsRollups(sel, r.ID, ur.Scope) {
					reasons = append(reasons, fmt.Sprintf("%s %s would count or show this rule's rollup records: %s", p.q.Source, p.q.Origin, p.q.Expr))
					break
				}
				if v := usage.Evaluate(sel, ur); v.Used {
					reasons = append(reasons, fmt.Sprintf("%s %s reads these lines: %s (e.g. %q)", p.q.Source, p.q.Origin, p.q.Expr, v.Witness))
					break
				}
			}
		}
		for _, sr := range scoped {
			if sr.Service == r.Service {
				reasons = append(reasons, fmt.Sprintf("%s %s may read these lines: %s", sr.Source, sr.Origin, sr.Reason))
			}
		}
		if len(reasons) > 0 {
			sort.Strings(reasons)
			res.Violations = append(res.Violations, Violation{RuleID: r.ID, Reasons: reasons})
			continue
		}
		res.Keep.Rules = append(res.Keep.Rules, r)
	}
	return res, nil
}

// EmitPolicies writes the rules as Telemetry Policies, each verified against policy-go; rules the
// format cannot express, or that the engine would apply differently, are returned with reasons.
func EmitPolicies(rf *RulesFile, scratch string) ([]byte, []emit.PolicySkip, error) {
	var rules []emit.Rule
	for _, r := range rf.Rules {
		rules = append(rules, r.Rule)
	}
	return emit.Policies(rules, scratch)
}

// EmitVector writes the Vector configuration for the rules in the given mode.
func EmitVector(c *Config, rf *RulesFile, mode emit.Mode) ([]byte, error) {
	var files [][]byte
	for _, f := range c.Vector.ConfigFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		files = append(files, b)
	}
	var rules []emit.Rule
	for _, r := range rf.Rules {
		rules = append(rules, r.Rule)
	}
	v := c.Vector
	return emit.Vector(files, emit.VectorTarget{After: v.After, ScopePath: v.ScopePath, TextPath: v.TextPath, FieldPaths: v.FieldPaths,
		GroupBy: v.GroupBy, MeasureSink: v.MeasureSink, DedupeMS: v.DedupeMS, SeverityPaths: v.SeverityPaths}, rules, mode)
}

// EmitFluentBit writes the Fluent Bit YAML configuration for the rules in the given mode.
func EmitFluentBit(c *Config, rf *RulesFile, mode emit.Mode) ([]byte, error) {
	var files [][]byte
	for _, f := range c.FluentBit.ConfigFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		files = append(files, b)
	}
	var rules []emit.Rule
	for _, r := range rf.Rules {
		rules = append(rules, r.Rule)
	}
	f := c.FluentBit
	return emit.FluentBit(files, emit.FluentBitTarget{Match: f.Match, After: f.After, ScopeKey: f.ScopeKey, TextKey: f.TextKey,
		FieldKeys: f.FieldKeys, MetricsTag: f.MetricsTag, SeverityKeys: f.SeverityKeys}, rules, mode)
}
