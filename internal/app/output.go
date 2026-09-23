package app

import (
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
	"github.com/Bisman-Singh/sievelog/internal/templating"
	"github.com/Bisman-Singh/sievelog/internal/usage"
)

// RulesFile is the set of rules an analysis decided to enforce.
type RulesFile struct {
	GeneratedAt  time.Time      `json:"generated_at"`
	DrainVersion string         `json:"drain_version"`
	LokiLabel    string         `json:"loki_label"`
	Rules        []EnforcedRule `json:"rules"`
}

// EnforcedRule is one rule to enforce, with what it was decided on.
type EnforcedRule struct {
	emit.Rule
	Service            string  `json:"service"`
	Template           string  `json:"template"`
	RemovedBytesPerDay float64 `json:"removed_bytes_per_day"`
}

// WriteReport writes report.json, report.md and rules.json into dir.
func WriteReport(dir string, c *Config, rep *Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), b, 0o644); err != nil {
		return err
	}
	rf := RulesFile{GeneratedAt: rep.GeneratedAt, DrainVersion: rep.DrainVersion, LokiLabel: c.Scope.LokiLabel}
	for _, r := range rep.Recommendations {
		if r.Action == "none" {
			continue
		}
		rf.Rules = append(rf.Rules, EnforcedRule{
			Rule: emit.Rule{ID: r.ID, ScopeAttr: c.Scope.OTelAttribute, ScopeValue: r.Candidate.Service, Language: r.Candidate.Language,
				Field: r.Candidate.Field, Action: r.Action, Keep: r.Keep},
			Service: r.Candidate.Service, Template: r.Candidate.Template, RemovedBytesPerDay: r.RemovedBytesPerDay,
		})
	}
	b, err = json.MarshalIndent(rf, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "rules.json"), b, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report.md"), []byte(Markdown(rep)), 0o644)
}

// LoadRules reads rules.json.
func LoadRules(path string) (*RulesFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rf RulesFile
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &rf, nil
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
		DedupeInterval: c.Collector.DedupeInterval}, rules, mode)
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
}

// Verify re-reads every evidence source, the topology and the drain version, and reports enforced
// rules that are no longer safe.
func Verify(ctx context.Context, c *Config, rf *RulesFile, now time.Time) (*VerifyResult, error) {
	rep := &Report{}
	queries, gaps, err := c.evidence(ctx, now, rep)
	if err != nil {
		return nil, err
	}
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
	if v, err := templating.DrainVersion(); err == nil && v != rf.DrainVersion {
		global = append(global, fmt.Sprintf("rules were made with drain %s, this binary embeds %s", rf.DrainVersion, v))
	}
	type parsed struct {
		q   analyze.UsageQuery
		sel []logql.Selection
		err error
	}
	var pqs []parsed
	for _, q := range queries {
		p, err := logql.Parse(q.Expr)
		if err != nil {
			pqs = append(pqs, parsed{q: q, err: err})
			continue
		}
		pqs = append(pqs, parsed{q: q, sel: p.Selections})
	}
	res := &VerifyResult{CheckedAt: now.UTC(), Keep: &RulesFile{GeneratedAt: rf.GeneratedAt, DrainVersion: rf.DrainVersion, LokiLabel: rf.LokiLabel}}
	for _, r := range rf.Rules {
		reasons := append([]string(nil), global...)
		lang, err := automaton.Compile(r.Language)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		ur := usage.Rule{ID: r.ID, Scope: map[string]string{rf.LokiLabel: r.Service}, Language: lang, Structured: r.Field != ""}
		for _, p := range pqs {
			if p.err != nil {
				reasons = append(reasons, fmt.Sprintf("%s %s does not parse; treated as reading every line", p.q.Source, p.q.Origin))
				continue
			}
			for _, sel := range p.sel {
				if v := usage.Evaluate(sel, ur); v.Used {
					reasons = append(reasons, fmt.Sprintf("%s %s reads these lines: %s (e.g. %q)", p.q.Source, p.q.Origin, p.q.Expr, v.Witness))
					break
				}
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
