package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/analyze"
	"github.com/Bisman-Singh/sievelog/internal/pricing"
	"github.com/Bisman-Singh/sievelog/internal/rule"
	"github.com/Bisman-Singh/sievelog/internal/source/grafana"
	"github.com/Bisman-Singh/sievelog/internal/source/loki"
	"github.com/Bisman-Singh/sievelog/internal/templating"
	"github.com/Bisman-Singh/sievelog/internal/topology"
)

// Report is the full result of one analysis.
type Report struct {
	GeneratedAt     time.Time                `json:"generated_at"`
	DrainVersion    string                   `json:"drain_version"`
	Window          string                   `json:"window"`
	EvidenceWindow  string                   `json:"evidence_window"`
	Services        []string                 `json:"services"`
	Recommendations []analyze.Recommendation `json:"recommendations"`
	Skipped         []Skipped                `json:"skipped"`
	Gaps            []analyze.Gap            `json:"gaps"`
	Notes           []string                 `json:"notes"`
	Evidence        EvidenceSummary          `json:"evidence"`
	Pricing         pricing.Table            `json:"pricing"`
	RemovedPerDay   float64                  `json:"removed_bytes_per_day"`
	MonthlyUSD      float64                  `json:"monthly_usd"`
}

// Skipped is a template that got no rule, and why.
type Skipped struct {
	Service  string `json:"service"`
	Template string `json:"template"`
	Samples  int    `json:"samples"`
	Reason   string `json:"reason"`
}

// EvidenceSummary says what usage evidence was read.
type EvidenceSummary struct {
	QueryLogLive    string    `json:"query_log_live"`
	QueryLogQueries int       `json:"query_log_queries"`
	QueryLogLines   int       `json:"query_log_lines"`
	QueryLogOldest  time.Time `json:"query_log_oldest"`
	RulerRules      int       `json:"ruler_rules"`
	GrafanaQueries  int       `json:"grafana_queries"`
	// OpenSearchUses counts audited requests, monitors and saved objects that may read documents.
	OpenSearchUses       int      `json:"opensearch_uses"`
	OpenSearchAuditLines int      `json:"opensearch_audit_lines"`
	Sinks                []string `json:"sinks"`
}

func (c *Config) lokiClient(url string) *loki.Client {
	cl := &loki.Client{Base: url, OrgID: c.Loki.OrgID, Username: c.Loki.Username}
	if c.Loki.PasswordEnv != "" {
		cl.Password = os.Getenv(c.Loki.PasswordEnv)
	}
	if c.Loki.BearerTokenEnv != "" {
		cl.BearerToken = os.Getenv(c.Loki.BearerTokenEnv)
	}
	return cl
}

// logqlString quotes s for LogQL: a raw string when possible, otherwise a Go-quoted string.
func logqlString(s string) string {
	if !strings.Contains(s, "`") {
		return "`" + s + "`"
	}
	return strconv.Quote(s)
}

func (c *Config) selector(service string) string {
	return "{" + c.Scope.LokiLabel + "=" + strconv.Quote(service) + "}"
}

// volumeQuery counts (or sums bytes of) the stored lines in a rule's language.
func (c *Config) volumeQuery(fn, service, field, language string, window time.Duration) string {
	sel := c.selector(service)
	rng := "[" + strconv.FormatInt(int64(window/time.Second), 10) + "s]"
	if field == "" {
		return fmt.Sprintf("sum(%s(%s |~ %s %s))", fn, sel, logqlString(language), rng)
	}
	return fmt.Sprintf("sum(%s(%s | json sievelog_field=%s | sievelog_field=~%s %s))", fn, sel, strconv.Quote(field), logqlString(language), rng)
}

// Analyze gathers every piece of evidence and decides.
func Analyze(ctx context.Context, c *Config, now time.Time) (*Report, error) {
	rep := &Report{GeneratedAt: now.UTC(), Window: c.Discovery.Window.String(), EvidenceWindow: c.Evidence.Window.String()}
	if v, err := templating.DrainVersion(); err == nil {
		rep.DrainVersion = v
	}
	lc := c.lokiClient(c.Loki.URL)
	start := now.Add(-c.Discovery.Window.Duration)

	services := c.Scope.Services
	if len(services) == 0 {
		v, err := lc.LabelValues(ctx, c.Scope.LokiLabel, start, now)
		if err != nil {
			return nil, fmt.Errorf("listing %s values: %w", c.Scope.LokiLabel, err)
		}
		services = v
	}
	rep.Services = services

	var cands []analyze.Candidate
	for _, svc := range services {
		cs, skipped, notes, err := c.discover(ctx, lc, svc, start, now)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", svc, err)
		}
		cands = append(cands, cs...)
		rep.Skipped = append(rep.Skipped, skipped...)
		rep.Notes = append(rep.Notes, notes...)
	}

	queries, scoped, gaps, err := c.evidence(ctx, now, services, rep)
	if err != nil {
		return nil, err
	}
	tg, err := c.topologyGaps(rep)
	if err != nil {
		return nil, err
	}
	gaps = append(gaps, tg...)
	rep.Gaps = gaps

	pol := analyze.Policy{Actions: c.Policy.Actions, SamplePercent: c.Policy.SamplePercent, Acknowledged: c.Policy.Acknowledge,
		Exempt: c.Policy.Exempt, ErrorPattern: c.Policy.ErrorPattern, MinDailyBytes: c.Policy.MinDailyBytes}
	if pol.ErrorPattern == "" {
		pol.ErrorPattern = analyze.DefaultErrorPattern
	}
	if c.Runtime != "collector" {
		var acts []string
		for _, a := range pol.Actions {
			switch {
			case a == "dedupe" && c.Runtime == "fluentbit":
				rep.Notes = append(rep.Notes, "dedupe is not offered: Fluent Bit cannot collapse lines while keeping their count")
				continue
			case a == "rollup" && c.Runtime == "fluentbit":
				rep.Notes = append(rep.Notes, "rollup is not offered: Fluent Bit cannot collapse lines while keeping their count")
				continue
			case a == "rollup":
				rep.Notes = append(rep.Notes, "rollup is not offered for "+c.Runtime+"; it is emitted for the OpenTelemetry Collector")
				continue
			}
			acts = append(acts, a)
		}
		pol.Actions = acts
	}
	recs, err := analyze.Decide(cands, queries, scoped, gaps, pol)
	if err != nil {
		return nil, err
	}
	if err := c.keepStreams(ctx, lc, recs, start, now); err != nil {
		return nil, err
	}
	rep.Recommendations = recs
	tbl, err := pricing.Lookup(c.Pricing.Backend)
	if err != nil {
		return nil, err
	}
	rep.Pricing = tbl
	for _, r := range recs {
		if r.Action == "none" {
			continue
		}
		rep.RemovedPerDay += r.RemovedBytesPerDay
		linesPerDay := r.Candidate.Lines / r.Candidate.Window.Hours() * 24
		frac := 1.0
		if r.Action == "sample" {
			frac = float64(100-r.Keep) / 100
		}
		rep.MonthlyUSD += tbl.Monthly(r.RemovedBytesPerDay, linesPerDay*frac)
	}
	return rep, nil
}

// sample reads up to SampleLinesPerService lines of a service spread over the window: it counts
// the lines in each slice first, gives each slice a share of the budget proportional to its count,
// and reads each slice's share spread over sub-windows, so bursts neither waste nor exhaust it.
func (c *Config) sample(ctx context.Context, lc *loki.Client, svc string, start, end time.Time) ([]loki.Entry, error) {
	n := c.Discovery.Slices
	slice := end.Sub(start) / time.Duration(n)
	counts := make([]int, n)
	total := 0
	for i := 0; i < n; i++ {
		s := start.Add(time.Duration(i) * slice)
		e := s.Add(slice)
		if i == n-1 {
			e = end
		}
		q := fmt.Sprintf("sum(count_over_time(%s [%ds]))", c.selector(svc), int64(e.Sub(s)/time.Second))
		v, err := c.scalar(ctx, lc, q, e)
		if err != nil {
			return nil, err
		}
		counts[i] = int(v)
		total += int(v)
	}
	if total == 0 {
		return nil, nil
	}
	budget := c.Discovery.SampleLinesPerService
	var out []loki.Entry
	for i := 0; i < n; i++ {
		if counts[i] == 0 {
			continue
		}
		s := start.Add(time.Duration(i) * slice)
		e := s.Add(slice)
		if i == n-1 {
			e = end
		}
		share := int(float64(budget) * float64(counts[i]) / float64(total))
		if share < 1 {
			share = 1
		}
		if share >= counts[i] {
			all, err := lc.QueryRange(ctx, c.selector(svc), s, e, 5000)
			if err != nil {
				return nil, err
			}
			out = append(out, all...)
			continue
		}
		parts := 20
		if share < parts {
			parts = share
		}
		sub := e.Sub(s) / time.Duration(parts)
		for j := 0; j < parts; j++ {
			ss := s.Add(time.Duration(j) * sub)
			se := ss.Add(sub)
			if j == parts-1 {
				se = e
			}
			part, err := lc.Sample(ctx, c.selector(svc), ss, se, (share+parts-1)/parts)
			if err != nil {
				return nil, err
			}
			out = append(out, part...)
		}
	}
	return out, nil
}

// discover samples one service, templates it, infers languages and measures each exactly.
func (c *Config) discover(ctx context.Context, lc *loki.Client, svc string, start, end time.Time) ([]analyze.Candidate, []Skipped, []string, error) {
	field := c.Scope.Structured[svc]
	entries, err := c.sample(ctx, lc, svc, start, end)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sampling: %w", err)
	}
	names, err := lc.LabelNames(ctx, c.selector(svc), start, end)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("stream labels: %w", err)
	}
	streamLabels := map[string]bool{}
	for _, n := range names {
		streamLabels[n] = true
	}
	var notes []string
	var inputs []templating.Input
	var texts []string
	var levels []string
	unstructured := 0
	for _, e := range entries {
		if field == "" {
			inputs = append(inputs, templating.Input{Body: e.Line})
			texts = append(texts, e.Line)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(e.Line), &m); err != nil {
			unstructured++
			continue
		}
		v, ok := m[field].(string)
		if !ok {
			unstructured++
			continue
		}
		inputs = append(inputs, templating.Input{Fields: m})
		texts = append(texts, v)
		l, _ := m["level"].(string)
		levels = append(levels, l) // aligned with inputs
	}
	if unstructured > 0 {
		notes = append(notes, fmt.Sprintf("%s: %d sampled lines are not JSON records with a string %q field; they get no rule", svc, unstructured, field))
	}
	if len(inputs) == 0 {
		return nil, nil, notes, nil
	}
	dcfg := templating.DefaultConfig()
	dcfg.BodyField = field
	for _, m := range c.Drain.MaskingRules {
		dcfg.MaskingRules = append(dcfg.MaskingRules, templating.MaskRule{Name: m.Name, Pattern: m.Pattern})
	}
	dcfg.SeedTemplates = c.Drain.SeedTemplates
	eng, err := templating.New(ctx, dcfg)
	if err != nil {
		return nil, nil, nil, err
	}
	defer eng.Close(ctx)
	// Two passes: the first converges the parse tree, the second assigns every line its final
	// template, so early lines are not left under cold-start literal templates.
	if _, err := eng.Template(ctx, inputs); err != nil {
		return nil, nil, nil, err
	}
	tmpls, err := eng.Template(ctx, inputs)
	if err != nil {
		return nil, nil, nil, err
	}
	groups := map[string][]string{}
	levelsBy := map[string]map[string]bool{}
	for i, t := range tmpls {
		groups[t] = append(groups[t], texts[i])
		if field != "" && levels[i] != "" {
			if levelsBy[t] == nil {
				levelsBy[t] = map[string]bool{}
			}
			levelsBy[t][levels[i]] = true
		}
	}
	var masks []rule.Mask
	for _, m := range c.Drain.MaskingRules {
		masks = append(masks, rule.Mask{Name: m.Name, Pattern: m.Pattern})
	}
	opt := rule.DefaultOptions()
	opt.MinSamples = c.Discovery.MinSamples
	var keys []string
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var cands []analyze.Candidate
	var skipped []Skipped
	window := end.Sub(start)
	for _, tpl := range keys {
		samples := groups[tpl]
		if tpl == "" {
			skipped = append(skipped, Skipped{Service: svc, Samples: len(samples), Reason: "no template (drain warm-up)"})
			continue
		}
		lang, err := rule.Infer(tpl, masks, samples, opt)
		if errors.Is(err, rule.ErrTooFewSamples) {
			skipped = append(skipped, Skipped{Service: svc, Template: tpl, Samples: len(samples), Reason: err.Error()})
			continue
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("template %q: %w", tpl, err)
		}
		constant := true
		for _, p := range lang.Positions {
			if p.Kind != "literal" {
				constant = false
			}
		}
		lines, err := c.scalar(ctx, lc, c.volumeQuery("count_over_time", svc, field, lang.Regex, window), end)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("measuring %q: %w", tpl, err)
		}
		bytes, err := c.scalar(ctx, lc, c.volumeQuery("bytes_over_time", svc, field, lang.Regex, window), end)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("measuring %q: %w", tpl, err)
		}
		var sev []string
		for l := range levelsBy[tpl] {
			sev = append(sev, l)
		}
		sort.Strings(sev)
		cands = append(cands, analyze.Candidate{
			Service: svc, Scope: map[string]string{c.Scope.LokiLabel: svc}, Template: tpl, Language: lang.Regex,
			Structured: field != "", Field: field, Constant: constant, Samples: lang.Samples,
			Lines: lines, Bytes: bytes, Window: window, Severities: sev, StreamLabels: streamLabels,
		})
	}
	return cands, skipped, notes, nil
}

func (c *Config) scalar(ctx context.Context, lc *loki.Client, q string, at time.Time) (float64, error) {
	s, err := lc.Instant(ctx, q, at)
	if err != nil {
		return 0, err
	}
	switch len(s) {
	case 0:
		return 0, nil
	case 1:
		return s[0].Value, nil
	}
	return 0, fmt.Errorf("expected one series from %s, got %d", q, len(s))
}

// removes reports whether an action leaves no record at all for some lines. Dedupe and rollup
// always leave a record where lines were.
func removes(action string) bool {
	return action == "drop" || action == "aggregate" || action == "sample"
}

// keepStreams blocks rules whose removal would leave some stream with no line at all in the
// window: the stream would disappear from label, series and volume results, which nothing else in
// the analysis models. Counting is exact, per stream label set, from Loki itself.
func (c *Config) keepStreams(ctx context.Context, lc *loki.Client, recs []analyze.Recommendation, start, now time.Time) error {
	rng := "[" + strconv.FormatInt(int64(now.Sub(start)/time.Second), 10) + "s]"
	bySvc := map[string][]int{}
	var svcs []string
	for i, r := range recs {
		if removes(r.Action) {
			if _, ok := bySvc[r.Candidate.Service]; !ok {
				svcs = append(svcs, r.Candidate.Service)
			}
			bySvc[r.Candidate.Service] = append(bySvc[r.Candidate.Service], i)
		}
	}
	for _, svc := range svcs {
		idx := bySvc[svc]
		var labels []string
		for l := range recs[idx[0]].Candidate.StreamLabels {
			labels = append(labels, l)
		}
		sort.Strings(labels)
		streams := func(rules []int) (float64, error) {
			var line, field []string
			for _, i := range rules {
				cd := recs[i].Candidate
				if cd.Structured {
					field = append(field, fmt.Sprintf("| json sievelog_f%d=%s | sievelog_f%d!~%s", i, strconv.Quote(cd.Field), i, logqlString(cd.Language)))
				} else {
					line = append(line, "!~ "+logqlString(cd.Language))
				}
			}
			q := c.selector(svc)
			if len(line) > 0 {
				q += " " + strings.Join(line, " ")
			}
			if len(field) > 0 {
				// A line that is not JSON is dropped here, so it can only count as removed: the check
				// errs towards blocking.
				q += " " + strings.Join(field, " ") + ` | __error__=""`
			}
			return c.scalar(ctx, lc, fmt.Sprintf("count(sum by (%s) (count_over_time(%s %s)))", strings.Join(labels, ", "), q, rng), now)
		}
		before, err := streams(nil)
		if err != nil {
			return fmt.Errorf("counting streams of %s: %w", svc, err)
		}
		block := func(i int, why string) {
			recs[i].Action, recs[i].Keep, recs[i].RemovedBytesPerDay, recs[i].Rewrites = "none", 0, 0, nil
			recs[i].Blockers = append(recs[i].Blockers, why)
		}
		for _, i := range idx {
			after, err := streams([]int{i})
			if err != nil {
				return fmt.Errorf("counting streams of %s: %w", svc, err)
			}
			if after < before {
				block(i, fmt.Sprintf("%.0f of %.0f streams hold only these lines; removing them would make those streams disappear", before-after, before))
			}
		}
		var left []int
		for _, i := range idx {
			if removes(recs[i].Action) {
				left = append(left, i)
			}
		}
		if len(left) > 1 {
			after, err := streams(left)
			if err != nil {
				return fmt.Errorf("counting streams of %s: %w", svc, err)
			}
			if after < before {
				for _, i := range left {
					block(i, fmt.Sprintf("together with the other rules of %s, removing these lines would empty %.0f streams", svc, before-after))
				}
			}
		}
	}
	return nil
}

// evidence reads every usage source. Anything that cannot be read becomes a gap with a stable key.
func (c *Config) evidence(ctx context.Context, now time.Time, services []string, rep *Report) ([]analyze.UsageQuery, []analyze.ScopedReader, []analyze.Gap, error) {
	var qs []analyze.UsageQuery
	var gaps []analyze.Gap
	from := now.Add(-c.Evidence.Window.Duration)

	if !c.Evidence.QueryLog.Enabled {
		gaps = append(gaps, analyze.Gap{Source: "loki", Origin: "query-log", Key: "querylog-disabled", Reason: "the Loki query log is not read, so executed queries are unknown"})
	} else {
		ql := &loki.QueryLog{Logs: c.lokiClient(c.Evidence.QueryLog.URL), Selector: c.Evidence.QueryLog.Selector}
		rep.Evidence.QueryLogLive = "not checked"
		if c.Evidence.QueryLog.ProveLive {
			if err := ql.ProveLive(ctx, c.lokiClient(c.Loki.URL), 2*time.Minute); err != nil {
				rep.Evidence.QueryLogLive = err.Error()
				gaps = append(gaps, analyze.Gap{Source: "loki", Origin: "query-log", Key: "querylog-not-live", Reason: err.Error()})
			} else {
				rep.Evidence.QueryLogLive = "proven with a marker query"
			}
		}
		res, err := ql.Read(ctx, from, now)
		if err != nil {
			gaps = append(gaps, analyze.Gap{Source: "loki", Origin: "query-log", Key: "querylog-unreadable", Reason: err.Error()})
		} else {
			rep.Evidence.QueryLogQueries = len(res.Queries)
			rep.Evidence.QueryLogLines = res.Lines
			rep.Evidence.QueryLogOldest = res.Oldest
			if res.Unparsed > 0 {
				gaps = append(gaps, analyze.Gap{Source: "loki", Origin: "query-log", Key: "querylog-unparsed", Reason: fmt.Sprintf("%d query-log lines did not parse", res.Unparsed)})
			}
			tol := c.Evidence.Window.Duration / 100
			if tol < time.Minute {
				tol = time.Minute
			}
			if tol > time.Hour {
				tol = time.Hour
			}
			if res.Oldest.IsZero() || res.Oldest.After(from.Add(tol)) {
				gaps = append(gaps, analyze.Gap{Source: "loki", Origin: "query-log", Key: "querylog-window",
					Reason: fmt.Sprintf("the query log starts at %s, after the evidence window start %s", res.Oldest.UTC().Format(time.RFC3339), from.UTC().Format(time.RFC3339))})
			}
			for _, q := range res.Queries {
				qs = append(qs, analyze.UsageQuery{Source: "loki-querylog", Origin: "query-log (" + q.Component + ")", Expr: q.Query, Count: q.Count, Last: q.Last})
			}
		}
	}

	if !c.Evidence.Ruler {
		gaps = append(gaps, analyze.Gap{Source: "loki", Origin: "ruler", Key: "ruler-not-checked", Reason: "Loki ruler rules are not read"})
	} else {
		rules, err := c.lokiClient(c.Loki.URL).Rules(ctx)
		if err != nil {
			gaps = append(gaps, analyze.Gap{Source: "loki", Origin: "ruler", Key: "ruler-unreadable", Reason: err.Error()})
		}
		rep.Evidence.RulerRules = len(rules)
		for _, r := range rules {
			qs = append(qs, analyze.UsageQuery{Source: "loki-ruler", Origin: fmt.Sprintf("%s/%s/%s (%s)", r.Namespace, r.Group, r.Name, r.Kind), Expr: r.Expr,
				Store: "loki-ruler", StoreURL: c.Loki.URL, Path: r.Namespace + "/" + r.Group + "/" + r.Name})
		}
	}

	if len(c.Evidence.Grafana) == 0 {
		gaps = append(gaps, analyze.Gap{Source: "grafana", Origin: "config", Key: "grafana-not-configured", Reason: "no Grafana is configured; dashboards, alerts and saved links elsewhere are unknown"})
	}
	for _, g := range c.Evidence.Grafana {
		gc := &grafana.Client{Base: g.URL, Username: g.Username}
		if g.PasswordEnv != "" {
			gc.Password = os.Getenv(g.PasswordEnv)
		}
		if g.TokenEnv != "" {
			gc.Token = os.Getenv(g.TokenEnv)
		}
		res, err := gc.Read(ctx)
		if err != nil {
			gaps = append(gaps, analyze.Gap{Source: "grafana", Origin: g.URL, Key: "grafana-unreadable", Reason: err.Error()})
			continue
		}
		want := map[string]bool{grafana.AnyLoki: true}
		for _, d := range g.Datasources {
			want[d] = true
		}
		for _, q := range res.Queries {
			hit := false
			for _, d := range q.Datasources {
				if want[d] {
					hit = true
				}
			}
			if !hit {
				continue // runs against a different Loki
			}
			rep.Evidence.GrafanaQueries++
			qs = append(qs, analyze.UsageQuery{Source: "grafana", Origin: fmt.Sprintf("%s org %d %s", g.URL, q.Org, q.Origin), Expr: q.Expr,
				Store: "grafana", StoreURL: g.URL, Org: q.Org, Path: q.Origin})
		}
		for _, gp := range res.Gaps {
			if strings.Contains(gp.Reason, "library panel") && strings.Contains(gp.Reason, "does not exist") {
				rep.Notes = append(rep.Notes, fmt.Sprintf("grafana org %d %s: %s (it reads nothing)", gp.Org, gp.Origin, gp.Reason))
				continue
			}
			key := "grafana-" + strings.SplitN(strings.SplitN(gp.Origin, ":", 2)[0], "/", 2)[0]
			gaps = append(gaps, analyze.Gap{Source: "grafana", Origin: fmt.Sprintf("org %d %s", gp.Org, gp.Origin), Key: key, Reason: gp.Reason})
		}
	}
	scoped, og := c.openSearchEvidence(ctx, from, now, services, rep)
	gaps = append(gaps, og...)
	return qs, scoped, gaps, nil
}

// topologyGaps checks every destination downstream of the enforcement point.
func (c *Config) topologyGaps(rep *Report) ([]analyze.Gap, error) {
	switch c.Runtime {
	case "vector":
		return c.vectorGaps(rep)
	case "fluentbit":
		return c.fluentBitGaps(rep)
	}
	var files [][]byte
	for _, f := range c.Collector.ConfigFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		files = append(files, b)
	}
	tc, err := topology.Load(files...)
	if err != nil {
		return nil, err
	}
	p, ok := tc.Pipelines[c.Collector.Pipeline]
	if !ok {
		return nil, fmt.Errorf("collector pipeline %s not found", c.Collector.Pipeline)
	}
	after := -1
	if c.Collector.After != "" {
		after = -2
		for i, x := range p.Processors {
			if x == c.Collector.After {
				after = i
			}
		}
		if after == -2 {
			return nil, fmt.Errorf("processor %s not in pipeline %s", c.Collector.After, c.Collector.Pipeline)
		}
	}
	reach, err := tc.Downstream(c.Collector.Pipeline, after)
	if err != nil {
		return nil, err
	}
	var gaps []analyze.Gap
	var ids []string
	for id := range reach.Exporters {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s, ok := c.Collector.Sinks[id]
		switch {
		case ok && s.Loki:
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": analysed Loki")
		case ok && s.OpenSearch != "":
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": opensearch "+s.OpenSearch)
		case ok:
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": exempt ("+s.Exempt+")")
		default:
			gaps = append(gaps, analyze.Gap{Source: "collector", Origin: strings.Join(reach.Exporters[id], " > "), Key: "sink:" + id,
				Reason: "removed lines would also vanish from " + id + ", which has no usage evidence"})
		}
	}
	for _, d := range reach.Derived {
		if why, ok := c.Collector.Derived[d]; ok {
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, d+": derived signal exempt ("+why+")")
			continue
		}
		gaps = append(gaps, analyze.Gap{Source: "collector", Origin: d, Key: "derived:" + d,
			Reason: d + " turns these logs into another signal; removing lines changes its output"})
	}
	return gaps, nil
}

func (c *Config) vectorGaps(rep *Report) ([]analyze.Gap, error) {
	var files [][]byte
	for _, f := range c.Vector.ConfigFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		files = append(files, b)
	}
	vc, err := topology.LoadVector(files...)
	if err != nil {
		return nil, err
	}
	sinks, derived, err := vc.VectorDownstream(c.Vector.After)
	if err != nil {
		return nil, err
	}
	var gaps []analyze.Gap
	var ids []string
	for id := range sinks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s, ok := c.Vector.Sinks[id]
		switch {
		case ok && s.Loki:
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": analysed Loki")
		case ok && s.OpenSearch != "":
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": opensearch "+s.OpenSearch)
		case ok:
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": exempt ("+s.Exempt+")")
		default:
			gaps = append(gaps, analyze.Gap{Source: "vector", Origin: strings.Join(sinks[id], " > "), Key: "sink:" + id,
				Reason: "removed lines would also vanish from " + id + ", which has no usage evidence"})
		}
	}
	for _, d := range derived {
		if why, ok := c.Vector.Derived[d]; ok {
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, d+": derived signal exempt ("+why+")")
			continue
		}
		gaps = append(gaps, analyze.Gap{Source: "vector", Origin: d, Key: "derived:" + d,
			Reason: d + " turns these logs into metrics; removing lines changes them"})
	}
	return gaps, nil
}

func (c *Config) fluentBitGaps(rep *Report) ([]analyze.Gap, error) {
	var files [][]byte
	for _, f := range c.FluentBit.ConfigFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		files = append(files, b)
	}
	fc, err := topology.LoadFluentBit(files...)
	if err != nil {
		return nil, err
	}
	outs, derived, err := fc.FluentBitDownstream(c.FluentBit.Match, c.FluentBit.After)
	if err != nil {
		return nil, err
	}
	var gaps []analyze.Gap
	var ids []string
	for id := range outs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s, ok := c.FluentBit.Sinks[id]
		switch {
		case ok && s.Loki:
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": analysed Loki")
		case ok && s.OpenSearch != "":
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": opensearch "+s.OpenSearch)
		case ok:
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": exempt ("+s.Exempt+")")
		default:
			gaps = append(gaps, analyze.Gap{Source: "fluentbit", Origin: id + " (" + outs[id] + ")", Key: "sink:" + id,
				Reason: "removed lines would also vanish from output " + id + ", which has no usage evidence"})
		}
	}
	for _, d := range derived {
		if why, ok := c.FluentBit.Derived[d]; ok {
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, d+": exempt ("+why+")")
			continue
		}
		gaps = append(gaps, analyze.Gap{Source: "fluentbit", Origin: d, Key: "derived:" + d,
			Reason: d + " re-emits or counts these records after the enforcement point"})
	}
	return gaps, nil
}
