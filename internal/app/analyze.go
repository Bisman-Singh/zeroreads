package app

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/analyze"
	"github.com/Bisman-Singh/sievelog/internal/logql"
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

// lokiClient is the client for the analysed Loki.
func (c *Config) lokiClient() (*loki.Client, error) {
	return lokiClient(c.Loki.URL, c.Loki.OrgID, c.Loki.Username, "loki", c.Loki.PasswordEnv, c.Loki.BearerTokenEnv)
}

// queryLogClient is the client for the Loki holding Loki's own logs. It gets loki's credentials only
// when it is that same Loki; settings under evidence.query_log override them.
func (c *Config) queryLogClient() (*loki.Client, error) {
	q := c.Evidence.QueryLog
	org, user, passEnv, tokenEnv := q.OrgID, q.Username, q.PasswordEnv, q.BearerTokenEnv
	if strings.TrimRight(q.URL, "/") == strings.TrimRight(c.Loki.URL, "/") {
		org = cmp.Or(org, c.Loki.OrgID)
		if user == "" && tokenEnv == "" {
			user, passEnv, tokenEnv = c.Loki.Username, c.Loki.PasswordEnv, c.Loki.BearerTokenEnv
		}
	}
	return lokiClient(q.URL, org, user, "evidence.query_log", passEnv, tokenEnv)
}

func lokiClient(url, org, user, setting, passwordEnv, tokenEnv string) (*loki.Client, error) {
	password, err := secret(setting+".password_env", passwordEnv)
	if err != nil {
		return nil, err
	}
	token, err := secret(setting+".bearer_token_env", tokenEnv)
	if err != nil {
		return nil, err
	}
	return &loki.Client{Base: url, OrgID: org, Username: user, Password: password, BearerToken: token}, nil
}

func (c *Config) selector(service string) string {
	return "{" + c.Scope.LokiLabel + "=" + strconv.Quote(service) + "}"
}

// linesIn is the log query selecting a service's stored lines in language, which for a structured
// service applies to its templated field; an empty language selects every line.
func (c *Config) linesIn(service, field, language string) string {
	sel := c.selector(service)
	switch {
	case language == "":
		return sel
	case field == "":
		return sel + " |~ " + logql.Quote(language)
	}
	return fmt.Sprintf("%s | json sievelog_field=%s | sievelog_field=~%s", sel, strconv.Quote(field), logql.Quote(language))
}

// rangeOf is a LogQL range covering d, in whole seconds.
func rangeOf(d time.Duration) string { return "[" + strconv.FormatInt(int64(d/time.Second), 10) + "s]" }

// volumeQuery counts (or sums bytes of) a service's stored lines in language over window.
func (c *Config) volumeQuery(fn, service, field, language string, window time.Duration) string {
	return fmt.Sprintf("sum(%s(%s %s))", fn, c.linesIn(service, field, language), rangeOf(window))
}

// Analyze gathers every piece of evidence and decides.
func Analyze(ctx context.Context, c *Config, now time.Time) (*Report, error) {
	rep := &Report{GeneratedAt: now.UTC(), Window: c.Discovery.Window.String(), EvidenceWindow: c.Evidence.Window.String()}
	v, err := templating.DrainVersion()
	if err != nil {
		return nil, fmt.Errorf("reading the embedded drain version, which rules are tied to: %w", err)
	}
	rep.DrainVersion = v
	lc, err := c.lokiClient()
	if err != nil {
		return nil, err
	}
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

	queries, scoped, gaps := c.evidence(ctx, now, services, rep)
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

// readPage is the page size for reading lines: Loki refuses larger pages by default
// (limits_config.max_entries_limit_per_query).
const readPage = 5000

// subWindows is how many pieces a slice's share is read from, so a burst at the start of a slice
// cannot take its whole share.
const subWindows = 20

// sample reads up to SampleLinesPerService lines of a service spread over the window: it counts
// the lines in each slice first, gives each slice a share of the budget proportional to its count,
// and reads each slice's share spread over sub-windows, so bursts neither waste nor exhaust it.
func (c *Config) sample(ctx context.Context, lc *loki.Client, svc string, start, end time.Time) ([]loki.Entry, error) {
	slices := split(start, end, c.Discovery.Slices)
	counts := make([]int, len(slices))
	total := 0
	for i, w := range slices {
		v, err := c.scalar(ctx, lc, c.volumeQuery("count_over_time", svc, "", "", w.End.Sub(w.Start)), w.End)
		if err != nil {
			return nil, err
		}
		counts[i] = int(v)
		total += int(v)
	}
	var out []loki.Entry
	for i, w := range slices {
		if counts[i] == 0 {
			continue
		}
		share := max(int(float64(c.Discovery.SampleLinesPerService)*float64(counts[i])/float64(total)), 1)
		if share >= counts[i] {
			all, err := lc.QueryRange(ctx, c.selector(svc), w.Start, w.End, readPage)
			if err != nil {
				return nil, err
			}
			out = append(out, all...)
			continue
		}
		parts := min(subWindows, share)
		for _, sw := range split(w.Start, w.End, parts) {
			part, err := lc.Sample(ctx, c.selector(svc), sw.Start, sw.End, (share+parts-1)/parts)
			if err != nil {
				return nil, err
			}
			out = append(out, part...)
		}
	}
	return out, nil
}

// split divides [start, end) into n consecutive windows; the last one ends exactly at end.
func split(start, end time.Time, n int) []Window {
	step := end.Sub(start) / time.Duration(n)
	out := make([]Window, n)
	for i := range out {
		out[i] = Window{Start: start.Add(time.Duration(i) * step), End: start.Add(time.Duration(i+1) * step)}
	}
	out[n-1].End = end
	return out
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
	lines := c.templatedTexts(entries, field)
	var notes []string
	if lines.unstructured > 0 {
		notes = append(notes, fmt.Sprintf("%s: %d sampled lines are not JSON records with a string %q field; they get no rule", svc, lines.unstructured, field))
	}
	if len(lines.inputs) == 0 {
		return nil, nil, notes, nil
	}
	tmpls, err := c.templates(ctx, field, lines.inputs)
	if err != nil {
		return nil, nil, nil, err
	}
	groups := map[string][]string{}
	levelsBy := map[string]map[string]bool{}
	for i, t := range tmpls {
		groups[t] = append(groups[t], lines.texts[i])
		if lines.levels[i] != "" {
			if levelsBy[t] == nil {
				levelsBy[t] = map[string]bool{}
			}
			levelsBy[t][lines.levels[i]] = true
		}
	}
	m := measure{lc: lc, svc: svc, field: field, window: end.Sub(start), end: end, streamLabels: streamLabels}
	var cands []analyze.Candidate
	var skipped []Skipped
	for _, tpl := range slices.Sorted(maps.Keys(groups)) {
		cand, skip, err := c.candidate(ctx, m, tpl, groups[tpl], slices.Sorted(maps.Keys(levelsBy[tpl])))
		switch {
		case err != nil:
			return nil, nil, nil, err
		case skip != nil:
			skipped = append(skipped, *skip)
		default:
			cands = append(cands, cand)
		}
	}
	return cands, skipped, notes, nil
}

// templatedLines are a service's sampled lines as drain templates them: the whole line, or the
// templated field of a structured record, with the level each line carries (aligned by index).
type templatedLines struct {
	inputs       []templating.Input
	texts        []string
	levels       []string
	unstructured int // records of a structured service without a string field: they get no rule
}

func (c *Config) templatedTexts(entries []loki.Entry, field string) templatedLines {
	var out templatedLines
	for _, e := range entries {
		if field == "" {
			out.inputs = append(out.inputs, templating.Input{Body: e.Line})
			out.texts = append(out.texts, e.Line)
			out.levels = append(out.levels, c.levelOf(e, nil))
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(e.Line), &m); err != nil {
			out.unstructured++
			continue
		}
		v, ok := m[field].(string)
		if !ok {
			out.unstructured++
			continue
		}
		out.inputs = append(out.inputs, templating.Input{Fields: m})
		out.texts = append(out.texts, v)
		out.levels = append(out.levels, c.levelOf(e, m))
	}
	return out
}

// levelOf reads a line's level from Loki's labels and structured metadata (dots become underscores
// there) and, for structured records, from the record's own fields.
func (c *Config) levelOf(e loki.Entry, record map[string]any) string {
	for _, k := range c.Scope.SeverityKeys {
		if v := e.Labels[k]; v != "" {
			return v
		}
		if v := e.Labels[strings.ReplaceAll(k, ".", "_")]; v != "" {
			return v
		}
		if v, ok := record[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// templates runs the embedded drain processor over the inputs twice: the first pass converges the
// parse tree, the second assigns every line its final template, so early lines are not left under
// cold-start literal templates.
func (c *Config) templates(ctx context.Context, field string, inputs []templating.Input) ([]string, error) {
	dcfg := templating.DefaultConfig()
	dcfg.BodyField = field
	for _, m := range c.Drain.MaskingRules {
		dcfg.MaskingRules = append(dcfg.MaskingRules, templating.MaskRule{Name: m.Name, Pattern: m.Pattern})
	}
	dcfg.SeedTemplates = c.Drain.SeedTemplates
	eng, err := templating.New(ctx, dcfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = eng.Close(ctx) }() // templating is done; a failed shutdown loses nothing
	if _, err := eng.Template(ctx, inputs); err != nil {
		return nil, err
	}
	return eng.Template(ctx, inputs)
}

// measure is where a service's templates are measured.
type measure struct {
	lc           *loki.Client
	svc, field   string
	window       time.Duration
	end          time.Time
	streamLabels map[string]bool
}

// candidate infers one template's exact language from its samples and measures its volume in Loki.
// A template without enough samples is skipped, with the reason.
func (c *Config) candidate(ctx context.Context, m measure, tpl string, samples, levels []string) (analyze.Candidate, *Skipped, error) {
	if tpl == "" {
		return analyze.Candidate{}, &Skipped{Service: m.svc, Samples: len(samples), Reason: "no template (drain warm-up)"}, nil
	}
	var masks []rule.Mask
	for _, mr := range c.Drain.MaskingRules {
		masks = append(masks, rule.Mask{Name: mr.Name, Pattern: mr.Pattern})
	}
	opt := rule.DefaultOptions()
	opt.MinSamples = c.Discovery.MinSamples
	lang, err := rule.Infer(tpl, masks, samples, opt)
	if errors.Is(err, rule.ErrTooFewSamples) {
		return analyze.Candidate{}, &Skipped{Service: m.svc, Template: tpl, Samples: len(samples), Reason: err.Error()}, nil
	}
	if err != nil {
		return analyze.Candidate{}, nil, fmt.Errorf("template %q: %w", tpl, err)
	}
	constant := !slices.ContainsFunc(lang.Positions, func(p rule.Position) bool { return p.Kind != "literal" })
	lines, err := c.scalar(ctx, m.lc, c.volumeQuery("count_over_time", m.svc, m.field, lang.Regex, m.window), m.end)
	if err != nil {
		return analyze.Candidate{}, nil, fmt.Errorf("measuring %q: %w", tpl, err)
	}
	bytes, err := c.scalar(ctx, m.lc, c.volumeQuery("bytes_over_time", m.svc, m.field, lang.Regex, m.window), m.end)
	if err != nil {
		return analyze.Candidate{}, nil, fmt.Errorf("measuring %q: %w", tpl, err)
	}
	return analyze.Candidate{
		Service: m.svc, Scope: map[string]string{c.Scope.LokiLabel: m.svc}, Template: tpl, Language: lang.Regex,
		Structured: m.field != "", Field: m.field, Constant: constant, Samples: lang.Samples,
		Lines: lines, Bytes: bytes, Window: m.window, Severities: levels, StreamLabels: m.streamLabels,
	}, nil, nil
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
	bySvc := map[string][]int{}
	var svcs []string
	for i, r := range recs {
		if !removes(r.Action) {
			continue
		}
		if _, ok := bySvc[r.Candidate.Service]; !ok {
			svcs = append(svcs, r.Candidate.Service)
		}
		bySvc[r.Candidate.Service] = append(bySvc[r.Candidate.Service], i)
	}
	for _, svc := range svcs {
		sc := streamCount{c: c, lc: lc, recs: recs, svc: svc, rng: rangeOf(now.Sub(start)), at: now,
			labels: slices.Sorted(maps.Keys(recs[bySvc[svc][0]].Candidate.StreamLabels))}
		if err := sc.keep(ctx, bySvc[svc]); err != nil {
			return fmt.Errorf("counting streams of %s: %w", svc, err)
		}
	}
	return nil
}

// streamCount counts one service's streams with and without the lines of some rules.
type streamCount struct {
	c      *Config
	lc     *loki.Client
	recs   []analyze.Recommendation
	svc    string
	labels []string // the stream label names: one stream per distinct label set
	rng    string
	at     time.Time
}

// keep blocks each rule that alone empties a stream, then all the remaining rules together if
// together they would.
func (sc streamCount) keep(ctx context.Context, idx []int) error {
	before, err := sc.streams(ctx, nil)
	if err != nil {
		return err
	}
	for _, i := range idx {
		after, err := sc.streams(ctx, []int{i})
		if err != nil {
			return err
		}
		if after < before {
			blockRemoval(&sc.recs[i], fmt.Sprintf("%.0f of %.0f streams hold only these lines; removing them would make those streams disappear", before-after, before))
		}
	}
	var left []int
	for _, i := range idx {
		if removes(sc.recs[i].Action) {
			left = append(left, i)
		}
	}
	if len(left) < 2 {
		return nil
	}
	after, err := sc.streams(ctx, left)
	if err != nil {
		return err
	}
	if after < before {
		for _, i := range left {
			blockRemoval(&sc.recs[i], fmt.Sprintf("together with the other rules of %s, removing these lines would empty %.0f streams", sc.svc, before-after))
		}
	}
	return nil
}

// streams counts the service's streams that keep a line once the given rules' lines are gone.
func (sc streamCount) streams(ctx context.Context, rules []int) (float64, error) {
	var line, field []string
	for _, i := range rules {
		cd := sc.recs[i].Candidate
		if cd.Structured {
			field = append(field, fmt.Sprintf("| json sievelog_f%d=%s | sievelog_f%d!~%s", i, strconv.Quote(cd.Field), i, logql.Quote(cd.Language)))
		} else {
			line = append(line, "!~ "+logql.Quote(cd.Language))
		}
	}
	q := sc.c.selector(sc.svc)
	if len(line) > 0 {
		q += " " + strings.Join(line, " ")
	}
	if len(field) > 0 {
		// A line that is not JSON is dropped here, so it can only count as removed: the check errs
		// towards blocking.
		q += " " + strings.Join(field, " ") + ` | __error__=""`
	}
	return sc.c.scalar(ctx, sc.lc, fmt.Sprintf("count(sum by (%s) (count_over_time(%s %s)))", strings.Join(sc.labels, ", "), q, sc.rng), sc.at)
}

// blockRemoval takes a rule's action away, with the reason.
func blockRemoval(rec *analyze.Recommendation, why string) {
	rec.Action, rec.Keep, rec.RemovedBytesPerDay, rec.Rewrites = "none", 0, 0, nil
	rec.Blockers = append(rec.Blockers, why)
}

// evidence reads every usage source. Anything that cannot be read becomes a gap with a stable key.
func (c *Config) evidence(ctx context.Context, now time.Time, services []string, rep *Report) ([]analyze.UsageQuery, []analyze.ScopedReader, []analyze.Gap) {
	from := now.Add(-c.Evidence.Window.Duration)
	var qs []analyze.UsageQuery
	var gaps []analyze.Gap
	for _, source := range []func() ([]analyze.UsageQuery, []analyze.Gap){
		func() ([]analyze.UsageQuery, []analyze.Gap) { return c.queryLogEvidence(ctx, from, now, rep) },
		func() ([]analyze.UsageQuery, []analyze.Gap) { return c.rulerEvidence(ctx, rep) },
		func() ([]analyze.UsageQuery, []analyze.Gap) { return c.grafanaEvidence(ctx, rep) },
	} {
		q, g := source()
		qs, gaps = append(qs, q...), append(gaps, g...)
	}
	scoped, og := c.openSearchEvidence(ctx, from, now, services, rep)
	return qs, scoped, append(gaps, og...)
}

func queryLogGap(key, reason string) analyze.Gap {
	return analyze.Gap{Source: "loki", Origin: "query-log", Key: key, Reason: reason}
}

// markerTimeout is how long a marker query, tail or pattern request may take to reach the query
// log: Loki's own logs pass through the collection pipeline first.
const markerTimeout = 2 * time.Minute

// queryLogEvidence reads the queries Loki executed, after proving the query log records them.
func (c *Config) queryLogEvidence(ctx context.Context, from, now time.Time, rep *Report) ([]analyze.UsageQuery, []analyze.Gap) {
	if !c.Evidence.QueryLog.Enabled {
		return nil, []analyze.Gap{queryLogGap("querylog-disabled", "the Loki query log is not read, so executed queries are unknown")}
	}
	logs, err := c.queryLogClient()
	if err != nil {
		return nil, []analyze.Gap{queryLogGap("querylog-unreadable", err.Error())}
	}
	target, err := c.lokiClient()
	if err != nil {
		return nil, []analyze.Gap{queryLogGap("querylog-unreadable", err.Error())}
	}
	ql := &loki.QueryLog{Logs: logs, Selector: c.Evidence.QueryLog.Selector}
	gaps := c.proveQueryLog(ctx, ql, target, rep)
	res, err := ql.Read(ctx, from, now)
	if err != nil {
		return nil, append(gaps, queryLogGap("querylog-unreadable", err.Error()))
	}
	rep.Evidence.QueryLogQueries = len(res.Queries)
	rep.Evidence.QueryLogLines = res.Lines
	rep.Evidence.QueryLogOldest = res.Oldest
	if res.Unparsed > 0 {
		gaps = append(gaps, queryLogGap("querylog-unparsed", fmt.Sprintf("%d query-log lines did not parse", res.Unparsed)))
	}
	// Loki's own logs arrive in batches, so the oldest line trails the window start a little even
	// when the log covers it: allow 1% of the window, between a minute and an hour.
	tolerance := min(max(c.Evidence.Window.Duration/100, time.Minute), time.Hour)
	if res.Oldest.IsZero() || res.Oldest.After(from.Add(tolerance)) {
		gaps = append(gaps, queryLogGap("querylog-window",
			fmt.Sprintf("the query log starts at %s, after the evidence window start %s", res.Oldest.UTC().Format(time.RFC3339), from.UTC().Format(time.RFC3339))))
	}
	var qs []analyze.UsageQuery
	for _, q := range res.Queries {
		qs = append(qs, analyze.UsageQuery{Source: "loki-querylog", Origin: "query-log (" + q.Component + ")", Expr: q.Query, Count: q.Count, Last: q.Last})
	}
	return qs, gaps
}

// proveQueryLog sends a marker query, tail and pattern request and waits for each in the query log.
// Tails and pattern requests (Logs Drilldown) are logged by other lines under other settings, so
// each is proven on its own; an endpoint the target does not serve has no users.
func (c *Config) proveQueryLog(ctx context.Context, ql *loki.QueryLog, target *loki.Client, rep *Report) []analyze.Gap {
	rep.Evidence.QueryLogLive = "not checked"
	if !c.Evidence.QueryLog.ProveLive {
		return []analyze.Gap{queryLogGap("querylog-not-proven",
			"evidence.query_log.prove_live is off, so it is not proven that queries, live tails and pattern requests are logged")}
	}
	var gaps []analyze.Gap
	if err := ql.ProveLive(ctx, target, markerTimeout); err != nil {
		rep.Evidence.QueryLogLive = err.Error()
		gaps = append(gaps, queryLogGap("querylog-not-live", err.Error()))
	} else {
		rep.Evidence.QueryLogLive = "proven with a marker query"
	}
	for _, p := range []struct {
		key   string
		prove func(context.Context, *loki.Client, time.Duration) error
		what  string
	}{
		{"querylog-tail-not-visible", ql.ProveTail, "live tails"},
		{"querylog-patterns-not-visible", ql.ProvePatterns, "pattern requests"},
	} {
		switch err := p.prove(ctx, target, markerTimeout); {
		case errors.Is(err, loki.ErrNotServed):
			rep.Notes = append(rep.Notes, "Loki does not serve "+p.what+", so none can read the lines")
		case err != nil:
			gaps = append(gaps, queryLogGap(p.key, err.Error()))
		}
	}
	return gaps
}

// rulerEvidence reads the Loki ruler's alerting and recording rules.
func (c *Config) rulerEvidence(ctx context.Context, rep *Report) ([]analyze.UsageQuery, []analyze.Gap) {
	gap := func(key, reason string) []analyze.Gap {
		return []analyze.Gap{{Source: "loki", Origin: "ruler", Key: key, Reason: reason}}
	}
	if !c.Evidence.Ruler {
		return nil, gap("ruler-not-checked", "Loki ruler rules are not read")
	}
	lc, err := c.lokiClient()
	if err != nil {
		return nil, gap("ruler-unreadable", err.Error())
	}
	rules, err := lc.Rules(ctx)
	if err != nil {
		return nil, gap("ruler-unreadable", err.Error())
	}
	rep.Evidence.RulerRules = len(rules)
	var qs []analyze.UsageQuery
	for _, r := range rules {
		qs = append(qs, analyze.UsageQuery{Source: "loki-ruler", Origin: fmt.Sprintf("%s/%s/%s (%s)", r.Namespace, r.Group, r.Name, r.Kind), Expr: r.Expr,
			Store: "loki-ruler", StoreURL: c.Loki.URL, Path: r.Namespace + "/" + r.Group + "/" + r.Name})
	}
	return qs, nil
}

// grafanaEvidence reads every stored query from every configured Grafana.
func (c *Config) grafanaEvidence(ctx context.Context, rep *Report) ([]analyze.UsageQuery, []analyze.Gap) {
	if len(c.Evidence.Grafana) == 0 {
		return nil, []analyze.Gap{{Source: "grafana", Origin: "config", Key: "grafana-not-configured", Reason: "no Grafana is configured; dashboards, alerts and saved links elsewhere are unknown"}}
	}
	var qs []analyze.UsageQuery
	var gaps []analyze.Gap
	for _, g := range c.Evidence.Grafana {
		q, gp := c.readGrafana(ctx, g, rep)
		qs, gaps = append(qs, q...), append(gaps, gp...)
	}
	return qs, gaps
}

func (c *Config) readGrafana(ctx context.Context, g GrafanaConfig, rep *Report) ([]analyze.UsageQuery, []analyze.Gap) {
	unreadable := func(err error) []analyze.Gap {
		return []analyze.Gap{{Source: "grafana", Origin: g.URL, Key: "grafana-unreadable", Reason: err.Error()}}
	}
	gc, err := g.client()
	if err != nil {
		return nil, unreadable(err)
	}
	res, err := gc.Read(ctx)
	if err != nil {
		return nil, unreadable(err)
	}
	want, gaps := c.analysedDatasources(g, res.LokiDatasources)
	var qs []analyze.UsageQuery
	for _, q := range res.Queries {
		if !slices.ContainsFunc(q.Datasources, func(d string) bool { return want[d] }) {
			continue // runs against a different Loki
		}
		rep.Evidence.GrafanaQueries++
		qs = append(qs, analyze.UsageQuery{Source: "grafana", Origin: fmt.Sprintf("%s org %d %s", g.URL, q.Org, q.Origin), Expr: q.Expr,
			Store: "grafana", StoreURL: g.URL, Org: q.Org, Path: q.Origin})
	}
	for _, n := range res.Notes {
		rep.Notes = append(rep.Notes, fmt.Sprintf("grafana %s org %d %s: %s", g.URL, n.Org, n.Origin, n.Reason))
	}
	for _, gp := range res.Gaps {
		gaps = append(gaps, analyze.Gap{Source: "grafana", Origin: fmt.Sprintf("org %d %s", gp.Org, gp.Origin), Key: grafanaGapKey(g.URL, gp), Reason: gp.Reason})
	}
	return qs, gaps
}

// grafanaGapKey names what a Grafana gap is about. A gap about one object (dashboard:uid/panel:3,
// shorturl:id) names that object, with its Grafana and org, so acknowledging it accepts that object
// only and not the next one that fails. A gap about a whole kind (every alert rule, query history)
// is named by the kind.
func grafanaGapKey(grafanaURL string, g grafana.Gap) string {
	kind, _, object := strings.Cut(g.Origin, ":")
	kind, _, _ = strings.Cut(kind, "/")
	if !object {
		return "grafana-" + kind
	}
	host := strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(grafanaURL, "https://"), "http://"), "/")
	return fmt.Sprintf("grafana-%s:%s/org%d/%s", kind, host, g.Org, g.Origin)
}

// analysedDatasources returns the Loki datasources whose queries read the analysed Loki: listed in
// datasources, or pointing at exactly loki.url. A Loki datasource that is neither listed nor declared
// other counts too, and is a gap until the config says which Loki it is: a forgotten entry must
// never hide readers.
func (c *Config) analysedDatasources(g GrafanaConfig, byOrg map[int64]map[string]string) (map[string]bool, []analyze.Gap) {
	want := map[string]bool{grafana.AnyLoki: true}
	for _, d := range g.Datasources {
		want[d] = true
	}
	var unmapped []string
	for org, dss := range byOrg {
		for uid, u := range dss {
			switch {
			case want[uid] || slices.Contains(g.OtherDatasources, uid):
			case strings.TrimRight(u, "/") == strings.TrimRight(c.Loki.URL, "/"):
				want[uid] = true
			default:
				want[uid] = true
				unmapped = append(unmapped, fmt.Sprintf("%s (org %d, %s)", uid, org, u))
			}
		}
	}
	if len(unmapped) == 0 {
		return want, nil
	}
	sort.Strings(unmapped)
	return want, []analyze.Gap{{Source: "grafana", Origin: g.URL, Key: "grafana-datasource-unmapped",
		Reason: "these Loki datasources are in neither datasources nor other_datasources, so their queries count as reading the analysed Loki: " + strings.Join(unmapped, ", ")}}
}

// topologyGaps checks every destination downstream of the enforcement point.
func (c *Config) topologyGaps(rep *Report) ([]analyze.Gap, error) {
	var d destinations
	var err error
	switch c.Runtime {
	case "vector":
		d, err = c.vectorDestinations()
	case "fluentbit":
		d, err = c.fluentBitDestinations()
	default:
		d, err = c.collectorDestinations()
	}
	if err != nil {
		return nil, err
	}
	return d.gaps(rep), nil
}

// destinations are what lines reach after the enforcement point, in one runtime.
type destinations struct {
	runtime    string            // the gap source
	sinks      map[string]string // sink ID -> how the lines get there
	configured map[string]Sink   // what the config says each sink is
	derived    []string          // components that turn the lines into another signal
	exempt     map[string]string // derived components the config accepts, with the reason
	derivedWhy string            // what a derived component does to the lines
}

// gaps records every destination the evidence covers (the analysed Loki, a connected OpenSearch,
// an exemption) and returns a gap for every other one: removing lines there is unobserved.
func (d destinations) gaps(rep *Report) []analyze.Gap {
	var gaps []analyze.Gap
	for _, id := range slices.Sorted(maps.Keys(d.sinks)) {
		s, ok := d.configured[id]
		switch {
		case ok && s.Loki:
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": analysed Loki")
		case ok && s.OpenSearch != "":
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": opensearch "+s.OpenSearch)
		case ok:
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, id+": exempt ("+s.Exempt+")")
		default:
			gaps = append(gaps, analyze.Gap{Source: d.runtime, Origin: d.sinks[id], Key: "sink:" + id,
				Reason: "removed lines would also vanish from " + id + ", which has no usage evidence"})
		}
	}
	for _, x := range d.derived {
		if why, ok := d.exempt[x]; ok {
			rep.Evidence.Sinks = append(rep.Evidence.Sinks, x+": derived signal exempt ("+why+")")
			continue
		}
		gaps = append(gaps, analyze.Gap{Source: d.runtime, Origin: x, Key: "derived:" + x, Reason: x + " " + d.derivedWhy})
	}
	return gaps
}

// readFiles reads the operator's pipeline configuration files, in order.
func readFiles(paths []string) ([][]byte, error) {
	var files [][]byte
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		files = append(files, b)
	}
	return files, nil
}

func (c *Config) collectorDestinations() (destinations, error) {
	files, err := readFiles(c.Collector.ConfigFiles)
	if err != nil {
		return destinations{}, err
	}
	tc, err := topology.Load(files...)
	if err != nil {
		return destinations{}, err
	}
	p, ok := tc.Pipelines[c.Collector.Pipeline]
	if !ok {
		return destinations{}, fmt.Errorf("collector pipeline %s not found", c.Collector.Pipeline)
	}
	after := -1
	if c.Collector.After != "" {
		if after = slices.Index(p.Processors, c.Collector.After); after < 0 {
			return destinations{}, fmt.Errorf("processor %s not in pipeline %s", c.Collector.After, c.Collector.Pipeline)
		}
	}
	reach, err := tc.Downstream(c.Collector.Pipeline, after)
	if err != nil {
		return destinations{}, err
	}
	sinks := map[string]string{}
	for id, path := range reach.Exporters {
		sinks[id] = strings.Join(path, " > ")
	}
	return destinations{runtime: "collector", sinks: sinks, configured: c.Collector.Sinks, derived: reach.Derived, exempt: c.Collector.Derived,
		derivedWhy: "turns these logs into another signal; removing lines changes its output"}, nil
}

func (c *Config) vectorDestinations() (destinations, error) {
	files, err := readFiles(c.Vector.ConfigFiles)
	if err != nil {
		return destinations{}, err
	}
	vc, err := topology.LoadVector(files...)
	if err != nil {
		return destinations{}, err
	}
	reach, derived, err := vc.VectorDownstream(c.Vector.After)
	if err != nil {
		return destinations{}, err
	}
	sinks := map[string]string{}
	for id, path := range reach {
		sinks[id] = strings.Join(path, " > ")
	}
	return destinations{runtime: "vector", sinks: sinks, configured: c.Vector.Sinks, derived: derived, exempt: c.Vector.Derived,
		derivedWhy: "turns these logs into metrics; removing lines changes them"}, nil
}

func (c *Config) fluentBitDestinations() (destinations, error) {
	files, err := readFiles(c.FluentBit.ConfigFiles)
	if err != nil {
		return destinations{}, err
	}
	fc, err := topology.LoadFluentBit(files...)
	if err != nil {
		return destinations{}, err
	}
	outs, derived, err := fc.FluentBitDownstream(c.FluentBit.Match, c.FluentBit.After)
	if err != nil {
		return destinations{}, err
	}
	sinks := map[string]string{}
	for id, plugin := range outs {
		sinks[id] = id + " (" + plugin + ")"
	}
	return destinations{runtime: "fluentbit", sinks: sinks, configured: c.FluentBit.Sinks, derived: derived, exempt: c.FluentBit.Derived,
		derivedWhy: "re-emits or counts these records after the enforcement point"}, nil
}
