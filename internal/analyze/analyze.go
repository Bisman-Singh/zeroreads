// Package analyze decides, for every candidate rule, whether a line-removing action is safe, and
// writes down why. It does no I/O: evidence comes in, recommendations with their ledger come out.
package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
	"github.com/Bisman-Singh/sievelog/internal/emit"
	"github.com/Bisman-Singh/sievelog/internal/logql"
	"github.com/Bisman-Singh/sievelog/internal/rewrite"
	"github.com/Bisman-Singh/sievelog/internal/usage"
)

// Candidate is one inferred rule with its measured volume.
type Candidate struct {
	Service    string            // scope value, e.g. checkout
	Scope      map[string]string // backend labels, e.g. {"service_name": "checkout"}
	Template   string
	Language   string // anchored RE2 removal language
	Structured bool   // Language applies to Field of a structured record
	Field      string
	Constant   bool // every position is a fixed literal: all removed lines are identical
	Samples    int
	// Volume of lines in Language over Window, measured by the backend.
	Lines  float64
	Bytes  float64
	Window time.Duration
	// Severities seen on sampled lines (from the pipeline or backend metadata).
	Severities []string
	// StreamLabels are the index label names of the service's streams in the backend; a counting
	// query grouped by any other label cannot be rewritten for a rollup.
	StreamLabels map[string]bool
}

// ID is stable for the same scope and language.
func (c Candidate) ID() string {
	h := sha256.Sum256([]byte(c.Service + "\x00" + c.Field + "\x00" + c.Language))
	return "r-" + hex.EncodeToString(h[:6])
}

// UsageQuery is one query that can read logs, from any evidence source.
type UsageQuery struct {
	Source string // loki-querylog | loki-ruler | grafana
	Origin string // where it lives: dashboard/panel, rule name, ...
	Expr   string
	Count  int       // executions seen (query log); 0 for stored queries
	Last   time.Time // last execution (query log)
	// Where a stored query lives, when it can be rewritten in place: Store is grafana or loki-ruler,
	// StoreURL the Grafana or Loki base URL, Org the Grafana org, Path the object inside it
	// (dashboard:uid/panel:id/refId, alertrule:uid/i, ... or namespace/group/rule for the ruler).
	Store, StoreURL, Path string
	Org                   int64
}

// Rewrite is one stored query rewritten so a rollup keeps its numbers.
type Rewrite struct {
	Source, Origin        string
	Store, StoreURL, Path string
	Org                   int64
	Old, New              string
}

// ScopedReader is a query in a store other than Loki that may read every line of one service.
type ScopedReader struct {
	Service, Source, Origin, Expr, Reason string
}

// Gap is missing evidence.
type Gap struct {
	Source, Origin, Reason string
	// Key identifies the kind of gap so a policy can acknowledge it deliberately.
	Key string
}

// Policy is the operator's settings.
type Policy struct {
	// Actions in order of preference. Allowed: aggregate, dedupe, sample, drop.
	Actions []string
	// SamplePercent is the share of lines a sample rule keeps.
	SamplePercent int
	// Acknowledged gap keys: the operator accepts that evidence is missing there.
	Acknowledged []string
	// Exempt rule IDs or template regexes: never acted on.
	Exempt []string
	// ErrorPattern marks lines as error-like; such rules are never acted on.
	ErrorPattern string
	// MinDailyBytes skips rules too small to matter.
	MinDailyBytes float64
}

// severe is the runtime guard's notion of warning or above, so analysis and enforcement agree.
var severe = regexp.MustCompile(emit.SeverePattern)

// DefaultErrorPattern flags any language that can contain an error-like word.
const DefaultErrorPattern = `(?i)(?:\b|_)(?:err|error|errors|warn|warning|fatal|crit|critical|panic|exception|fail|failed|failure|denied|refused|timeout|timed out|unavailable|declined|emerg|alert)(?:\b|_)`

// DefaultPolicy keeps every line recoverable as a count and never drops outright.
func DefaultPolicy() Policy {
	return Policy{Actions: []string{"aggregate", "dedupe", "sample"}, SamplePercent: 10, ErrorPattern: DefaultErrorPattern}
}

// Reader is one query that reads a rule's lines.
type Reader struct {
	Source, Origin, Expr string
	Counting             bool
	Witness              string
	Reason               string
	Rewrite              *Rewrite // set when a rollup can keep this reader's numbers
	// Compensated is true for a query sievelog already rewrote for a rollup of this rule: its
	// raw-line term reads the lines, and only a rollup keeps its numbers.
	Compensated bool
}

// Recommendation is the decision for one candidate.
type Recommendation struct {
	ID        string
	Candidate Candidate
	Action    string // none | aggregate | dedupe | sample | drop | rollup
	Keep      int    // percent kept for sample
	Readers   []Reader
	Blockers  []string
	// Rewrites must be applied for a rollup to keep every reader's numbers.
	Rewrites []Rewrite
	// RemovedBytesPerDay is the measured bytes/day this action removes (0 for none). For dedupe it is
	// an upper bound until shadow mode measures it.
	RemovedBytesPerDay float64
	UpperBound         bool
}

// Decide produces one recommendation per candidate.
func Decide(cands []Candidate, queries []UsageQuery, scoped []ScopedReader, gaps []Gap, pol Policy) ([]Recommendation, error) {
	errRe, err := automaton.Compile(pol.ErrorPattern)
	if err != nil {
		return nil, fmt.Errorf("analyze: error pattern: %w", err)
	}
	for _, a := range pol.Actions {
		switch a {
		case "aggregate", "dedupe", "sample", "drop", "rollup":
		default:
			return nil, fmt.Errorf("analyze: unknown action %q", a)
		}
	}
	var exemptRes []*regexp.Regexp
	exemptIDs := map[string]bool{}
	for _, e := range pol.Exempt {
		if strings.HasPrefix(e, "r-") {
			exemptIDs[e] = true
			continue
		}
		re, err := regexp.Compile(e)
		if err != nil {
			return nil, fmt.Errorf("analyze: exempt %q: %w", e, err)
		}
		exemptRes = append(exemptRes, re)
	}
	ack := map[string]bool{}
	for _, k := range pol.Acknowledged {
		ack[k] = true
	}
	var blockingGaps []string
	for _, g := range gaps {
		if !ack[g.Key] {
			blockingGaps = append(blockingGaps, fmt.Sprintf("evidence gap %q (%s %s): %s", g.Key, g.Source, g.Origin, g.Reason))
		}
	}
	sort.Strings(blockingGaps)

	// Parse every query once. A query that does not parse reads everything and counts.
	type parsed struct {
		q      UsageQuery
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

	rollup := false
	for _, a := range pol.Actions {
		if a == "rollup" {
			rollup = true
		}
	}
	languages := make(map[string]string, len(cands))
	for _, c := range cands {
		languages[c.ID()] = c.Language
	}
	var out []Recommendation
	for _, c := range cands {
		rec := Recommendation{ID: c.ID(), Candidate: c, Action: "none"}
		lang, err := automaton.Compile(c.Language)
		if err != nil {
			return nil, fmt.Errorf("analyze: %s: language: %w", rec.ID, err)
		}
		rule := usage.Rule{ID: rec.ID, Scope: c.Scope, Language: lang, Structured: c.Structured}
		for _, p := range pqs {
			if p.err != nil {
				rec.Readers = append(rec.Readers, Reader{Source: p.q.Source, Origin: p.q.Origin, Expr: p.q.Expr, Counting: true,
					Reason: "query does not parse (" + p.err.Error() + "); treated as reading and counting every line"})
				continue
			}
			for _, sel := range p.sel {
				if rewrite.Compensated(p.parsed, sel, rec.ID, languages) {
					// A sievelog rewrite's raw-line term: summed with the rollup counts, it keeps the
					// query's numbers only if this rule is rolled up.
					rec.Readers = append(rec.Readers, Reader{Source: p.q.Source, Origin: p.q.Origin, Expr: p.q.Expr, Counting: true, Compensated: true,
						Reason: "already rewritten for a rollup of these lines; any other removal changes its count"})
					break
				}
				v := usage.Evaluate(sel, rule)
				if v.Used {
					rd := Reader{Source: p.q.Source, Origin: p.q.Origin, Expr: p.q.Expr, Counting: v.Counting, Witness: v.Witness, Reason: v.Reason}
					if rollup && !c.Structured {
						rd.Rewrite = rewriteFor(p.q, rec.ID, c)
					}
					rec.Readers = append(rec.Readers, rd)
					break
				}
			}
		}
		rollupOK := rollup && !c.Structured && len(rec.Readers) > 0
		for i, rd := range rec.Readers {
			if rd.Rewrite != nil || rd.Compensated {
				continue
			}
			// An executed query (query log) is covered when it is exactly a stored query being rewritten.
			if rd.Source == "loki-querylog" {
				for _, o := range rec.Readers {
					if o.Rewrite != nil && logql.Canonical(o.Expr) == logql.Canonical(rd.Expr) {
						cp := *o.Rewrite
						cp.Source, cp.Origin, cp.Store, cp.Path = rd.Source, rd.Origin, "", ""
						rec.Readers[i].Rewrite = &cp
						break
					}
				}
				if rec.Readers[i].Rewrite != nil {
					continue
				}
			}
			rollupOK = false
		}
		// Rollup records are new lines in the rule's streams: any other query that can select them
		// would count or show them, so it rules a rollup out (and nothing else).
		var rollupBlockedBy []string
		replaced := map[string]bool{}
		for _, rd := range rec.Readers {
			if rd.Rewrite != nil || rd.Compensated {
				replaced[logql.Canonical(rd.Expr)] = true
			}
		}
		if rollup && !c.Structured {
			for _, p := range pqs {
				if p.err != nil || replaced[logql.Canonical(p.q.Expr)] {
					continue // already a reader of everything, or replaced by this rule's rewrite
				}
				for _, sel := range p.sel {
					if rewrite.ReadsRollups(sel, rec.ID, c.Scope) {
						rollupBlockedBy = append(rollupBlockedBy, fmt.Sprintf("%s %s would also select this rule's rollup records: %s", p.q.Source, p.q.Origin, p.q.Expr))
						break
					}
				}
			}
		}
		if len(rollupBlockedBy) > 0 {
			rollupOK = false
		}
		for _, sr := range scoped {
			if sr.Service == c.Service {
				rec.Readers = append(rec.Readers, Reader{Source: sr.Source, Origin: sr.Origin, Expr: sr.Expr, Counting: true, Reason: sr.Reason})
				rollupOK = false // only Loki queries can be rewritten for a rollup
			}
		}
		// Blockers, in the order an operator should read them.
		rec.Blockers = append(rec.Blockers, blockingGaps...)
		if len(rec.Readers) > 0 && !rollupOK {
			rec.Blockers = append(rec.Blockers, fmt.Sprintf("%d quer%s read these lines", len(rec.Readers), plural(len(rec.Readers), "y", "ies")))
		}
		if w, found, err := automaton.Intersects(lang, errRe, 0); err != nil || found {
			if err != nil {
				rec.Blockers = append(rec.Blockers, "could not prove the lines are not error-like: "+err.Error())
			} else {
				rec.Blockers = append(rec.Blockers, fmt.Sprintf("lines can be error-like, e.g. %q", w))
			}
		}
		for _, s := range c.Severities {
			if severe.MatchString(s) {
				rec.Blockers = append(rec.Blockers, "sampled lines carry severity "+s)
			}
		}
		if exemptIDs[rec.ID] {
			rec.Blockers = append(rec.Blockers, "exempt by policy")
		}
		for _, re := range exemptRes {
			if re.MatchString(c.Template) {
				rec.Blockers = append(rec.Blockers, "template exempt by policy ("+re.String()+")")
			}
		}
		perDay := 0.0
		if c.Window > 0 {
			perDay = c.Bytes / c.Window.Hours() * 24
		}
		if perDay < pol.MinDailyBytes {
			rec.Blockers = append(rec.Blockers, fmt.Sprintf("only %.0f bytes/day, under the policy minimum", perDay))
		}
		if len(rec.Blockers) == 0 {
			for _, a := range pol.Actions {
				if a == "dedupe" && !c.Constant {
					continue // dedupe only keeps every line's content when all lines are identical
				}
				if a == "rollup" && c.Structured {
					continue // a rollup record replaces the whole line; field rules cannot be rewritten
				}
				if len(rec.Readers) > 0 && a != "rollup" {
					continue // only a rollup with its rewrites keeps readers' numbers
				}
				if a == "rollup" && len(rollupBlockedBy) > 0 {
					continue
				}
				rec.Action = a
				break
			}
			if rec.Action == "rollup" {
				seen := map[string]bool{}
				for _, rd := range rec.Readers {
					if rd.Rewrite == nil {
						continue // already rewritten
					}
					if k := rd.Rewrite.Source + "\x00" + rd.Rewrite.Origin; !seen[k] {
						seen[k] = true
						rec.Rewrites = append(rec.Rewrites, *rd.Rewrite)
					}
				}
			}
			switch rec.Action {
			case "aggregate", "drop", "rollup":
				rec.RemovedBytesPerDay = perDay
			case "dedupe":
				rec.RemovedBytesPerDay = perDay
				rec.UpperBound = true
			case "sample":
				rec.Keep = pol.SamplePercent
				rec.RemovedBytesPerDay = perDay * float64(100-pol.SamplePercent) / 100
			case "none":
				rec.Blockers = append(rec.Blockers, rollupBlockedBy...)
				rec.Blockers = append(rec.Blockers, "no allowed action applies")
			}
		}
		out = append(out, rec)
	}
	combineRewrites(out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RemovedBytesPerDay != out[j].RemovedBytesPerDay {
			return out[i].RemovedBytesPerDay > out[j].RemovedBytesPerDay
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// combineRewrites rewrites each stored query once for every rolled-up rule it reads, and proves the
// combined result for each of them. A rule whose proof fails loses its rollup, which can change
// the set for other queries, so it repeats until nothing changes.
func combineRewrites(recs []Recommendation) {
	languages := make(map[string]string, len(recs))
	for _, r := range recs {
		languages[r.ID] = r.Candidate.Language
	}
	for changed := true; changed; {
		changed = false
		readers, order := rollupReaders(recs)
		for _, sq := range order {
			if combineRewrite(recs, sq, readers[sq], languages) {
				changed = true
			}
		}
	}
}

// storedQuery identifies one stored query that rollups rewrite.
type storedQuery struct {
	store, url, path, old string
	org                   int64
}

// rollupReaders maps each stored query to the rolled-up rules that rewrite it, with the queries in
// first-seen order so the result is deterministic.
func rollupReaders(recs []Recommendation) (map[storedQuery][]int, []storedQuery) {
	readers := map[storedQuery][]int{}
	var order []storedQuery
	for i, r := range recs {
		if r.Action != "rollup" {
			continue
		}
		for _, rw := range r.Rewrites {
			if rw.Store == "" {
				continue // an executed query covered by a stored one
			}
			sq := storedQuery{rw.Store, rw.StoreURL, rw.Path, rw.Old, rw.Org}
			if _, ok := readers[sq]; !ok {
				order = append(order, sq)
			}
			readers[sq] = append(readers[sq], i)
		}
	}
	return readers, order
}

// combineRewrite rewrites sq for all the rules in idx at once and proves it for each. A rule whose
// proof fails loses its rollup; it reports whether any did.
func combineRewrite(recs []Recommendation, sq storedQuery, idx []int, languages map[string]string) bool {
	rules := make([]rewrite.Rule, len(idx))
	candidates := make([]Candidate, len(idx))
	for j, i := range idx {
		c := recs[i].Candidate
		rules[j] = rewrite.Rule{ID: recs[i].ID, Language: c.Language, Scope: c.Scope}
		candidates[j] = c
	}
	res, err := rewrite.Query(sq.old, rules, sharedStreamLabels(candidates))
	var nq *logql.Query
	if err == nil && res.Changed {
		nq, err = logql.Parse(res.Expr)
	}
	lost := false
	for _, i := range idx {
		if err != nil || !res.Changed || !proven(nq, recs[i].ID, recs[i].Candidate, languages) {
			recs[i].Action, recs[i].RemovedBytesPerDay, recs[i].Rewrites = "none", 0, nil
			recs[i].Blockers = append(recs[i].Blockers, "a stored query reading these lines also reads another rolled-up rule, and the combined rewrite could not be proven")
			lost = true
			continue
		}
		for j := range recs[i].Rewrites {
			if rw := &recs[i].Rewrites[j]; logql.Canonical(rw.Old) == logql.Canonical(sq.old) {
				rw.New = res.Expr // the same combined text for every rule, and for executions of it
			}
		}
	}
	return lost
}

// sharedStreamLabels are the labels that are index labels for every candidate's streams: a rollup
// record carries only its stream's labels, so a sum by any other label would move its count.
func sharedStreamLabels(cands []Candidate) map[string]bool {
	shared := map[string]bool{}
	for l := range cands[0].StreamLabels {
		shared[l] = true
	}
	for _, c := range cands[1:] {
		for l := range shared {
			if !c.StreamLabels[l] {
				delete(shared, l)
			}
		}
	}
	return shared
}

// proven reports whether the rewritten query nq reads rule id's lines only through a compensated
// raw-line term. A language that does not compile proves nothing.
func proven(nq *logql.Query, id string, c Candidate, languages map[string]string) bool {
	lang, err := automaton.Compile(c.Language)
	if err != nil {
		return false
	}
	ur := usage.Rule{ID: id, Scope: c.Scope, Language: lang}
	for _, sel := range nq.Selections {
		if usage.Evaluate(sel, ur).Used && !rewrite.Compensated(nq, sel, id, languages) {
			return false
		}
	}
	return true
}

// rewritable stores are the stored queries sievelog can rewrite in place.
func rewritable(q UsageQuery) bool {
	switch q.Store {
	case "loki-ruler":
		return true
	case "grafana":
		for _, p := range []string{"dashboard:", "librarypanel:", "alertrule:", "recordingrule:"} {
			if strings.HasPrefix(q.Path, p) {
				return true
			}
		}
	}
	return false
}

// rewriteFor rewrites a stored query for a rollup of the candidate, and proves the result: the
// rewritten query must parse and no longer read the rule's lines except through its compensated
// raw-line term. Anything short of that returns nil and the reader keeps blocking.
func rewriteFor(q UsageQuery, id string, c Candidate) *Rewrite {
	if !rewritable(q) {
		return nil
	}
	res, err := rewrite.Query(q.Expr, []rewrite.Rule{{ID: id, Language: c.Language, Scope: c.Scope}}, c.StreamLabels)
	if err != nil || !res.Changed {
		return nil
	}
	nq, err := logql.Parse(res.Expr)
	if err != nil || !proven(nq, id, c, map[string]string{id: c.Language}) {
		return nil
	}
	return &Rewrite{Source: q.Source, Origin: q.Origin, Store: q.Store, StoreURL: q.StoreURL, Path: q.Path, Org: q.Org, Old: q.Expr, New: res.Expr}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
