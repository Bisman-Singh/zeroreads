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
	"github.com/Bisman-Singh/sievelog/internal/logql"
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
}

// Recommendation is the decision for one candidate.
type Recommendation struct {
	ID        string
	Candidate Candidate
	Action    string // none | aggregate | dedupe | sample | drop
	Keep      int    // percent kept for sample
	Readers   []Reader
	Blockers  []string
	// RemovedBytesPerDay is the measured bytes/day this action removes (0 for none). For dedupe it is
	// an upper bound until shadow mode measures it.
	RemovedBytesPerDay float64
	UpperBound         bool
}

// Decide produces one recommendation per candidate.
func Decide(cands []Candidate, queries []UsageQuery, gaps []Gap, pol Policy) ([]Recommendation, error) {
	errRe, err := automaton.Compile(pol.ErrorPattern)
	if err != nil {
		return nil, fmt.Errorf("analyze: error pattern: %w", err)
	}
	for _, a := range pol.Actions {
		switch a {
		case "aggregate", "dedupe", "sample", "drop":
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
		q   UsageQuery
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
				v := usage.Evaluate(sel, rule)
				if v.Used {
					rec.Readers = append(rec.Readers, Reader{Source: p.q.Source, Origin: p.q.Origin, Expr: p.q.Expr, Counting: v.Counting, Witness: v.Witness, Reason: v.Reason})
					break
				}
			}
		}
		// Blockers, in the order an operator should read them.
		rec.Blockers = append(rec.Blockers, blockingGaps...)
		if len(rec.Readers) > 0 {
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
			switch strings.ToLower(s) {
			case "warn", "warning", "error", "err", "fatal", "critical", "crit", "alert", "emergency", "emerg", "panic":
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
				rec.Action = a
				break
			}
			switch rec.Action {
			case "aggregate", "drop":
				rec.RemovedBytesPerDay = perDay
			case "dedupe":
				rec.RemovedBytesPerDay = perDay
				rec.UpperBound = true
			case "sample":
				rec.Keep = pol.SamplePercent
				rec.RemovedBytesPerDay = perDay * float64(100-pol.SamplePercent) / 100
			case "none":
				rec.Blockers = append(rec.Blockers, "no allowed action applies")
			}
		}
		out = append(out, rec)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RemovedBytesPerDay != out[j].RemovedBytesPerDay {
			return out[i].RemovedBytesPerDay > out[j].RemovedBytesPerDay
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
