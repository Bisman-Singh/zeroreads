package app

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/logql"
	"github.com/Bisman-Singh/sievelog/internal/rewrite"
	"github.com/Bisman-Singh/sievelog/internal/source/loki"
)

// Window is a closed time range.
type Window struct {
	Start, End time.Time
}

func (w Window) seconds() int64 { return int64(w.End.Sub(w.Start) / time.Second) }

// RuleReconciliation compares what Loki stored for one rule before and after enforcement.
type RuleReconciliation struct {
	RuleID       string  `json:"rule_id"`
	Service      string  `json:"service"`
	Action       string  `json:"action"`
	Keep         int     `json:"keep,omitempty"`
	BeforeLines  float64 `json:"before_lines"`
	BeforeBytes  float64 `json:"before_bytes"`
	AfterLines   float64 `json:"after_lines"`
	AfterBytes   float64 `json:"after_bytes"`
	KeptFraction float64 `json:"kept_fraction"` // after rate / before rate
	Status       string  `json:"status"`        // ok | mismatch | no-traffic
	Detail       string  `json:"detail"`
}

// ServiceReconciliation is the whole service's stored volume in both windows.
type ServiceReconciliation struct {
	Service         string  `json:"service"`
	BeforeBytesRate float64 `json:"before_bytes_per_hour"`
	AfterBytesRate  float64 `json:"after_bytes_per_hour"`
}

// Reconciliation is the result of `sievelog reconcile`.
type Reconciliation struct {
	Before   Window                  `json:"before"`
	After    Window                  `json:"after"`
	Rules    []RuleReconciliation    `json:"rules"`
	Services []ServiceReconciliation `json:"services"`
	OK       bool                    `json:"ok"`
}

// Reconcile measures, from Loki itself, each enforced rule's stored lines before and after
// enforcement. Drop and aggregate rules must store nothing afterwards; a sample rule's stored share
// must be within tolerance of its keep percentage; dedupe must store fewer records than lines seen;
// a rollup must store no line and, when the rule had lines before, rollup records carrying counts.
func Reconcile(ctx context.Context, c *Config, rf *RulesFile, before, after Window, tolerance float64) (*Reconciliation, error) {
	lc, err := c.lokiClient()
	if err != nil {
		return nil, err
	}
	m := reconciler{c: c, lc: lc, before: before, after: after}
	res := &Reconciliation{Before: before, After: after, OK: true}
	for _, r := range rf.Rules {
		rr, err := m.rule(ctx, r)
		if err != nil {
			return nil, err
		}
		rolled := 0.0
		if r.Action == "rollup" {
			if rolled, err = m.rolledUp(ctx, r); err != nil {
				return nil, err
			}
		}
		rr.Status, rr.Detail = verdict(r, rr, rolled, tolerance)
		if rr.Status == "mismatch" {
			res.OK = false
		}
		res.Rules = append(res.Rules, rr)
	}
	for _, svc := range rf.services() {
		b, err := m.volume(ctx, "bytes_over_time", svc, "", "", before)
		if err != nil {
			return nil, err
		}
		a, err := m.volume(ctx, "bytes_over_time", svc, "", "", after)
		if err != nil {
			return nil, err
		}
		res.Services = append(res.Services, ServiceReconciliation{Service: svc,
			BeforeBytesRate: b / before.End.Sub(before.Start).Hours(), AfterBytesRate: a / after.End.Sub(after.Start).Hours()})
	}
	return res, nil
}

// reconciler measures stored volume in the windows before and after enforcement.
type reconciler struct {
	c             *Config
	lc            *loki.Client
	before, after Window
}

func (m reconciler) volume(ctx context.Context, fn, svc, field, lang string, w Window) (float64, error) {
	return m.c.scalar(ctx, m.lc, m.c.volumeQuery(fn, svc, field, lang, w.End.Sub(w.Start)), w.End)
}

// rule measures a rule's stored lines and bytes in both windows.
func (m reconciler) rule(ctx context.Context, r EnforcedRule) (RuleReconciliation, error) {
	rr := RuleReconciliation{RuleID: r.ID, Service: r.Service, Action: r.Action, Keep: r.Keep}
	for _, x := range []struct {
		out *float64
		fn  string
		w   Window
	}{{&rr.BeforeLines, "count_over_time", m.before}, {&rr.BeforeBytes, "bytes_over_time", m.before},
		{&rr.AfterLines, "count_over_time", m.after}, {&rr.AfterBytes, "bytes_over_time", m.after}} {
		v, err := m.volume(ctx, x.fn, r.Service, r.Field, r.Language, x.w)
		if err != nil {
			return rr, err
		}
		*x.out = v
	}
	if beforeRate := rr.BeforeLines / float64(m.before.seconds()); beforeRate > 0 {
		rr.KeptFraction = rr.AfterLines / float64(m.after.seconds()) / beforeRate
	}
	return rr, nil
}

// rolledUp is how many lines a rollup rule's records count in the window after enforcement.
func (m reconciler) rolledUp(ctx context.Context, r EnforcedRule) (float64, error) {
	q := fmt.Sprintf("sum(sum_over_time(%s |= %s | %s=%s | unwrap %s %s))", m.c.selector(r.Service),
		logql.Quote(rewrite.Marker(r.ID)), rewrite.RuleLabel, strconv.Quote(r.ID), rewrite.CountLabel, rangeOf(m.after.End.Sub(m.after.Start)))
	return m.c.scalar(ctx, m.lc, q, m.after.End)
}

// verdict compares what a rule stored after enforcement with what its action promises.
func verdict(r EnforcedRule, rr RuleReconciliation, rolled, tolerance float64) (status, detail string) {
	stillStored := fmt.Sprintf("%.0f lines of this rule were still stored after enforcement", rr.AfterLines)
	switch {
	case !slices.Contains([]string{"drop", "aggregate", "archive", "rollup", "sample", "dedupe"}, r.Action):
		return "mismatch", fmt.Sprintf("unknown action %q", r.Action)
	case r.Action == "drop" || r.Action == "aggregate" || r.Action == "archive":
		if rr.AfterLines > 0 {
			return "mismatch", stillStored
		}
		return "ok", "no lines of this rule were stored after enforcement"
	case r.Action == "rollup":
		switch {
		case rr.AfterLines > 0:
			return "mismatch", stillStored
		case rolled == 0 && rr.BeforeLines > 0:
			return "mismatch", fmt.Sprintf("no rollup record after enforcement, although the rule had %.0f lines before: their counts may be lost", rr.BeforeLines)
		}
		return "ok", fmt.Sprintf("no lines stored after enforcement; rollup records count %.0f lines", rolled)
	case rr.BeforeLines == 0:
		return "no-traffic", "no lines of this rule in the before window"
	case r.Action == "sample":
		want := float64(r.Keep) / 100
		detail = fmt.Sprintf("kept %.3f of the before rate, target %.2f±%.2f", rr.KeptFraction, want, tolerance)
		if d := rr.KeptFraction - want; d > tolerance || d < -tolerance {
			return "mismatch", detail
		}
		return "ok", detail
	}
	detail = fmt.Sprintf("stored records at %.3f of the before rate", rr.KeptFraction)
	if rr.KeptFraction >= 1 {
		return "mismatch", detail
	}
	return "ok", detail
}
