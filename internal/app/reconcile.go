package app

import (
	"context"
	"fmt"
	"github.com/Bisman-Singh/sievelog/internal/rewrite"
	"slices"
	"strconv"
	"time"
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
	res := &Reconciliation{Before: before, After: after, OK: true}
	measure := func(fn, svc, field, lang string, w Window) (float64, error) {
		sel := c.selector(svc)
		rng := "[" + strconv.FormatInt(w.seconds(), 10) + "s]"
		var q string
		switch {
		case lang == "":
			q = fmt.Sprintf("sum(%s(%s %s))", fn, sel, rng)
		case field == "":
			q = fmt.Sprintf("sum(%s(%s |~ %s %s))", fn, sel, logqlString(lang), rng)
		default:
			q = fmt.Sprintf("sum(%s(%s | json sievelog_field=%s | sievelog_field=~%s %s))", fn, sel, strconv.Quote(field), logqlString(lang), rng)
		}
		return c.scalar(ctx, lc, q, w.End)
	}
	services := map[string]bool{}
	for _, r := range rf.Rules {
		services[r.Service] = true
		rr := RuleReconciliation{RuleID: r.ID, Service: r.Service, Action: r.Action, Keep: r.Keep}
		var err error
		if rr.BeforeLines, err = measure("count_over_time", r.Service, r.Field, r.Language, before); err != nil {
			return nil, err
		}
		if rr.BeforeBytes, err = measure("bytes_over_time", r.Service, r.Field, r.Language, before); err != nil {
			return nil, err
		}
		if rr.AfterLines, err = measure("count_over_time", r.Service, r.Field, r.Language, after); err != nil {
			return nil, err
		}
		if rr.AfterBytes, err = measure("bytes_over_time", r.Service, r.Field, r.Language, after); err != nil {
			return nil, err
		}
		beforeRate := rr.BeforeLines / float64(before.seconds())
		afterRate := rr.AfterLines / float64(after.seconds())
		if beforeRate > 0 {
			rr.KeptFraction = afterRate / beforeRate
		}
		switch {
		case !slices.Contains([]string{"drop", "aggregate", "rollup", "sample", "dedupe"}, r.Action):
			rr.Status, rr.Detail = "mismatch", fmt.Sprintf("unknown action %q", r.Action)
		case r.Action == "drop" || r.Action == "aggregate":
			if rr.AfterLines == 0 {
				rr.Status, rr.Detail = "ok", "no lines of this rule were stored after enforcement"
			} else {
				rr.Status, rr.Detail = "mismatch", fmt.Sprintf("%.0f lines of this rule were still stored after enforcement", rr.AfterLines)
			}
		case r.Action == "rollup":
			q := fmt.Sprintf("sum(sum_over_time(%s |= %s | %s=%s | unwrap %s [%ds]))", c.selector(r.Service),
				logqlString(rewrite.Marker(r.ID)), rewrite.RuleLabel, strconv.Quote(r.ID), rewrite.CountLabel, after.seconds())
			rolled, err := c.scalar(ctx, lc, q, after.End)
			if err != nil {
				return nil, err
			}
			switch {
			case rr.AfterLines > 0:
				rr.Status, rr.Detail = "mismatch", fmt.Sprintf("%.0f lines of this rule were still stored after enforcement", rr.AfterLines)
			case rolled == 0 && rr.BeforeLines > 0:
				rr.Status, rr.Detail = "mismatch", fmt.Sprintf("no rollup record after enforcement, although the rule had %.0f lines before: their counts may be lost", rr.BeforeLines)
			default:
				rr.Status, rr.Detail = "ok", fmt.Sprintf("no lines stored after enforcement; rollup records count %.0f lines", rolled)
			}
		case rr.BeforeLines == 0:
			rr.Status, rr.Detail = "no-traffic", "no lines of this rule in the before window"
		case r.Action == "sample":
			want := float64(r.Keep) / 100
			if d := rr.KeptFraction - want; d <= tolerance && d >= -tolerance {
				rr.Status = "ok"
			} else {
				rr.Status = "mismatch"
			}
			rr.Detail = fmt.Sprintf("kept %.3f of the before rate, target %.2f±%.2f", rr.KeptFraction, want, tolerance)
		case r.Action == "dedupe":
			if rr.KeptFraction < 1 {
				rr.Status = "ok"
			} else {
				rr.Status = "mismatch"
			}
			rr.Detail = fmt.Sprintf("stored records at %.3f of the before rate", rr.KeptFraction)
		}
		if rr.Status == "mismatch" {
			res.OK = false
		}
		res.Rules = append(res.Rules, rr)
	}
	for svc := range services {
		b, err := measure("bytes_over_time", svc, "", "", before)
		if err != nil {
			return nil, err
		}
		a, err := measure("bytes_over_time", svc, "", "", after)
		if err != nil {
			return nil, err
		}
		res.Services = append(res.Services, ServiceReconciliation{Service: svc,
			BeforeBytesRate: b / before.End.Sub(before.Start).Hours(), AfterBytesRate: a / after.End.Sub(after.Start).Hours()})
	}
	return res, nil
}
