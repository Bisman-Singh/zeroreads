package app

import (
	"sort"

	"github.com/Bisman-Singh/zeroreads/internal/analyze"
	"github.com/Bisman-Singh/zeroreads/internal/usage"
)

// ReaderSummary counts the readers behind every rule's decision. A reader is exact when the query
// really reads the rule's lines, as the line it shows proves. Every other reader was assumed to read
// more than it may, because part of the query is not modelled: each can block a rule that is in fact
// safe, so these are the over-blocking to look at first.
type ReaderSummary struct {
	Readers     int          `json:"readers"`
	Exact       int          `json:"exact"`
	Assumptions []Assumption `json:"assumptions"`
}

// Assumption is one kind of unmodelled query part and how many readers it made broader.
type Assumption struct {
	Kind    string `json:"kind"`
	Readers int    `json:"readers"`
}

func summarizeReaders(recs []analyze.Recommendation) ReaderSummary {
	var s ReaderSummary
	counts := map[string]int{}
	for _, r := range recs {
		for _, rd := range r.Readers {
			s.Readers++
			if len(rd.Widened) == 0 {
				s.Exact++
				continue
			}
			kinds := map[string]bool{}
			for _, w := range rd.Widened {
				kinds[usage.Kind(w)] = true
			}
			for k := range kinds {
				counts[k]++
			}
		}
	}
	for k, n := range counts {
		s.Assumptions = append(s.Assumptions, Assumption{Kind: k, Readers: n})
	}
	sort.Slice(s.Assumptions, func(i, j int) bool {
		a, b := s.Assumptions[i], s.Assumptions[j]
		return a.Readers > b.Readers || a.Readers == b.Readers && a.Kind < b.Kind
	})
	return s
}
