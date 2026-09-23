// Package gen produces deterministic synthetic logs with an exact ground truth: for every line
// it knows which template produced it, and it totals lines and bytes per template.
package gen

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
)

// Record is one emitted log line and the template that produced it.
type Record struct {
	Service    string
	TemplateID string
	Severity   string
	Message    string // the templated text (the whole line for plain services, msg for JSON)
	Line       string // exactly what is written to the stream, without the trailing newline
}

// Totals is the ground truth for one template.
type Totals struct {
	Lines        int64 `json:"lines"`
	LineBytes    int64 `json:"line_bytes"`    // len(Line), what a collector receives as the body
	MessageBytes int64 `json:"message_bytes"` // len(Message), the templated field only
}

// Manifest is the ground truth for a whole run.
type Manifest struct {
	Seed      uint64                       `json:"seed"`
	Lines     int                          `json:"lines"`
	Templates map[string]map[string]Totals `json:"templates"` // service -> template ID -> totals
}

// Generator emits records for one service from a seeded PRNG. The same seed, service and
// sequence of calls always yields the same records.
type Generator struct {
	svc     Service
	rng     *rand.Rand
	total   int
	cum     []int
	counter int
}

// New returns a generator for the named service in the corpus.
func New(service string, seed uint64) (*Generator, error) {
	for _, s := range Corpus() {
		if s.Name != service {
			continue
		}
		g := &Generator{svc: s, rng: rand.New(rand.NewPCG(seed, seedSalt(service)))}
		for _, t := range s.Templates {
			if t.Weight <= 0 {
				return nil, fmt.Errorf("template %s: weight must be positive", t.ID)
			}
			g.total += t.Weight
			g.cum = append(g.cum, g.total)
		}
		return g, nil
	}
	return nil, fmt.Errorf("unknown service %q", service)
}

// seedSalt gives each service an independent stream from the same seed.
func seedSalt(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// Next returns the next record.
func (g *Generator) Next() Record {
	pick := g.rng.IntN(g.total)
	idx := 0
	for pick >= g.cum[idx] {
		idx++
	}
	t := g.svc.Templates[idx]
	g.counter++
	msg := g.render(t.Pattern)
	line := msg
	if g.svc.JSON {
		line = g.renderJSON(t, msg)
	}
	return Record{Service: g.svc.Name, TemplateID: t.ID, Severity: t.Severity, Message: msg, Line: line}
}

func (g *Generator) render(pattern string) string {
	toks := strings.Split(pattern, " ")
	for i, tok := range toks {
		if strings.HasPrefix(tok, "{") && strings.HasSuffix(tok, "}") {
			toks[i] = g.value(tok[1 : len(tok)-1])
		}
	}
	return strings.Join(toks, " ")
}

// renderJSON builds a structured record. Only msg is templated; route and status exist so that
// queries filtering on non-message fields can be exercised.
func (g *Generator) renderJSON(t Template, msg string) string {
	rec := struct {
		Level  string `json:"level"`
		Msg    string `json:"msg"`
		Route  string `json:"route"`
		Status int    `json:"status"`
	}{
		Level:  strings.ToLower(t.Severity),
		Msg:    msg,
		Route:  pickStr(g.rng, "/checkout", "/cart", "/orders"),
		Status: pickInt(g.rng, 200, 200, 200, 201, 404, 503),
	}
	b, err := json.Marshal(rec)
	if err != nil {
		panic(err) // a fixed struct of strings and ints always marshals
	}
	return string(b)
}

func (g *Generator) value(kind string) string {
	r := g.rng
	switch kind {
	case "duration":
		return fmt.Sprintf("%dms", 1+r.IntN(900))
	case "reqid":
		return fmt.Sprintf("%016x", r.Uint64())
	case "hex":
		return fmt.Sprintf("%08x", r.Uint32())
	case "status":
		return fmt.Sprint(pickInt(r, 200, 200, 200, 200, 201, 404, 503))
	case "ip":
		return fmt.Sprintf("10.%d.%d.%d", r.IntN(256), r.IntN(256), 1+r.IntN(254))
	case "small":
		return fmt.Sprint(1 + r.IntN(5))
	case "payid":
		return fmt.Sprintf("pay_%d", 100000+r.IntN(900000))
	case "declinecode":
		return pickStr(r, "insufficient_funds", "card_expired", "do_not_honor")
	case "user":
		return pickStr(r, "alice", "bob", "carol", "dave", "erin", "frank")
	case "orderid":
		return fmt.Sprintf("ord-%d", 1000+r.IntN(9000))
	case "step":
		return pickStr(r, "reserve", "charge", "ship")
	}
	panic("unknown variable kind " + kind) // corpus is static; covered by tests
}

func pickStr(r *rand.Rand, v ...string) string { return v[r.IntN(len(v))] }
func pickInt(r *rand.Rand, v ...int) int       { return v[r.IntN(len(v))] }

// Run generates n records per service for every service in the corpus and returns them with
// the exact ground truth.
func Run(seed uint64, n int) ([]Record, Manifest, error) {
	m := Manifest{Seed: seed, Lines: n, Templates: map[string]map[string]Totals{}}
	var out []Record
	for _, s := range Corpus() {
		g, err := New(s.Name, seed)
		if err != nil {
			return nil, Manifest{}, err
		}
		m.Templates[s.Name] = map[string]Totals{}
		for i := 0; i < n; i++ {
			rec := g.Next()
			m.Add(rec)
			out = append(out, rec)
		}
	}
	return out, m, nil
}

// Add counts one record into the manifest.
func (m *Manifest) Add(rec Record) {
	if m.Templates == nil {
		m.Templates = map[string]map[string]Totals{}
	}
	if m.Templates[rec.Service] == nil {
		m.Templates[rec.Service] = map[string]Totals{}
	}
	t := m.Templates[rec.Service][rec.TemplateID]
	t.Lines++
	t.LineBytes += int64(len(rec.Line))
	t.MessageBytes += int64(len(rec.Message))
	m.Templates[rec.Service][rec.TemplateID] = t
}
