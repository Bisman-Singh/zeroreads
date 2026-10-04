package templating

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Bisman-Singh/zeroreads/internal/gen"
)

var ipMask = MaskRule{Name: gen.IPMaskName, Pattern: gen.IPMaskPattern}

// corpusConfig is the drain config used for the ground-truth corpus: defaults plus an IP mask and
// msg as the templated field of structured records.
func corpusConfig(seed bool) *Config {
	cfg := DefaultConfig()
	cfg.BodyField = "msg"
	cfg.MaskingRules = []MaskRule{ipMask}
	if seed {
		cfg.SeedTemplates = gen.SeedTemplates()
	}
	return cfg
}

func toInputs(t *testing.T, recs []gen.Record) []Input {
	t.Helper()
	isJSON := map[string]bool{}
	for _, s := range gen.Corpus() {
		isJSON[s.Name] = s.JSON
	}
	in := make([]Input, len(recs))
	for i, r := range recs {
		if !isJSON[r.Service] {
			in[i] = Input{Body: r.Line}
			continue
		}
		var m map[string]any
		if err := jsonUnmarshal(r.Line, &m); err != nil {
			t.Fatal(err)
		}
		in[i] = Input{Fields: m}
	}
	return in
}

// mapping groups ground-truth template IDs by the drain template assigned to their lines.
type mapping struct {
	byGT    map[string]map[string]int // gt id -> drain template -> lines
	byDrain map[string]map[string]int // drain template -> gt id -> lines
}

func buildMapping(recs []gen.Record, tmpl []string) mapping {
	m := mapping{byGT: map[string]map[string]int{}, byDrain: map[string]map[string]int{}}
	for i, r := range recs {
		gt := r.Service + "/" + r.TemplateID
		if m.byGT[gt] == nil {
			m.byGT[gt] = map[string]int{}
		}
		if m.byDrain[tmpl[i]] == nil {
			m.byDrain[tmpl[i]] = map[string]int{}
		}
		m.byGT[gt][tmpl[i]]++
		m.byDrain[tmpl[i]][gt]++
	}
	return m
}

// splits lists ground-truth templates whose lines landed in more than one drain template.
func (m mapping) splits() []string {
	var out []string
	for gt, d := range m.byGT {
		if len(d) > 1 {
			out = append(out, fmt.Sprintf("%s -> %v", gt, d))
		}
	}
	sort.Strings(out)
	return out
}

// merges lists drain templates that hold lines from more than one ground-truth template.
func (m mapping) merges() map[string][]string {
	out := map[string][]string{}
	for d, gts := range m.byDrain {
		if len(gts) < 2 {
			continue
		}
		for gt := range gts {
			out[d] = append(out[d], gt)
		}
		sort.Strings(out[d])
	}
	return out
}

func templateCorpus(t *testing.T, cfg *Config, n int) ([]gen.Record, []string) {
	t.Helper()
	ctx := context.Background()
	recs, _, err := gen.Run(11, n)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)
	tmpl, err := e.Template(ctx, toInputs(t, recs))
	if err != nil {
		t.Fatal(err)
	}
	return recs, tmpl
}

// expectedMerges is the observed behaviour of drainprocessor v0.161.0 on the corpus with default
// settings, pinned so any change in Drain behaviour fails loudly. cache hit and cache miss have
// the same length and differ in one literal; at merge_threshold 0.4 the two seeds merge with each
// other, so both lines land in one template. Merges are the conservative direction for usage.
var expectedMerges = map[string][]string{
	"DEBUG cache <*> key <*>": {"checkout/cache-hit", "checkout/cache-miss"},
}

func checkSeededMapping(m mapping, tmpl []string) error {
	for i, s := range tmpl {
		if s == "" {
			return fmt.Errorf("record %d has no template", i)
		}
	}
	if sp := m.splits(); len(sp) > 0 {
		return fmt.Errorf("splits: %v", sp)
	}
	if got := m.merges(); !reflect.DeepEqual(got, expectedMerges) {
		return fmt.Errorf("merges %v, want %v", got, expectedMerges)
	}
	return nil
}

// With seeds, every ground-truth template lands in exactly one drain template and the only merge
// is the pinned one.
func TestSeededCorpusMapping(t *testing.T) {
	recs, tmpl := templateCorpus(t, corpusConfig(true), 3000)
	m := buildMapping(recs, tmpl)
	if err := checkSeededMapping(m, tmpl); err != nil {
		t.Fatal(err)
	}
	if len(m.byDrain) != 12 {
		t.Fatalf("got %d drain templates, want 12", len(m.byDrain))
	}
	// Negative: an unexpected merge must be caught.
	bad := append([]string(nil), tmpl...)
	for i, r := range recs {
		if r.TemplateID == "heartbeat" {
			bad[i] = "INFO GET /healthz 200 <*>"
		}
	}
	if checkSeededMapping(buildMapping(recs, bad), bad) == nil {
		t.Fatal("unexpected merge was not detected")
	}
}

// Without seeds the first line of each template becomes its own literal template. This is why the
// analyzer emits seed_templates for the pipeline; the test pins that the split check really fires.
func TestColdStartSplits(t *testing.T) {
	recs, tmpl := templateCorpus(t, corpusConfig(false), 3000)
	m := buildMapping(recs, tmpl)
	if len(m.splits()) == 0 {
		t.Fatal("expected cold-start splits without seeds")
	}
	if checkSeededMapping(m, tmpl) == nil {
		t.Fatal("seeded-mapping check passed on an unseeded run")
	}
}

// drainprocessor does not escape literal mask text: a raw line containing the characters "<ip>"
// gets the same token as a masked IP. The placeholder template proves it: its lines contain no IP.
func TestLiteralMaskTextCollides(t *testing.T) {
	recs, tmpl := templateCorpus(t, corpusConfig(true), 3000)
	for i, r := range recs {
		if r.TemplateID != "placeholder" {
			continue
		}
		ipRe := regexp.MustCompile(ipMask.Pattern)
		if strings.Contains(tmpl[i], "<ip>") && strings.Contains(r.Line, "<ip>") && !ipRe.MatchString(r.Line) {
			return
		}
		t.Fatalf("placeholder line %q got template %q", r.Line, tmpl[i])
	}
	t.Fatal("no placeholder lines generated")
}

func TestDrainVersionPinned(t *testing.T) {
	v, err := DrainVersion()
	if err != nil {
		t.Fatal(err)
	}
	if v != "v0.161.0" {
		t.Fatalf("embedded drain processor %s, want v0.161.0", v)
	}
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }
