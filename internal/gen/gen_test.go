package gen

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// kindRegex describes what each variable kind may render as. It is written independently of
// value() so the tests catch a generator that drifts from its own corpus.
var kindRegex = map[string]string{
	"duration":    `[1-9][0-9]{0,2}ms`,
	"reqid":       `[0-9a-f]{16}`,
	"hex":         `[0-9a-f]{8}`,
	"status":      `(200|201|404|503)`,
	"ip":          `10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`,
	"small":       `[1-5]`,
	"payid":       `pay_[0-9]{6}`,
	"declinecode": `(insufficient_funds|card_expired|do_not_honor)`,
	"user":        `(alice|bob|carol|dave|erin|frank)`,
	"orderid":     `ord-[0-9]{4}`,
	"step":        `(reserve|charge|ship)`,
}

func patternRegex(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	var parts []string
	for _, tok := range strings.Split(pattern, " ") {
		if strings.HasPrefix(tok, "{") && strings.HasSuffix(tok, "}") {
			re, ok := kindRegex[tok[1:len(tok)-1]]
			if !ok {
				t.Fatalf("corpus uses kind %s with no test regex", tok)
			}
			parts = append(parts, re)
			continue
		}
		parts = append(parts, regexp.QuoteMeta(tok))
	}
	return regexp.MustCompile("^" + strings.Join(parts, " ") + "$")
}

func TestDeterministic(t *testing.T) {
	a, ma, err := Run(42, 2000)
	if err != nil {
		t.Fatal(err)
	}
	b, mb, _ := Run(42, 2000)
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(ma, mb) {
		t.Fatal("same seed produced different output")
	}
	c, _, _ := Run(43, 2000)
	if reflect.DeepEqual(a, c) {
		t.Fatal("different seeds produced identical output")
	}
}

// checkLabels verifies every line matches its own template and no other template in its
// service. This proves the ground-truth label is consistent with the content, independently of
// the generator's code.
func checkLabels(t *testing.T, recs []Record) error {
	res := map[string]map[string]*regexp.Regexp{}
	for _, s := range Corpus() {
		res[s.Name] = map[string]*regexp.Regexp{}
		for _, tp := range s.Templates {
			res[s.Name][tp.ID] = patternRegex(t, tp.Pattern)
		}
	}
	for _, r := range recs {
		var matched []string
		for id, re := range res[r.Service] {
			if re.MatchString(r.Message) {
				matched = append(matched, id)
			}
		}
		if len(matched) != 1 || matched[0] != r.TemplateID {
			return fmt.Errorf("line %q labelled %s matched %v", r.Message, r.TemplateID, matched)
		}
	}
	return nil
}

func TestLabelsMatchContentExactly(t *testing.T) {
	recs, _, err := Run(7, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkLabels(t, recs); err != nil {
		t.Fatal(err)
	}
	// Negative: a mislabelled record must be caught.
	bad := append([]Record(nil), recs...)
	bad[10].TemplateID = "not-" + bad[10].TemplateID
	if checkLabels(t, bad) == nil {
		t.Fatal("mislabelled record was not detected")
	}
	// Negative: a line that matches no template must be caught.
	bad = append([]Record(nil), recs...)
	bad[20].Message += " extra"
	if checkLabels(t, bad) == nil {
		t.Fatal("line matching no template was not detected")
	}
}

// checkManifest verifies the manifest equals an independent recount of the records.
func checkManifest(recs []Record, m Manifest) error {
	type key struct{ svc, id string }
	got := map[key]Totals{}
	for _, r := range recs {
		k := key{r.Service, r.TemplateID}
		x := got[k]
		x.Lines++
		x.LineBytes += int64(len(r.Line))
		x.MessageBytes += int64(len(r.Message))
		got[k] = x
	}
	n := 0
	for svc, byID := range m.Templates {
		for id, tot := range byID {
			n++
			if got[key{svc, id}] != tot {
				return fmt.Errorf("%s/%s manifest %+v recount %+v", svc, id, tot, got[key{svc, id}])
			}
		}
	}
	if n != len(got) {
		return fmt.Errorf("manifest has %d templates, recount has %d", n, len(got))
	}
	return nil
}

func TestManifestEqualsRecount(t *testing.T) {
	recs, m, err := Run(9, 3000)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkManifest(recs, m); err != nil {
		t.Fatal(err)
	}
	// Negative: a manifest off by one byte must be caught.
	tot := m.Templates["checkout"]["health"]
	tot.LineBytes++
	m.Templates["checkout"]["health"] = tot
	if checkManifest(recs, m) == nil {
		t.Fatal("wrong byte total was not detected")
	}
}

// With enough lines every template appears, and every service emits exactly n lines.
func TestCoverage(t *testing.T) {
	_, m, err := Run(1, 20000)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range Corpus() {
		var sum int64
		for _, tp := range s.Templates {
			tot := m.Templates[s.Name][tp.ID]
			if tot.Lines == 0 {
				t.Fatalf("%s/%s never emitted", s.Name, tp.ID)
			}
			sum += tot.Lines
		}
		if sum != 20000 {
			t.Fatalf("%s emitted %d lines, want 20000", s.Name, sum)
		}
	}
}

// JSON services must emit valid JSON whose msg is the templated text, and plain services must
// emit the message as the whole line.
func TestLineShape(t *testing.T) {
	recs, _, _ := Run(3, 1000)
	isJSON := map[string]bool{}
	for _, s := range Corpus() {
		isJSON[s.Name] = s.JSON
	}
	for _, r := range recs {
		if !isJSON[r.Service] {
			if r.Line != r.Message {
				t.Fatalf("plain line %q differs from message %q", r.Line, r.Message)
			}
			continue
		}
		var obj map[string]any
		if err := jsonUnmarshal(r.Line, &obj); err != nil {
			t.Fatalf("invalid JSON %q: %v", r.Line, err)
		}
		if obj["msg"] != r.Message {
			t.Fatalf("msg %v != message %q", obj["msg"], r.Message)
		}
	}
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

func TestUnknownService(t *testing.T) {
	if _, err := New("nope", 1); err == nil {
		t.Fatal("expected error for unknown service")
	}
}
