//go:build docker

package emit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const vectorUserConfig = `
sources:
  in:
    type: stdin
    decoding: {codec: json}
transforms:
  prep:
    type: remap
    inputs: [in]
    source: |
      .timestamp = from_unix_timestamp!(to_int!(.tsn), unit: "nanoseconds")
      if .structured == true { .body = parse_json!(string!(.message)) }
sinks:
  out:
    type: file
    inputs: [prep]
    path: /w/out.json
    encoding: {codec: json}
`

func vectorTarget() VectorTarget {
	return VectorTarget{After: "prep", ScopePath: ".service", TextPath: ".message",
		FieldPaths: map[string]string{"orders": ".body.msg"}, DedupeMS: 1000,
		MeasureSink: map[string]any{"type": "file", "path": "/w/metrics.json", "encoding": map[string]any{"codec": "json"}}}
}

func vectorKeep(text string, ts int64, keep int) bool {
	sum := sha256.Sum256([]byte(text + "|" + strconv.FormatInt(ts, 10)))
	v, _ := strconv.ParseInt(hex.EncodeToString(sum[:])[:15], 16, 64)
	return v < VectorSampleThreshold(keep)
}

func runVector(t *testing.T, cfg []byte, recs []record) (events []map[string]any, metrics map[string]float64) {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "vector.yaml"), cfg, 0o644)
	var in strings.Builder
	for _, r := range recs {
		ev := map[string]any{"service": r.service, "tsn": r.ts}
		if r.mapBody {
			b, _ := json.Marshal(map[string]any{"msg": r.text, "route": "/cart"})
			ev["message"], ev["structured"] = string(b), true
		} else {
			ev["message"] = r.text
		}
		b, _ := json.Marshal(ev)
		in.Write(b)
		in.WriteByte('\n')
	}
	return runVectorInput(t, dir, in.String())
}

// runVectorInput runs Vector over raw JSON lines with the config already written to dir.
func runVectorInput(t *testing.T, dir, input string) (events []map[string]any, metrics map[string]float64) {
	t.Helper()
	cmd := exec.Command("docker", "run", "-i", "--rm", "-v", dir+":/w", "timberio/vector:0.58.0-debian", "--config", "/w/vector.yaml")
	cmd.Stdin = strings.NewReader(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("vector: %v\n%s", err, out)
	}
	f, err := os.Open(filepath.Join(dir, "out.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 16<<20), 16<<20)
	for sc.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		events = append(events, ev)
	}
	metrics = map[string]float64{}
	if mf, err := os.Open(filepath.Join(dir, "metrics.json")); err == nil {
		defer mf.Close()
		ms := bufio.NewScanner(mf)
		for ms.Scan() {
			var m struct {
				Name    string            `json:"name"`
				Tags    map[string]string `json:"tags"`
				Counter struct {
					Value float64 `json:"value"`
				} `json:"counter"`
			}
			if err := json.Unmarshal(ms.Bytes(), &m); err != nil {
				t.Fatal(err)
			}
			metrics[m.Name+"|"+m.Tags["rule"]] += m.Counter.Value
		}
	}
	return events, metrics
}

func eventText(ev map[string]any) (svc, text string, structured bool) {
	svc, _ = ev["service"].(string)
	if b, ok := ev["body"].(map[string]any); ok {
		text, _ = b["msg"].(string)
		return svc, text, true
	}
	text, _ = ev["message"].(string)
	return svc, text, false
}

func TestVectorEnforcesExactly(t *testing.T) {
	out, err := Vector([][]byte{[]byte(vectorUserConfig)}, vectorTarget(), testRules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	recs := genRecords(3000)
	events, metrics := runVector(t, out, recs)
	type key struct {
		svc, text string
		ts        float64
	}
	expect := map[key]int{}
	dedupeWant := map[string]int{}
	wantLines := map[string]float64{}
	wantBytes := map[string]float64{}
	for _, r := range recs {
		x := matched(r)
		if x != nil {
			wantLines[x.ID]++
			wantBytes[x.ID] += float64(len(r.text))
		}
		switch {
		case x == nil:
			expect[key{r.service, r.text, float64(r.ts)}]++
		case x.Action == "sample":
			if vectorKeep(r.text, r.ts, x.Keep) {
				expect[key{r.service, r.text, float64(r.ts)}]++
			}
		case x.Action == "dedupe":
			dedupeWant[x.ID]++
		}
	}
	got := map[key]int{}
	dedupeGot := map[string]int{}
	for _, ev := range events {
		svc, text, structured := eventText(ev)
		if c, ok := ev["sievelog_count"]; ok {
			x := matched(record{service: svc, text: text, mapBody: structured})
			if x == nil || x.Action != "dedupe" {
				t.Fatalf("count on a non-dedupe event: %v", ev)
			}
			dedupeGot[x.ID] += int(c.(float64))
			continue
		}
		for _, f := range []string{"sievelog_rule", "sievelog_bytes", "sievelog_aggregate"} {
			if _, ok := ev[f]; ok {
				t.Fatalf("internal field %s leaked downstream: %v", f, ev)
			}
		}
		ts, _ := ev["tsn"].(float64)
		got[key{svc, text, ts}]++
	}
	for k, n := range expect {
		if got[k] != n {
			t.Fatalf("expected %d of %+v, got %d", n, k, got[k])
		}
	}
	for k, n := range got {
		if expect[k] != n {
			t.Fatalf("unexpected %d of %+v (want %d)", n, k, expect[k])
		}
	}
	for id, n := range dedupeWant {
		if dedupeGot[id] != n {
			t.Fatalf("dedupe %s: counted %d, want %d", id, dedupeGot[id], n)
		}
	}
	for _, r := range testRules {
		if r.Action != "aggregate" {
			continue
		}
		if metrics["sievelog_aggregate_lines|"+r.ID] != wantLines[r.ID] {
			t.Fatalf("aggregate counter %s: %v want %v", r.ID, metrics["sievelog_aggregate_lines|"+r.ID], wantLines[r.ID])
		}
	}
	for id, n := range wantLines {
		if metrics["sievelog_rule_lines|"+id] != n || metrics["sievelog_rule_bytes|"+id] != wantBytes[id] {
			t.Fatalf("measurement %s: %v lines %v bytes, want %v / %v", id, metrics["sievelog_rule_lines|"+id], metrics["sievelog_rule_bytes|"+id], n, wantBytes[id])
		}
	}
	t.Logf("vector: %d events out of %d records exactly as predicted; dedupe %v", len(events), len(recs), dedupeGot)
}

func TestVectorShadowChangesNothing(t *testing.T) {
	out, err := Vector([][]byte{[]byte(vectorUserConfig)}, vectorTarget(), testRules, Shadow)
	if err != nil {
		t.Fatal(err)
	}
	recs := genRecords(1500)
	events, metrics := runVector(t, out, recs)
	if len(events) != len(recs) {
		t.Fatalf("shadow delivered %d of %d", len(events), len(recs))
	}
	want := map[string]float64{}
	for _, r := range recs {
		if x := matched(r); x != nil {
			want[x.ID]++
		}
	}
	for id, n := range want {
		if metrics["sievelog_rule_lines|"+id] != n {
			t.Fatalf("shadow measurement %s: %v want %v", id, metrics["sievelog_rule_lines|"+id], n)
		}
	}
}

// The runtime severity guard under real Vector: a drop rule's line at warning or above, by any
// level field or severity_number, passes through and is not counted.
func TestVectorSeverityGuard(t *testing.T) {
	rules := []Rule{
		{ID: "r-plain", ScopeAttr: "service.name", ScopeValue: "checkout", Language: `\AINFO heartbeat ok\z`, Action: "drop"},
		{ID: "r-field", ScopeAttr: "service.name", ScopeValue: "orders", Language: `\Ahandled route in 5ms\z`, Field: "msg", Action: "drop"},
	}
	cfg, err := Vector([][]byte{[]byte(vectorUserConfig)}, vectorTarget(), rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "vector.yaml"), cfg, 0o644)
	cases := []struct {
		extra   map[string]any
		svc     string
		removed bool
	}{
		{map[string]any{}, "checkout", true},
		{map[string]any{"level": "ERROR"}, "checkout", false},
		{map[string]any{"severity": " warning"}, "checkout", false},
		{map[string]any{"level": "info"}, "checkout", true},
		{map[string]any{"level": 50}, "checkout", true},
		{map[string]any{"severity_number": 13}, "checkout", false},
		{map[string]any{"severity_number": 9}, "checkout", true},
		{map[string]any{"body_level": "fatal"}, "orders", false},
		{map[string]any{}, "orders", true},
	}
	var in strings.Builder
	for i, c := range cases {
		ev := map[string]any{"service": c.svc, "tsn": 1790000000000000000 + i, "case": i}
		if c.svc == "orders" {
			body := map[string]any{"msg": "handled route in 5ms"}
			if lv, ok := c.extra["body_level"]; ok {
				body["level"] = lv
			}
			b, _ := json.Marshal(body)
			ev["message"], ev["structured"] = string(b), true
		} else {
			ev["message"] = "INFO heartbeat ok"
			for k, v := range c.extra {
				ev[k] = v
			}
		}
		b, _ := json.Marshal(ev)
		in.Write(b)
		in.WriteByte('\n')
	}
	events, metrics := runVectorInput(t, dir, in.String())
	kept := map[int]bool{}
	for _, ev := range events {
		if n, ok := ev["case"].(float64); ok {
			kept[int(n)] = true
		}
	}
	want := map[string]float64{}
	for i, c := range cases {
		if kept[i] == c.removed {
			t.Fatalf("case %d %v (%s): kept=%v, want removed=%v", i, c.extra, c.svc, kept[i], c.removed)
		}
		if c.removed {
			want["sievelog_rule_lines|r-"+map[string]string{"checkout": "plain", "orders": "field"}[c.svc]]++
		}
	}
	for k, v := range want {
		if metrics[k] != v {
			t.Fatalf("%s counted %v, want %v (severe events must not be measured)", k, metrics[k], v)
		}
	}
}
