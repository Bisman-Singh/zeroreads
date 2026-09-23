//go:build docker

package emit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The user's config: records arrive on stdin tagged app; rewrite_tag keeps an untouched copy tagged
// raw (it never matches the rules' tag pattern), marked so the two streams can be told apart.
const fluentBitUserConfig = `
service:
  flush: 1
  log_level: error
pipeline:
  inputs:
    - name: stdin
      tag: app
  filters:
    - name: rewrite_tag
      match: app
      rule: $service ^.*$ raw true
      alias: copy
    - name: modify
      match: raw
      add: stream raw
    - name: modify
      match: app
      alias: prep
      add: stream app
  outputs:
    - name: stdout
      match_regex: ^(app|raw)$
      format: otlp_json
    - name: stdout
      match: sievelog.metrics
`

func fluentBitTarget() FluentBitTarget {
	return FluentBitTarget{Match: "app", After: "prep", ScopeKey: "service", TextKey: []string{"text"},
		FieldKeys: map[string][]string{"orders": {"body", "msg"}}, MetricsTag: "sievelog.metrics"}
}

type fbRecord struct {
	stream, service, text string
	structured            bool
	ts                    int64
}

func runFluentBit(t *testing.T, cfg []byte, recs []record) ([]fbRecord, string) {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "fb.yaml"), cfg, 0o644)
	var in strings.Builder
	for _, r := range recs {
		ev := map[string]any{"service": r.service}
		if r.mapBody {
			ev["body"] = map[string]any{"msg": r.text, "route": "/cart"}
		} else {
			ev["text"] = r.text // not "log": otlp_json output would make it the whole body and drop the other keys
		}
		b, _ := json.Marshal(ev)
		in.Write(b)
		in.WriteByte('\n')
	}
	cmd := exec.Command("docker", "run", "-i", "--rm", "-v", dir+":/w", "fluent/fluent-bit:5.1.2", "-c", "/w/fb.yaml")
	cmd.Stdin = strings.NewReader(in.String())
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("fluent-bit: %v\n%s\n%s", err, out, stderr.String())
	}
	var res []fbRecord
	var metrics strings.Builder
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "{") {
			metrics.WriteString(l + "\n")
			continue
		}
		var doc struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []struct {
						TimeUnixNano string          `json:"timeUnixNano"`
						Body         json.RawMessage `json:"body"`
					} `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		if err := json.Unmarshal([]byte(l), &doc); err != nil {
			t.Fatalf("otlp_json line %q: %v", l, err)
		}
		for _, rl := range doc.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				for _, lr := range sl.LogRecords {
					fields := kvlist(t, lr.Body)
					ts, _ := strconv.ParseInt(lr.TimeUnixNano, 10, 64)
					r := fbRecord{stream: str(fields["stream"]), service: str(fields["service"]), ts: ts}
					if b, ok := fields["body"].(map[string]any); ok {
						r.text, r.structured = str(b["msg"]), true
					} else {
						r.text = str(fields["text"])
					}
					if _, leaked := fields["sievelog_rule"]; leaked {
						t.Fatalf("sievelog_rule leaked downstream: %v", fields)
					}
					res = append(res, r)
				}
			}
		}
	}
	return res, metrics.String()
}

func str(v any) string { s, _ := v.(string); return s }

// kvlist decodes an OTLP AnyValue into plain Go values.
func kvlist(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var v struct {
		KvlistValue struct {
			Values []struct {
				Key   string          `json:"key"`
				Value json.RawMessage `json:"value"`
			} `json:"values"`
		} `json:"kvlistValue"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	for _, kv := range v.KvlistValue.Values {
		var sv struct {
			StringValue *string         `json:"stringValue"`
			Kvlist      json.RawMessage `json:"kvlistValue"`
		}
		json.Unmarshal(kv.Value, &sv)
		switch {
		case sv.StringValue != nil:
			out[kv.Key] = *sv.StringValue
		case sv.Kvlist != nil:
			out[kv.Key] = kvlist(t, kv.Value)
		}
	}
	return out
}

func fbKeep(text string, ts int64, keep int) bool {
	sum := sha256.Sum256([]byte(text + "|" + strconv.FormatInt(ts/1e9, 10) + leftPad(strconv.FormatInt(ts%1e9, 10), 9)))
	v, _ := strconv.ParseInt(hex.EncodeToString(sum[:])[:13], 16, 64)
	return v < FluentBitSampleThreshold(keep)
}

func leftPad(s string, n int) string { return strings.Repeat("0", n-len(s)) + s }

// fbRules is testRules without dedupe, which Fluent Bit cannot do.
func fbRules() []Rule {
	var out []Rule
	for _, r := range testRules {
		if r.Action != "dedupe" {
			out = append(out, r)
		}
	}
	return out
}

func TestFluentBitEnforcesExactly(t *testing.T) {
	rules := fbRules()
	out, err := FluentBit([][]byte{[]byte(fluentBitUserConfig)}, fluentBitTarget(), rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	recs := genRecords(2500)
	got, metrics := runFluentBit(t, out, recs)
	match := func(svc, text string, structured bool) *Rule {
		for i := range rules {
			r := &rules[i]
			if r.ScopeValue == svc && (r.Field != "") == structured && regexp.MustCompile(r.Language).MatchString(text) {
				return r
			}
		}
		return nil
	}
	type key struct {
		svc, text string
		ts        int64
	}
	raw, app := map[key]bool{}, map[key]bool{}
	for _, r := range got {
		k := key{r.service, r.text, r.ts}
		switch r.stream {
		case "raw":
			raw[k] = true
		case "app":
			app[k] = true
		default:
			t.Fatalf("record without stream: %+v", r)
		}
	}
	if len(raw) != len(recs) {
		t.Fatalf("raw copy has %d records, want %d", len(raw), len(recs))
	}
	counts := map[string]int{}
	for k := range raw {
		structured := false
		for _, r := range got {
			if r.stream == "raw" && r.service == k.svc && r.text == k.text && r.ts == k.ts {
				structured = r.structured
				break
			}
		}
		x := match(k.svc, k.text, structured)
		want := true
		if x != nil {
			counts[x.ID]++
			switch x.Action {
			case "drop", "aggregate":
				want = false
			case "sample":
				want = fbKeep(k.text, k.ts, x.Keep)
			}
		}
		if app[k] != want {
			rid := "none"
			if x != nil {
				rid = x.ID
			}
			t.Fatalf("%+v (rule %s): delivered=%v want %v", k, rid, app[k], want)
		}
	}
	for k := range app {
		if !raw[k] {
			t.Fatalf("delivered record not in the raw copy: %+v", k)
		}
	}
	for id, n := range counts {
		name := metricName("sievelog_rule_lines", id)
		re := regexp.MustCompile(regexp.QuoteMeta(name) + `\S* = (\d+)`)
		m := re.FindAllStringSubmatch(metrics, -1)
		if len(m) == 0 {
			t.Fatalf("no metric %s in:\n%s", name, metrics)
		}
		last, _ := strconv.Atoi(m[len(m)-1][1])
		if last != n {
			t.Fatalf("%s = %d, want %d", name, last, n)
		}
	}
	t.Logf("fluent bit: %d of %d records delivered exactly as predicted; per-rule counts %v", len(app), len(recs), counts)
}

func TestFluentBitRefusesDedupe(t *testing.T) {
	if _, err := FluentBit([][]byte{[]byte(fluentBitUserConfig)}, fluentBitTarget(), testRules, Enforce); err == nil || !strings.Contains(err.Error(), "deduplicate") {
		t.Fatalf("got %v", err)
	}
}
