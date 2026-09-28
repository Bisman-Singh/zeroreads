//go:build docker

package emit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
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
	archive               string // the rule that archived the record, if any
}

func runFluentBit(t *testing.T, cfg []byte, recs []record) ([]fbRecord, string) {
	t.Helper()
	return runFluentBitEnv(t, cfg, recs, nil)
}

// runFluentBitEnv runs Fluent Bit with extra environment variables (NAME=value).
func runFluentBitEnv(t *testing.T, cfg []byte, recs []record, env []string) ([]fbRecord, string) {
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
		for k, v := range r.extra {
			if bk, ok := strings.CutPrefix(k, "body."); ok && r.mapBody {
				ev["body"].(map[string]any)[bk] = v
			} else {
				ev[k] = v
			}
		}
		b, _ := json.Marshal(ev)
		in.Write(b)
		in.WriteByte('\n')
	}
	// Fluent Bit exits at stdin EOF without draining rewrite_tag's emitter, so part of the raw copy
	// would be lost (reproduced with the user config alone). stdin stays open until the whole raw
	// copy is out, then closes so the rest flushes.
	args := []string{"run", "-i", "--rm", "-v", dir + ":/w"}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	cmd := exec.Command("docker", append(args, "fluent/fluent-bit:5.1.2", "-c", "/w/fb.yaml")...)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { io.WriteString(stdin, in.String()) }()
	var outBuf strings.Builder
	rawSeen := 0
	closed := false
	timer := time.AfterFunc(90*time.Second, func() { stdin.Close(); cmd.Process.Kill() })
	defer timer.Stop()
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		l := sc.Text()
		outBuf.WriteString(l + "\n")
		rawSeen += strings.Count(l, `"stringValue":"raw"`)
		if !closed && rawSeen >= len(recs) {
			closed = true
			time.AfterFunc(3*time.Second, func() { stdin.Close() })
		}
	}
	if err := cmd.Wait(); err != nil || !closed {
		t.Fatalf("fluent-bit: %v (raw copy %d of %d records)\n%s", err, rawSeen, len(recs), stderr.String())
	}
	out := outBuf.String()
	var res []fbRecord
	var metrics strings.Builder
	// Both stdout outputs share one stream and their writes can land on the same line, so each
	// OTLP document is cut out wherever it starts and the text around it is metrics.
	var docs []string
	for _, l := range strings.Split(out, "\n") {
		for {
			i := strings.Index(l, `{"resourceLogs"`)
			if i < 0 {
				metrics.WriteString(l + "\n")
				break
			}
			metrics.WriteString(l[:i] + "\n")
			dec := json.NewDecoder(strings.NewReader(l[i:]))
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				t.Fatalf("otlp_json in %q: %v", l, err)
			}
			docs = append(docs, string(raw))
			l = l[i+int(dec.InputOffset()):]
		}
	}
	for _, l := range docs {
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
					r := fbRecord{stream: str(fields["stream"]), service: str(fields["service"]), ts: ts, archive: str(fields["sievelog_archive"])}
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
	// Fluent Bit stamps a whole stdin read with one time, so identical lines can share a key: records
	// are counted as a multiset, never collapsed.
	type key struct {
		svc, text  string
		ts         int64
		structured bool
	}
	raw, app := map[key]int{}, map[key]int{}
	for _, r := range got {
		k := key{r.service, r.text, r.ts, r.structured}
		switch r.stream {
		case "raw":
			raw[k]++
		case "app":
			app[k]++
		default:
			t.Fatalf("record without stream: %+v", r)
		}
	}
	total := 0
	for _, n := range raw {
		total += n
	}
	if total != len(recs) {
		t.Fatalf("raw copy has %d records, want %d", total, len(recs))
	}
	counts := map[string]int{}
	delivered := 0
	for k, n := range raw {
		x := match(k.svc, k.text, k.structured)
		want := n
		if x != nil {
			counts[x.ID] += n
			switch x.Action {
			case "drop", "aggregate":
				want = 0
			case "sample":
				if !fbKeep(k.text, k.ts, x.Keep) {
					want = 0
				}
			}
		}
		if app[k] != want {
			rid := "none"
			if x != nil {
				rid = x.ID
			}
			t.Fatalf("%+v (rule %s): delivered %d of %d, want %d", k, rid, app[k], n, want)
		}
		delivered += want
	}
	for k := range app {
		if raw[k] == 0 {
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
	t.Logf("fluent bit: %d of %d records delivered exactly as predicted (%d distinct keys); per-rule counts %v", delivered, len(recs), len(raw), counts)
}

func TestFluentBitRefusesDedupe(t *testing.T) {
	if _, err := FluentBit([][]byte{[]byte(fluentBitUserConfig)}, fluentBitTarget(), testRules, Enforce); err == nil || !strings.Contains(err.Error(), "cannot enforce dedupe") {
		t.Fatalf("got %v", err)
	}
}

// The runtime severity guard under real Fluent Bit: a drop rule's record at warning or above in a
// level field passes through and is not counted.
func TestFluentBitSeverityGuard(t *testing.T) {
	rules := []Rule{
		{ID: "r-plain", ScopeAttr: "service.name", ScopeValue: "checkout", Language: `\AINFO heartbeat [0-9]+\z`, Action: "drop"},
		{ID: "r-field", ScopeAttr: "service.name", ScopeValue: "orders", Language: `\Ahandled route in [0-9]+ms\z`, Field: "msg", Action: "drop"},
	}
	cfg, err := FluentBit([][]byte{[]byte(fluentBitUserConfig)}, fluentBitTarget(), rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		extra   map[string]any
		body    bool
		removed bool
	}{
		{nil, false, true},
		{map[string]any{"level": "ERROR"}, false, false},
		{map[string]any{"severity": " warning"}, false, false},
		{map[string]any{"level": "info"}, false, true},
		{map[string]any{"lvl": "Fatal"}, false, false},
		{map[string]any{"body.level": "crit"}, true, false},
		{nil, true, true},
	}
	var recs []record
	for i, c := range cases {
		r := record{service: "checkout", text: fmt.Sprintf("INFO heartbeat %d", i), extra: c.extra}
		if c.body {
			r = record{service: "orders", text: fmt.Sprintf("handled route in %dms", i), mapBody: true, extra: c.extra}
		}
		recs = append(recs, r)
	}
	got, metrics := runFluentBit(t, cfg, recs)
	delivered := map[string]bool{}
	for _, r := range got {
		if r.stream == "app" {
			delivered[r.text] = true
		}
	}
	counted := map[string]int{}
	for i, c := range cases {
		if delivered[recs[i].text] == c.removed {
			t.Fatalf("case %d %v: delivered=%v, want removed=%v", i, c.extra, delivered[recs[i].text], c.removed)
		}
		if c.removed {
			counted[map[bool]string{false: "r-plain", true: "r-field"}[c.body]]++
		}
	}
	for id, n := range counted {
		re := regexp.MustCompile(regexp.QuoteMeta(metricName("sievelog_rule_lines", id)) + `\S* = (\d+)`)
		m := re.FindAllStringSubmatch(metrics, -1)
		if len(m) == 0 || m[len(m)-1][1] != strconv.Itoa(n) {
			t.Fatalf("%s: counted %v, want %d (severe records must not be measured)", id, m, n)
		}
	}
}

// Fluent Bit expands ${NAME} anywhere in its configuration and has no escape for it: values from
// the logs must reach it only as regex escapes. Found by the v1 audit.
func TestFluentBitWritesDollarLiterally(t *testing.T) {
	svc, text := "svc${SECRET}", "cost ${SECRET} x"
	rules := []Rule{{ID: "r-dollar", ScopeAttr: "service.name", ScopeValue: svc, Language: `\A` + regexp.QuoteMeta(text) + `\z`, Action: "drop"}}
	cfg, err := FluentBit([][]byte{[]byte(fluentBitUserConfig)}, fluentBitTarget(), rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), "${") {
		t.Fatalf("the emitted configuration contains ${:\n%s", cfg)
	}
	recs := []record{{service: svc, text: text, ts: 1}, {service: "svcleaked", text: text, ts: 2}, {service: svc, text: "cost leaked x", ts: 3}}
	out, _ := runFluentBitEnv(t, cfg, recs, []string{"SECRET=leaked"})
	kept := map[[2]string]bool{}
	for _, r := range out {
		if r.stream == "app" {
			kept[[2]string{r.service, r.text}] = true
		}
	}
	for k, want := range map[[2]string]bool{{svc, text}: false, {"svcleaked", text}: true, {svc, "cost leaked x"}: true} {
		if kept[k] != want {
			t.Fatalf("%q: kept %v, want %v", k, kept[k], want)
		}
	}
}
