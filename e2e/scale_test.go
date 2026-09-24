//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/app"
	"github.com/Bisman-Singh/sievelog/internal/gen"
	"github.com/Bisman-Singh/sievelog/internal/source/opensearch"
)

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

// pushLoki writes lines to Loki in large batches. Each stream's lines must be in time order.
func pushLoki(t *testing.T, base string, streams map[string]map[string]string, lines map[string][][2]string) {
	t.Helper()
	for key, labels := range streams {
		vals := lines[key]
		for i := 0; i < len(vals); i += 20000 {
			j := min(i+20000, len(vals))
			b, _ := json.Marshal(map[string]any{"streams": []any{map[string]any{"stream": labels, "values": vals[i:j]}}})
			resp, err := http.Post(base+"/loki/api/v1/push", "application/json", bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("loki push: %d %s", resp.StatusCode, body)
			}
		}
	}
}

// TestScale runs the analysis over a million stored lines and a query log of hundreds of thousands
// of executions, and reads a million audit entries from OpenSearch, checking every result exactly
// against the ground truth and bounding time and memory.
func TestScale(t *testing.T) {
	lokiURL := env(t, "LOKI_URL")
	work := env(t, "E2E_WORK")
	root, _ := filepath.Abs("..")
	total := envInt("E2E_SCALE_LINES", 1_000_000)
	execs := envInt("E2E_SCALE_QUERIES", 300_000)
	distinct := envInt("E2E_SCALE_DISTINCT", 20_000)
	audits := envInt("E2E_SCALE_AUDIT", 1_000_000)
	now := time.Now()
	run := fmt.Sprintf("scale%d", now.Unix()) // names of this run only, so reruns never see each other
	from := now.Add(-50 * time.Minute)
	span := 48 * time.Minute

	// 1. A million lines over 48 minutes, three services, four pods each.
	services := []string{"checkout", "auth", "orders"}
	streams := map[string]map[string]string{}
	lines := map[string][][2]string{}
	truth := map[string][]string{} // service -> templated text of every line
	per := total / len(services)
	for _, svc := range services {
		g, err := gen.New(svc, 99)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < per; i++ {
			r := g.Next()
			pod := fmt.Sprintf("pod-%d", i%4)
			key := svc + "/" + pod
			if streams[key] == nil {
				streams[key] = map[string]string{"service_name": run + "-" + svc, "k8s_namespace_name": "scale", "k8s_pod_name": pod}
			}
			ts := from.Add(time.Duration(int64(span) * int64(i) / int64(per)))
			lines[key] = append(lines[key], [2]string{strconv.FormatInt(ts.UnixNano(), 10), r.Line})
			truth[svc] = append(truth[svc], r.Message)
		}
	}
	start := time.Now()
	pushLoki(t, lokiURL, streams, lines)
	t.Logf("pushed %d lines to Loki in %s", per*len(services), time.Since(start).Round(time.Second))

	// 2. A query log: distinct queries executed many times, one of which reads the health checks.
	reader := `sum(count_over_time({service_name="` + run + `-checkout"} |= "healthz" [5m]))`
	var qlines [][2]string
	rng := rand.New(rand.NewPCG(7, 7))
	counts := map[string]int{}
	for i := 0; i < execs; i++ {
		q := fmt.Sprintf(`{service_name="%s-nothing-%d"} |= "x"`, run, rng.IntN(distinct-1))
		if i%1000 == 0 {
			q = reader
		}
		counts[q]++
		ts := from.Add(time.Duration(int64(span) * int64(i) / int64(execs)))
		line := fmt.Sprintf(`level=info ts=%s caller=metrics.go:237 component=frontend org_id=fake latency=fast query_type=filter status=200 query=%s`,
			ts.UTC().Format(time.RFC3339Nano), strconv.Quote(q))
		qlines = append(qlines, [2]string{strconv.FormatInt(ts.UnixNano(), 10), line})
	}
	pushLoki(t, lokiURL, map[string]map[string]string{"q": {"service_name": run + "-loki"}}, map[string][][2]string{"q": qlines})

	// 3. Analyze, measuring wall time and peak memory of the real binary.
	bin := filepath.Join(work, "sievelog")
	if out, err := runCmd(root, "go", "build", "-o", bin, "./cmd/sievelog"); err != nil {
		t.Fatal(out)
	}
	cfgPath := filepath.Join(work, "sievelog-scale.yaml")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(`loki:
  url: %[2]s
scope:
  services: [%[1]s-checkout, %[1]s-auth, %[1]s-orders]
  structured: {%[1]s-orders: msg}
discovery:
  window: 1h
drain:
  masking_rules:
    - {name: %[3]s, pattern: '%[4]s'}
evidence:
  window: 1h
  query_log: {enabled: true, selector: '{service_name="%[1]s-loki"}', prove_live: false}
  ruler: false
collector:
  config_files: [%[5]s]
  pipeline: logs
  after: transform/prep
  measure_exporters: [file/metrics]
  sinks:
    otlp_http/loki: {loki: true}
    file/logs: {exempt: "e2e local copy"}
policy:
  actions: [aggregate]
  acknowledge: [grafana-not-configured, ruler-not-checked, querylog-window]
`, run, lokiURL, gen.IPMaskName, gen.IPMaskPattern, filepath.Join(work, "loop-user.yaml"))), 0o644)
	outDir := filepath.Join(work, "scale-out")
	start = time.Now()
	out, err := runCmd(root, "/usr/bin/time", "-l", bin, "analyze", "-c", cfgPath, "-o", outDir)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("analyze: %v\n%s", err, out)
	}
	rss := 0
	if m := regexp.MustCompile(`(\d+)\s+maximum resident set size`).FindStringSubmatch(out); m != nil {
		rss, _ = strconv.Atoi(m[1])
	}
	t.Logf("analyze over %d lines and %d query executions: %s, peak memory %d MB", per*len(services), execs, elapsed.Round(time.Second), rss>>20)
	if elapsed > 10*time.Minute || rss > 2<<30 {
		t.Fatalf("analyze took %s and %d MB", elapsed, rss>>20)
	}
	var rep app.Report
	rb, _ := os.ReadFile(filepath.Join(outDir, "report.json"))
	if err := json.Unmarshal(rb, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Evidence.QueryLogLines != execs || rep.Evidence.QueryLogQueries != len(counts) {
		t.Fatalf("query log: %d lines, %d distinct; want %d and %d", rep.Evidence.QueryLogLines, rep.Evidence.QueryLogQueries, execs, len(counts))
	}
	// Every rule's measured volume equals the ground truth, and exactly the health rule is read.
	checked := 0
	for _, r := range rep.Recommendations {
		svc := strings.TrimPrefix(r.Candidate.Service, run+"-")
		re := regexp.MustCompile(r.Candidate.Language)
		want := 0
		for _, text := range truth[svc] {
			if re.MatchString(text) {
				want++
			}
		}
		if int(r.Candidate.Lines) != want {
			t.Fatalf("%s %q: measured %v lines, ground truth %d", r.Candidate.Service, r.Candidate.Template, r.Candidate.Lines, want)
		}
		read := false
		for _, rd := range r.Readers {
			if rd.Expr == reader {
				read = true
			} else {
				t.Fatalf("%s: unexpected reader %s", r.ID, rd.Expr)
			}
		}
		if read != (r.Candidate.Service == run+"-checkout" && strings.Contains(r.Candidate.Template, "healthz")) {
			t.Fatalf("%s %q: read %v", r.ID, r.Candidate.Template, read)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no rules")
	}
	t.Logf("scale: %d rules, every volume exact, exactly the health rule read, %d distinct queries from %d executions", checked, len(counts), execs)

	// 4. A million OpenSearch audit entries: identical requests fold, decisions stay exact.
	if os.Getenv("OPENSEARCH_URL") == "" {
		t.Fatal("OPENSEARCH_URL is not set")
	}
	idx := fmt.Sprintf("security-auditlog-scale-%d", now.Unix())
	defer osAdmin(t, "DELETE", "/"+idx, nil)
	osAdmin(t, "PUT", "/"+idx, map[string]any{"settings": map[string]any{"number_of_replicas": 0, "refresh_interval": "-1"}})
	distinctAudit := 10_000
	var buf strings.Builder
	flush := func() {
		if buf.Len() > 0 {
			osAdmin(t, "POST", "/_bulk", buf.String())
			buf.Reset()
		}
	}
	start = time.Now()
	for i := 0; i < audits; i++ {
		k := i % distinctAudit
		svc := []string{"checkout", "auth"}[k%2]
		body, _ := json.Marshal(map[string]any{"query": map[string]any{"term": map[string]any{"service.name": svc}}, "size": k % 50})
		doc, _ := json.Marshal(map[string]any{"@timestamp": from.Add(time.Duration(int64(span) * int64(i) / int64(audits))).UTC().Format(time.RFC3339Nano),
			"audit_request_layer": "REST", "audit_category": "AUTHENTICATED", "audit_rest_request_method": "POST",
			"audit_rest_request_path": "/scale-logs/_search", "audit_request_body": string(body)})
		fmt.Fprintf(&buf, "{\"index\":{\"_index\":%q}}\n%s\n", idx, doc)
		if (i+1)%20000 == 0 {
			flush()
		}
	}
	flush()
	osAdmin(t, "POST", "/"+idx+"/_refresh", nil)
	t.Logf("indexed %d audit entries in %s", audits, time.Since(start).Round(time.Second))
	cl := &opensearch.Client{Base: os.Getenv("OPENSEARCH_URL"), Username: "admin", Password: os.Getenv("OPENSEARCH_PASSWORD"), InsecureSkipVerify: true}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start = time.Now()
	res := (&opensearch.Reader{C: cl, AuditIndex: idx, DashboardsIndex: ".kibana*"}).Read(context.Background(), from.Add(-time.Minute), now)
	elapsed = time.Since(start)
	runtime.ReadMemStats(&after)
	if g := gapSet(res.Gaps); g["opensearch-audit-unreadable"] != "" {
		t.Fatal(g["opensearch-audit-unreadable"])
	}
	var uses []opensearch.Use
	folded := 0
	for _, u := range res.Uses {
		if u.Source == "audit" && u.Origin == "POST /scale-logs/_search" {
			uses = append(uses, u)
			folded += u.Count
		}
	}
	// 50 distinct bodies, but only the query decides what a search reads: they fold into one use
	// per service filter.
	if res.Lines != audits || folded != audits || len(uses) != 2 {
		t.Fatalf("audit: %d entries read, %d folded into %d uses; want %d into 2", res.Lines, folded, len(uses), audits)
	}
	scope := opensearch.Scope{Indices: []string{"scale-logs"}, ServiceField: "service.name", Service: "checkout"}
	reads := 0
	for _, u := range uses {
		if !u.CannotRead(scope) {
			reads += u.Count
		}
	}
	if reads != audits/2 {
		t.Fatalf("audit: %d executions read checkout, want %d", reads, audits/2)
	}
	t.Logf("audit: %d entries read in %s, folded into %d uses, %d MB allocated; decisions exact", audits, elapsed.Round(time.Second), len(uses), (after.TotalAlloc-before.TotalAlloc)>>20)
	if elapsed > 10*time.Minute {
		t.Fatalf("reading the audit log took %s", elapsed)
	}
}

func runCmd(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
