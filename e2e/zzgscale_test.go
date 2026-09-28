//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/app"
	"github.com/Bisman-Singh/sievelog/internal/gen"
)

// TestGrafanaScale stores thousands of dashboards in one Grafana organisation and runs the real
// analyze against it through that org's service account token, as an operator would. Every panel
// query is decided against every rule, the decisions must stay exact (only the panels that read the
// health checks read anything), and time and memory are bounded.
func TestGrafanaScale(t *testing.T) {
	base, lokiURL, work := env(t, "GRAFANA_URL"), env(t, "LOKI_URL"), env(t, "E2E_WORK")
	root, _ := filepath.Abs("..")
	n := envInt("E2E_GRAFANA_DASHBOARDS", 5000)
	readerEvery := 700
	run := fmt.Sprintf("gscale%d", time.Now().Unix())

	// 1. Lines of three services for the analysis to build rules from.
	services := []string{"checkout", "auth", "orders"}
	streams := map[string]map[string]string{}
	lines := map[string][][2]string{}
	from := time.Now().Add(-40 * time.Minute)
	for _, svc := range services {
		g, err := gen.New(svc, 5)
		if err != nil {
			t.Fatal(err)
		}
		streams[svc] = map[string]string{"service_name": run + "-" + svc, "k8s_namespace_name": "gscale"}
		for i := 0; i < 20000; i++ {
			ts := from.Add(time.Duration(i) * 100 * time.Millisecond)
			lines[svc] = append(lines[svc], [2]string{strconv.FormatInt(ts.UnixNano(), 10), g.Next().Line})
		}
	}
	pushLoki(t, lokiURL, streams, lines)

	// 2. An organisation with n dashboards of four panels each; every readerEvery-th dashboard has a
	// fifth panel that reads the checkout health checks.
	org := scaleOrg(t, base)
	reader := `sum(count_over_time({service_name="` + run + `-checkout"} |= "healthz" [$__auto]))`
	panel := func(id int, expr string) map[string]any {
		ds := map[string]any{"type": "loki", "uid": "scale-loki"}
		return map[string]any{"id": id, "type": "timeseries", "title": strconv.Itoa(id), "datasource": ds,
			"targets": []any{map[string]any{"refId": "A", "expr": expr, "datasource": ds}}}
	}
	start := time.Now()
	readers := 0
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed []string
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				panels := []any{
					panel(1, fmt.Sprintf(`{service_name="%s-auth"} |= "zq%dnone"`, run, i)),
					panel(2, fmt.Sprintf(`sum(rate({service_name="%s-checkout"} |~ "zq%d-[0-9]+" [$__auto]))`, run, i)),
					panel(3, fmt.Sprintf(`{service_name="%s-checkout"} != "healthz" |= "zq%d"`, run, i)),
					panel(4, fmt.Sprintf(`{service_name="%s-billing"} |= "x"`, run)),
				}
				if i%readerEvery == 0 {
					panels = append(panels, panel(5, reader))
				}
				body := map[string]any{"overwrite": true, "dashboard": map[string]any{
					"uid": fmt.Sprintf("%s-%d", run, i), "title": fmt.Sprintf("scale %d", i), "schemaVersion": 39, "panels": panels}}
				var s int
				var b []byte
				for attempt := 0; attempt < 5; attempt++ {
					var err error
					if s, b, err = grafanaDo(base, "POST", "/api/dashboards/db", org, body); err == nil && s == http.StatusOK {
						break
					} else if err != nil {
						b = []byte(err.Error())
					}
					time.Sleep(time.Duration(attempt+1) * time.Second) // SQLite can be briefly locked
				}
				if s != http.StatusOK {
					mu.Lock()
					failed = append(failed, fmt.Sprintf("%d: %d %.200s", i, s, b))
					mu.Unlock()
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		if i%readerEvery == 0 {
			readers++
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if len(failed) > 0 {
		t.Fatalf("%d dashboards not stored, e.g. %s", len(failed), failed[0])
	}
	queries := 4*n + readers
	t.Logf("stored %d dashboards with %d Loki queries in %s", n, queries, time.Since(start).Round(time.Second))
	token := scaleToken(t, base, org)

	// 3. Analyze through the org's token, measuring wall time and peak memory of the real binary.
	bin := filepath.Join(work, "sievelog")
	if out, err := runCmd(root, "go", "build", "-o", bin, "./cmd/sievelog"); err != nil {
		t.Fatal(out)
	}
	collector := filepath.Join(work, "gscale-collector.yaml")
	os.WriteFile(collector, []byte(`receivers:
  otlp:
    protocols: {http: {}}
processors:
  transform/prep:
    log_statements:
      - context: resource
        statements:
          - set(resource.attributes["service.name"], resource.attributes["k8s.container.name"])
exporters:
  otlp_http/loki:
    endpoint: http://loki.sievelog-system.svc:3100/otlp
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [transform/prep]
      exporters: [otlp_http/loki]
`), 0o644)
	cfgPath := filepath.Join(work, "sievelog-gscale.yaml")
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
  grafana:
    - url: %[5]s
      token_env: E2E_GSCALE_TOKEN
      datasources: [scale-loki]
collector:
  config_files: [%[6]s]
  pipeline: logs
  after: transform/prep
  sinks:
    otlp_http/loki: {loki: true}
policy:
  actions: [aggregate]
  acknowledge: [ruler-not-checked, querylog-window, querylog-not-proven, grafana-orgs, grafana-queryhistory]
`, run, lokiURL, gen.IPMaskName, gen.IPMaskPattern, base, collector)), 0o644)
	t.Setenv("E2E_GSCALE_TOKEN", token)
	outDir := filepath.Join(work, "gscale-out")
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
	var rep app.Report
	rb, _ := os.ReadFile(filepath.Join(outDir, "report.json"))
	if err := json.Unmarshal(rb, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Gaps) > 0 {
		for _, g := range rep.Gaps {
			if !slices.Contains([]string{"ruler-not-checked", "querylog-window", "querylog-not-proven", "grafana-orgs", "grafana-queryhistory"}, g.Key) {
				t.Fatalf("unexpected gap %s: %s", g.Key, g.Reason)
			}
		}
	}
	if rep.Evidence.GrafanaQueries != queries {
		t.Fatalf("read %d Grafana queries, stored %d", rep.Evidence.GrafanaQueries, queries)
	}
	// Exactly the checkout health rule is read, by exactly the reading panels, each exactly.
	healthRead := 0
	for _, r := range rep.Recommendations {
		for _, rd := range r.Readers {
			if rd.Expr != reader || len(rd.Widened) > 0 {
				t.Fatalf("%s %q: unexpected reader %s %v", r.ID, r.Candidate.Template, rd.Expr, rd.Widened)
			}
		}
		if len(r.Readers) > 0 {
			if r.Candidate.Service != run+"-checkout" || !strings.Contains(r.Candidate.Template, "healthz") || len(r.Readers) != readers {
				t.Fatalf("%s %q read by %d panels, want only the checkout health rule by %d", r.ID, r.Candidate.Template, len(r.Readers), readers)
			}
			healthRead++
		}
	}
	if healthRead != 1 || len(rep.Recommendations) < 5 {
		t.Fatalf("%d rules read, %d rules: want exactly the health rule read", healthRead, len(rep.Recommendations))
	}
	t.Logf("analyze with %d dashboards (%d Grafana queries): %d rules decided in %s, peak memory %d MB; exactly the health rule read, by its %d panels",
		n, queries, len(rep.Recommendations), elapsed.Round(time.Second), rss>>20, readers)
	if elapsed > 10*time.Minute || rss > 2<<30 {
		t.Fatalf("analyze took %s and %d MB", elapsed, rss>>20)
	}
}

// scaleOrg creates a throwaway organisation with one Loki datasource, deleted when the test ends so
// later tests never read its dashboards.
func scaleOrg(t *testing.T, base string) int64 {
	t.Helper()
	s, b := grafanaCall(t, base, "POST", "/api/orgs", 0, map[string]any{"name": fmt.Sprintf("sievelog-gscale-%d", time.Now().UnixNano())})
	must(t, s, b, http.StatusOK)
	var created struct {
		OrgID int64 `json:"orgId"`
	}
	json.Unmarshal(b, &created)
	t.Cleanup(func() { dropOrg(t, base, created.OrgID) })
	s, b = grafanaCall(t, base, "POST", "/api/datasources", created.OrgID, map[string]any{
		"name": "scale-loki", "uid": "scale-loki", "type": "loki", "access": "proxy", "url": "http://loki.sievelog-system.svc:3100", "isDefault": true})
	must(t, s, b, http.StatusOK)
	return created.OrgID
}

// scaleToken creates an Admin service account in the org and returns a token for it: such a token
// sees only its own org, which is how an operator would scope sievelog to one org.
func scaleToken(t *testing.T, base string, org int64) string {
	t.Helper()
	s, b := grafanaCall(t, base, "POST", "/api/serviceaccounts", org, map[string]any{"name": "sievelog-scale", "role": "Admin"})
	must(t, s, b, http.StatusOK, http.StatusCreated)
	var sa struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(b, &sa)
	s, b = grafanaCall(t, base, "POST", fmt.Sprintf("/api/serviceaccounts/%d/tokens", sa.ID), org, map[string]any{"name": "scale"})
	must(t, s, b, http.StatusOK)
	var tok struct {
		Key string `json:"key"`
	}
	json.Unmarshal(b, &tok)
	if tok.Key == "" {
		t.Fatalf("no token: %s", b)
	}
	return tok.Key
}
