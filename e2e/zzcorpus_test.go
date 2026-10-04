//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/logql"
	"github.com/Bisman-Singh/sievelog/internal/source/grafana"
	"github.com/Bisman-Singh/sievelog/internal/usage"
)

// corpusLokiTag is the Loki release whose mixin dashboards are measured: the tested Loki version.
const corpusLokiTag = "v3.7.8"

// corpusDashboard is one downloaded dashboard and where it came from.
type corpusDashboard struct {
	Key, Source, Name string
	Model             []byte
}

// TestCorpusCoverage measures how much of the public Loki dashboard corpus sievelog decides
// exactly: every dashboard in the public Grafana dashboard directory that uses Loki, and the Loki
// mixin's dashboards at the tested Loki version. They are downloaded at run time into the e2e work
// directory, never into the repository (their licences are their authors'), imported into a
// throwaway Grafana organisation, read back with the product's Grafana reader, parsed with its
// parser and classified by usage.Assumptions, exactly as analyze would. It needs the internet, so it
// runs only with E2E_CORPUS=1.
func TestCorpusCoverage(t *testing.T) {
	if os.Getenv("E2E_CORPUS") != "1" {
		t.Skip("set E2E_CORPUS=1 to download the public dashboards")
	}
	base := env(t, "GRAFANA_URL")
	work := filepath.Join(env(t, "E2E_WORK"), "corpus")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	dashboards := append(directoryDashboards(t, work), mixinDashboards(t, work)...)
	org := corpusOrg(t, base)
	imported := importDashboards(t, base, org, dashboards)

	start := time.Now()
	res, err := (&grafana.Client{Base: base, Username: grafanaUser, Password: grafanaPass}).Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Grafana serves each dashboard in two schema versions, and the reader keeps a query from both when
	// they name its datasource differently: harmless for decisions, but the measure counts each distinct
	// query of a dashboard once.
	var queries []grafana.Query
	read, seen := 0, map[string]bool{}
	for _, q := range res.Queries {
		if q.Org != org {
			continue
		}
		read++
		dashboard, _, _ := strings.Cut(q.Origin, "/")
		if key := dashboard + "\x00" + q.Expr; !seen[key] {
			seen[key] = true
			queries = append(queries, q)
		}
	}
	t.Logf("corpus: %d dashboards downloaded, %d imported; the Grafana reader returned %d Loki queries from them in %s, %d distinct per dashboard",
		len(dashboards), imported, read, time.Since(start).Round(time.Millisecond), len(queries))
	// Any gap in the corpus org other than other users' query history means some dashboard was not read,
	// and the measure would count fewer queries than the corpus holds.
	incomplete := 0
	for _, g := range res.Gaps {
		if g.Org == org && g.Origin != "queryhistory" {
			t.Logf("gap %s: %s", g.Origin, g.Reason)
			incomplete++
		}
	}
	if incomplete > 0 || len(queries) < 100 {
		t.Fatalf("%d gaps and %d queries (orgs read %v): the corpus was not read whole", incomplete, len(queries), res.Orgs)
	}
	// Every distinct query read, so two runs can be compared dashboard by dashboard.
	var read2 []string
	for _, q := range queries {
		dashboard, _, _ := strings.Cut(q.Origin, "/")
		read2 = append(read2, dashboard+"\t"+q.Expr)
	}
	sort.Strings(read2)
	qb, _ := json.MarshalIndent(read2, "", "  ")
	if err := os.WriteFile(filepath.Join(env(t, "E2E_WORK"), "corpus-queries.json"), qb, 0o644); err != nil {
		t.Fatal(err)
	}
	cov := classifyCorpus(queries)
	t.Logf("corpus: %s", cov)
	b, _ := json.MarshalIndent(cov, "", "  ")
	if err := os.WriteFile(filepath.Join(env(t, "E2E_WORK"), "corpus-coverage.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// corpusCoverage is what the corpus measurement reports.
type corpusCoverage struct {
	Queries         int            `json:"queries"`
	Parsed          int            `json:"parsed"`
	ParseFailures   []string       `json:"parse_failures"`
	ExactPipeline   int            `json:"exact_pipeline"`     // every line filter modelled exactly
	ExactServiceTag int            `json:"exact_service_name"` // and the selector decides service_name exactly
	ExactOwnLabel   int            `json:"exact_own_label"`    // exact if the scope label were the label the query selects by
	TemplatedSel    int            `json:"templated_selector"` // a template variable in a stream matcher
	Kinds           map[string]int `json:"assumption_kinds"`   // queries per kind of assumption, scope label service_name
}

func (c corpusCoverage) String() string {
	pct := func(n int) float64 { return 100 * float64(n) / float64(max(c.Parsed, 1)) }
	kinds := make([]string, 0, len(c.Kinds))
	for k, n := range c.Kinds {
		kinds = append(kinds, fmt.Sprintf("%s=%d", k, n))
	}
	sort.Strings(kinds)
	return fmt.Sprintf("%d queries, %d parse (%d do not, each would block every rule); line filters modelled exactly in %d (%.1f%%); "+
		"exact with scope label service_name in %d (%.1f%%), with the scope label set to the label each query selects by in %d (%.1f%%); "+
		"a template variable in the selector in %d (%.1f%%); assumptions with service_name: %s",
		c.Queries, c.Parsed, len(c.ParseFailures), c.ExactPipeline, pct(c.ExactPipeline), c.ExactServiceTag, pct(c.ExactServiceTag),
		c.ExactOwnLabel, pct(c.ExactOwnLabel), c.TemplatedSel, pct(c.TemplatedSel), strings.Join(kinds, ", "))
}

func classifyCorpus(queries []grafana.Query) corpusCoverage {
	c := corpusCoverage{Queries: len(queries), Kinds: map[string]int{}}
	for _, q := range queries {
		pq, err := logql.Parse(q.Expr)
		if err != nil {
			c.ParseFailures = append(c.ParseFailures, fmt.Sprintf("%s: %v: %s", q.Origin, err, q.Expr))
			continue
		}
		c.Parsed++
		pipelineExact, serviceExact, ownExact, templated := true, true, true, false
		kinds := map[string]bool{}
		for _, sel := range pq.Selections {
			pipelineExact = pipelineExact && len(usage.Assumptions(sel, nil)) == 0
			full := usage.Assumptions(sel, []string{"service_name"})
			serviceExact = serviceExact && len(full) == 0
			for _, a := range full {
				kinds[usage.Kind(a)] = true
			}
			ownExact = ownExact && len(usage.Assumptions(sel, ownLabel(sel))) == 0
			for _, m := range sel.Matchers {
				templated = templated || strings.Contains(m.Value, "$") || strings.Contains(m.Value, "[[")
			}
		}
		for k := range kinds {
			c.Kinds[k]++
		}
		if pipelineExact {
			c.ExactPipeline++
		}
		if serviceExact {
			c.ExactServiceTag++
		}
		if ownExact {
			c.ExactOwnLabel++
		}
		if templated {
			c.TemplatedSel++
		}
	}
	return c
}

// ownLabel is the label a selection selects by with a literal value, as the scope label an operator
// whose dashboards look like this one would configure; nil when it has none.
func ownLabel(sel logql.Selection) []string {
	for _, m := range sel.Matchers {
		if !strings.Contains(m.Value, "$") && !strings.Contains(m.Value, "[[") {
			return []string{m.Name}
		}
	}
	if len(sel.Matchers) > 0 {
		return []string{sel.Matchers[0].Name}
	}
	return nil
}

// corpusGet fetches a public URL, retrying transient failures, identifying itself politely.
func corpusGet(t *testing.T, url string) []byte {
	t.Helper()
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		time.Sleep(time.Duration(attempt*attempt) * time.Second)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "sievelog-e2e-corpus")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			last = err
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err == nil && resp.StatusCode == http.StatusOK {
			return b
		}
		last = fmt.Errorf("status %d: %.200s", resp.StatusCode, b)
	}
	t.Fatalf("GET %s: %v", url, last)
	return nil
}

// cached returns the file at path, fetching url into it first when it is not there yet.
func cached(t *testing.T, path, url string) []byte {
	t.Helper()
	if b, err := os.ReadFile(path); err == nil {
		return b
	}
	b := corpusGet(t, url)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return b
}

// directoryDashboards downloads every dashboard of the public Grafana dashboard directory that uses
// Loki, at its latest revision.
func directoryDashboards(t *testing.T, work string) []corpusDashboard {
	t.Helper()
	var out []corpusDashboard
	for page := 1; ; page++ {
		var list struct {
			Items []struct {
				ID       int    `json:"id"`
				Revision int    `json:"revision"`
				Name     string `json:"name"`
			} `json:"items"`
		}
		url := fmt.Sprintf("https://grafana.com/api/dashboards?dataSourceSlugIn=loki&orderBy=downloads&direction=desc&pageSize=100&page=%d", page)
		if err := json.Unmarshal(corpusGet(t, url), &list); err != nil {
			t.Fatal(err)
		}
		if len(list.Items) == 0 {
			return out
		}
		for _, it := range list.Items {
			key := fmt.Sprintf("gcom-%d-r%d", it.ID, it.Revision)
			model := cached(t, filepath.Join(work, key+".json"),
				fmt.Sprintf("https://grafana.com/api/dashboards/%d/revisions/%d/download", it.ID, it.Revision))
			out = append(out, corpusDashboard{Key: key, Source: "dashboard directory", Name: it.Name, Model: model})
		}
	}
}

// mixinDashboards downloads the Loki mixin's compiled dashboards at the tested Loki version.
func mixinDashboards(t *testing.T, work string) []corpusDashboard {
	t.Helper()
	var files []struct {
		Name        string `json:"name"`
		DownloadURL string `json:"download_url"`
	}
	url := "https://api.github.com/repos/grafana/loki/contents/production/loki-mixin-compiled/dashboards?ref=" + corpusLokiTag
	if err := json.Unmarshal(cached(t, filepath.Join(work, "mixin-"+corpusLokiTag+".json"), url), &files); err != nil {
		t.Fatal(err)
	}
	var out []corpusDashboard
	for _, f := range files {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		key := "mixin-" + strings.TrimSuffix(f.Name, ".json")
		out = append(out, corpusDashboard{Key: key, Source: "Loki mixin " + corpusLokiTag, Name: f.Name,
			Model: cached(t, filepath.Join(work, key+".json"), f.DownloadURL)})
	}
	return out
}

// corpusOrg creates a throwaway Grafana organisation with a Loki and a Prometheus datasource, and
// deletes it when the test ends so no other test reads the corpus.
func corpusOrg(t *testing.T, base string) int64 {
	t.Helper()
	s, b := grafanaCall(t, base, "POST", "/api/orgs", 0, map[string]any{"name": fmt.Sprintf("sievelog-corpus-%d", time.Now().Unix())})
	must(t, s, b, http.StatusOK)
	var created struct {
		OrgID int64 `json:"orgId"`
	}
	json.Unmarshal(b, &created)
	t.Cleanup(func() { dropOrg(t, base, created.OrgID) })
	for _, ds := range []map[string]any{
		{"name": "corpus-loki", "uid": "corpus-loki", "type": "loki", "access": "proxy", "url": "http://loki.sievelog-system.svc:3100", "isDefault": true},
		{"name": "corpus-prom", "uid": "corpus-prom", "type": "prometheus", "access": "proxy", "url": "http://localhost:9"},
	} {
		s, b := grafanaCall(t, base, "POST", "/api/datasources", created.OrgID, ds)
		must(t, s, b, http.StatusOK)
	}
	return created.OrgID
}

// importDashboards stores each dashboard as an operator would after importing it: every datasource
// input bound to the org's datasource of that type, library panels created first.
func importDashboards(t *testing.T, base string, org int64, dashboards []corpusDashboard) int {
	t.Helper()
	imported := 0
	for _, d := range dashboards {
		raw := string(d.Model)
		var model map[string]any
		if err := json.Unmarshal(d.Model, &model); err != nil {
			t.Logf("skip %s: not JSON: %v", d.Key, err)
			continue
		}
		inputs, _ := model["__inputs"].([]any)
		for _, in := range inputs {
			m, _ := in.(map[string]any)
			name, _ := m["name"].(string)
			value := ""
			switch m["type"] {
			case "datasource":
				switch m["pluginId"] {
				case "loki":
					value = "corpus-loki"
				case "prometheus":
					value = "corpus-prom"
				default:
					value = "corpus-other"
				}
			case "constant":
				value, _ = m["value"].(string)
			}
			if name != "" {
				raw = strings.ReplaceAll(raw, "${"+name+"}", value)
			}
		}
		if err := json.Unmarshal([]byte(raw), &model); err != nil {
			t.Logf("skip %s: inputs broke the JSON: %v", d.Key, err)
			continue
		}
		if elements, ok := model["__elements"].(map[string]any); ok {
			for uid, el := range elements {
				e, _ := el.(map[string]any)
				grafanaCall(t, base, "POST", "/api/library-elements", org, map[string]any{
					"uid": uid, "name": e["name"], "kind": 1, "model": e["model"]})
			}
		}
		for _, k := range []string{"__inputs", "__requires", "__elements", "id"} {
			delete(model, k)
		}
		model["uid"] = d.Key
		model["title"] = d.Key + " " + d.Name
		s, b := grafanaCall(t, base, "POST", "/api/dashboards/db", org, map[string]any{"dashboard": model, "overwrite": true})
		if s != http.StatusOK {
			t.Logf("skip %s: Grafana refused it (%d): %.200s", d.Key, s, b)
			continue
		}
		imported++
	}
	return imported
}
