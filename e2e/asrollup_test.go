//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bisman-Singh/zeroreads/internal/analyze"
	"github.com/Bisman-Singh/zeroreads/internal/app"
	"github.com/Bisman-Singh/zeroreads/internal/gen"
	"github.com/Bisman-Singh/zeroreads/internal/rewrite"
	"github.com/Bisman-Singh/zeroreads/internal/source/loki"
)

// TestRollupRewritesKeepCounts rolls up a template that a Grafana alert rule and a dashboard panel
// count, rewrites both, and proves on real Loki that every rewritten query returns the original
// numbers before enforcement and after it, while the lines themselves are gone.
func TestRollupRewritesKeepCounts(t *testing.T) {
	e := &loopEnv{t: t, work: env(t, "E2E_WORK"), loki: env(t, "LOKI_URL")}
	e.root, _ = filepath.Abs("..")
	e.kube = filepath.Join(e.work, "kubeconfig")
	grafanaURL := env(t, "GRAFANA_URL")
	setupGrafanaFixtures(t, grafanaURL)
	lc := &loki.Client{Base: e.loki}

	// A batch generated through the normal pipeline, so the analysis sees fresh lines.
	userCfg, code := e.run(filepath.Join(e.root, "e2e"), "go", "run", "./render", "--loop")
	if code != 0 {
		t.Fatal(userCfg)
	}
	userPath := filepath.Join(e.work, "rollup-user.yaml")
	os.WriteFile(userPath, []byte(userCfg), 0o644)
	e.resetOutputs()
	e.deployCollector(userPath)
	preStart := time.Now().Add(-time.Second)
	nsA := e.batch("rollup-pre", 31, 2000)
	e.nsLines(nsA, 6000)
	preEnd := time.Now()

	// The readers: an API-managed alert rule and a dashboard panel, both counting cache lines.
	s, b := grafanaCall(t, grafanaURL, "POST", "/api/folders", 1, map[string]any{"uid": "zeroreads-rollup", "title": "zeroreads rollup e2e"})
	if s != 200 && s != 412 && s != 409 {
		t.Fatalf("folder: %d %s", s, b)
	}
	alertExpr := `sum(count_over_time({service_name="checkout"} |= "DEBUG cache" [10m]))`
	s, b = grafanaCall(t, grafanaURL, "POST", "/api/v1/provisioning/alert-rules", 1, map[string]any{
		"uid": "rollup-cache", "title": "cache volume", "ruleGroup": "rollup", "folderUID": "zeroreads-rollup", "orgID": 1,
		"condition": "C", "for": "0s", "noDataState": "OK", "execErrState": "OK",
		"data": []any{
			map[string]any{"refId": "A", "datasourceUid": "loki", "relativeTimeRange": map[string]any{"from": 600, "to": 0},
				"model": map[string]any{"refId": "A", "expr": alertExpr, "queryType": "instant"}},
			map[string]any{"refId": "C", "datasourceUid": "__expr__", "relativeTimeRange": map[string]any{"from": 0, "to": 0},
				"model": map[string]any{"refId": "C", "type": "threshold", "expression": "A",
					"conditions": []any{map[string]any{"evaluator": map[string]any{"type": "gt", "params": []any{1e12}}}}}},
		}})
	if s != 201 {
		t.Fatalf("alert rule: %d %s", s, b)
	}
	defer grafanaCall(t, grafanaURL, "DELETE", "/api/v1/provisioning/alert-rules/rollup-cache", 1, nil)
	panelExpr := `sum by (k8s_namespace_name) (count_over_time({service_name="checkout"} |~ "cache" [$__interval]))`
	s, b = grafanaCall(t, grafanaURL, "POST", "/api/dashboards/db", 1, map[string]any{"overwrite": true, "folderUid": "zeroreads-rollup", "dashboard": map[string]any{
		"uid": "rollup-cache", "title": "Cache volume", "schemaVersion": 41,
		"panels": []any{map[string]any{"id": 1, "type": "timeseries", "datasource": map[string]any{"type": "loki", "uid": "loki"},
			"targets": []any{map[string]any{"refId": "A", "expr": panelExpr}}}}}})
	must(t, s, b, 200)
	defer grafanaCall(t, grafanaURL, "DELETE", "/api/dashboards/uid/rollup-cache", 1, nil)
	defer grafanaCall(t, grafanaURL, "DELETE", "/api/folders/zeroreads-rollup", 1, nil)

	cfgPath := filepath.Join(e.work, "zeroreads-rollup.yaml")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(`loki:
  url: %s
scope:
  services: [checkout, auth, orders]
  structured: {orders: msg}
discovery:
  window: 1h
  slices: 12
  sample_lines_per_service: 6000
drain:
  masking_rules:
    - {name: %s, pattern: '%s'}
evidence:
  window: 1h
  query_log: {enabled: true, selector: '{service_name="loki"}', prove_live: true}
  ruler: true
  grafana:
    - {url: %s, username: admin, password_env: E2E_GRAFANA_PASSWORD, datasources: [loki, loki2]}
collector:
  config_files: [%s]
  pipeline: logs
  after: transform/prep
  measure_exporters: [file/metrics]
  dedupe_interval: 3s
  sinks:
    otlp_http/loki: {loki: true}
    file/logs: {exempt: "e2e local copy"}
policy:
  actions: [rollup]
  experimental_rollup: true
  acknowledge: ["%s", querylog-window]
`, e.loki, gen.IPMaskName, gen.IPMaskPattern, grafanaURL, userPath, grafanaGap("queryhistory", grafanaURL))), 0o644)
	os.Setenv("E2E_GRAFANA_PASSWORD", grafanaPass)
	e.bin = filepath.Join(e.work, "zeroreads")
	if out, code := e.run(e.root, "go", "build", "-o", e.bin, "./cmd/zeroreads"); code != 0 {
		t.Fatal(out)
	}

	// 1. Analyze: the cache template rolls up, with both readers rewritten.
	outDir := filepath.Join(e.work, "rollup-out")
	out, code := e.run(e.root, e.bin, "analyze", "-c", cfgPath, "-o", outDir)
	if code != 0 {
		t.Fatal(out)
	}
	rulesPath := filepath.Join(outDir, "rules.json")
	rf, err := app.LoadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	var cacheRule *app.EnforcedRule
	for i := range rf.Rules {
		if rf.Rules[i].Template == "DEBUG cache <*> key <*>" {
			cacheRule = &rf.Rules[i]
		}
	}
	if cacheRule == nil || cacheRule.Action != "rollup" {
		md, _ := os.ReadFile(filepath.Join(outDir, "report.md"))
		t.Fatalf("cache template not rolled up:\n%s", md)
	}
	stored := map[string]string{}
	for _, rw := range cacheRule.Rewrites {
		if rw.Store == "grafana" {
			stored[strings.SplitN(rw.Path, "/", 2)[0]] = rw.New
		}
	}
	if stored["alertrule:rollup-cache"] == "" || stored["dashboard:rollup-cache"] == "" {
		t.Fatalf("rewrites %+v, want the alert rule and the dashboard", cacheRule.Rewrites)
	}
	t.Logf("analyze: %s rolls up with %d rewrites", cacheRule.ID, len(cacheRule.Rewrites))

	// 2. Before enforcement the rewritten queries return exactly the original numbers.
	now := time.Now()
	for _, rw := range cacheRule.Rewrites {
		if rw.Store == "" {
			continue
		}
		oldQ := strings.ReplaceAll(rw.Old, "$__interval", "30m")
		newQ := strings.ReplaceAll(rw.New, "$__interval", "30m")
		if a, b := instant(t, lc, oldQ, now), instant(t, lc, newQ, now); a != b || a == "" {
			t.Fatalf("before enforcement %s:\n  original %s = %s\n  rewritten %s = %s", rw.Path, oldQ, a, newQ, b)
		}
	}
	t.Logf("before enforcement: every rewritten query returns the original result")

	// One query rewritten for every rolled-up rule at once, and two rules in different services with
	// the same language under one selector spanning both: each line is still counted exactly once.
	var rolledUp []rewrite.Rule
	for _, r := range rf.Rules {
		if r.Action == "rollup" {
			rolledUp = append(rolledUp, rewrite.Rule{ID: r.ID, Language: r.Language, Scope: map[string]string{"service_name": r.Service}})
		}
	}
	twins := []rewrite.Rule{
		{ID: cacheRule.ID, Language: cacheRule.Language, Scope: map[string]string{"service_name": "checkout"}},
		{ID: "r-000000000000", Language: cacheRule.Language, Scope: map[string]string{"service_name": "auth"}},
	}
	nsSel := `{k8s_namespace_name="` + nsA + `"}`
	for _, c := range []struct {
		expr  string
		rules []rewrite.Rule
	}{
		{`sum(count_over_time({service_name="checkout", k8s_namespace_name="` + nsA + `"} != "/healthz" [30m]))`, rolledUp},
		{`sum(count_over_time(` + nsSel + ` |= "DEBUG cache" [30m]))`, twins},
		{`sum by (service_name) (count_over_time(` + nsSel + ` [30m]))`, twins},
	} {
		res, err := rewrite.Query(c.expr, c.rules, map[string]bool{"service_name": true, "k8s_namespace_name": true})
		if err != nil || !res.Changed || len(res.Rules) != len(c.rules) {
			t.Fatalf("rewrite %s: %v %+v", c.expr, err, res)
		}
		if a, b := instant(t, lc, c.expr, now), instant(t, lc, res.Expr, now); a != b || a == "" {
			t.Fatalf("before enforcement, %d rules:\n  original %s = %s\n  rewritten %s = %s", len(c.rules), c.expr, a, res.Expr, b)
		}
	}
	t.Logf("before enforcement: a query rewritten for %d rolled-up rules, and for two services sharing a language, returns the original result", len(rolledUp))

	// 3. Apply the rewrites; the stored objects now hold the rewritten queries.
	rwDir := filepath.Join(e.work, "rollup-rewrites")
	out, code = e.run(e.root, e.bin, "rewrite", "-c", cfgPath, "-rules", rulesPath, "-o", rwDir, "-apply")
	rulerFile := ""
	for _, rw := range cacheRuleAndOthers(rf) {
		if rw.Store == "loki-ruler" {
			matches, _ := filepath.Glob(filepath.Join(rwDir, "*-loki-ruler.yaml"))
			if len(matches) != 1 {
				t.Fatalf("ruler rewrite file: %v", matches)
			}
			rulerFile = matches[0]
		}
	}
	if rulerFile != "" {
		// This ruler reads local files, so the API refuses the group: the operator installs the
		// written namespace file, the ruler reloads it, and a second apply records completion.
		if code != 5 || !strings.Contains(out, "local files needs the written file") {
			t.Fatalf("rewrite -apply with a local-file ruler (exit %d): %s", code, out)
		}
		nsFile, _ := os.ReadFile(rulerFile)
		cm := e.kubectl("create", "configmap", "loki-rules", "-n", "zeroreads-system", "--from-literal=rules.yaml="+string(nsFile), "--dry-run=client", "-o", "yaml")
		cmPath := filepath.Join(e.work, "rollup-loki-rules.yaml")
		os.WriteFile(cmPath, []byte(cm), 0o644)
		e.kubectl("apply", "-f", cmPath)
		t.Cleanup(func() {
			// Put the fixture rules back for the tests that follow, and wait until the ruler has them.
			e.kubectl("apply", "-f", filepath.Join(e.root, "e2e", "k8s", "loki.yaml"))
			for deadline := time.Now().Add(5 * time.Minute); time.Now().Before(deadline); time.Sleep(5 * time.Second) {
				rules, err := lc.Rules(context.Background())
				restored := err == nil && len(rules) > 0
				for _, r := range rules {
					if strings.Contains(r.Expr, "zeroreads rollup ") {
						restored = false
					}
				}
				if restored {
					return
				}
			}
			t.Errorf("the ruler did not reload the fixture rules")
		})
		deadline := time.Now().Add(5 * time.Minute)
		for {
			rules, err := lc.Rules(context.Background())
			found := false
			for _, r := range rules {
				if strings.Contains(r.Expr, "zeroreads rollup ") {
					found = true
				}
			}
			if err == nil && found {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the ruler never loaded the rewritten rules: %v", err)
			}
			time.Sleep(5 * time.Second)
		}
		out, code = e.run(e.root, e.bin, "rewrite", "-c", cfgPath, "-rules", rulesPath, "-o", rwDir, "-apply")
	}
	if code != 0 {
		t.Fatalf("rewrite -apply (exit %d): %s", code, out)
	}
	_, ab := grafanaCall(t, grafanaURL, "GET", "/api/v1/provisioning/alert-rules/rollup-cache", 1, nil)
	_, db := grafanaCall(t, grafanaURL, "GET", "/api/dashboards/uid/rollup-cache", 1, nil)
	for what, body := range map[string][]byte{"alert rule": ab, "dashboard": db} {
		if !strings.Contains(string(body), rewrite.Marker(cacheRule.ID)) {
			t.Fatalf("%s was not rewritten: %s", what, body)
		}
	}
	if rf, err = app.LoadRules(rulesPath); err != nil || rf.RewritesAppliedAt.IsZero() {
		t.Fatalf("rules file does not record the rewrite: %v", err)
	}
	t.Logf("rewrite: alert rule and dashboard rewritten in Grafana: %s", strings.TrimSpace(out))

	// 4. Enforce the rollup.
	enforcePath := filepath.Join(e.work, "rollup-enforce.yaml")
	if out, code := e.run(e.root, e.bin, "emit", "-c", cfgPath, "-rules", rulesPath, "-mode", "enforce", "-o", enforcePath); code != 0 {
		t.Fatal(out)
	}
	e.resetOutputs()
	e.deployCollector(enforcePath)
	batchStart := time.Now().Add(-time.Second)
	nsB := e.batch("rollup", 32, 2000)
	time.Sleep(10 * time.Second) // rollups flush every 3s
	raw := e.readRaw(nsB)
	if len(raw) != 6000 {
		t.Fatalf("raw copy has %d records", len(raw))
	}
	lang := regexp.MustCompile(cacheRule.Language)
	var removed, cacheLike int
	for _, r := range raw {
		if r.service != "checkout" || r.structured {
			continue
		}
		if lang.MatchString(r.text) {
			removed++
		}
		if strings.Contains(r.text, "DEBUG cache") {
			cacheLike++
		}
	}
	sel := `{service_name="checkout", k8s_namespace_name="` + nsB + `"}`
	rng := strconv.Itoa(int(time.Since(batchStart).Seconds())+5) + "s"
	if got := instant(t, lc, "sum(count_over_time("+sel+" |~ `"+cacheRule.Language+"` ["+rng+"]))", time.Now()); got != "" {
		t.Fatalf("rolled-up lines still stored: %s", got)
	}
	rolled := instant(t, lc, "sum(sum_over_time("+sel+" |= `"+rewrite.Marker(cacheRule.ID)+"` | unwrap "+rewrite.CountLabel+" ["+rng+"]))", time.Now())
	if rolled != strconv.Itoa(removed) {
		t.Fatalf("rollup records count %s lines, the pipeline received %d", rolled, removed)
	}
	// The original query now misses the removed lines; its rewrite returns exactly the ground truth.
	orig := "sum(count_over_time(" + sel + ` |= "DEBUG cache" [` + rng + "]))"
	res, err := rewrite.Query(orig, []rewrite.Rule{{ID: cacheRule.ID, Language: cacheRule.Language, Scope: map[string]string{"service_name": "checkout"}}},
		map[string]bool{"service_name": true, "k8s_namespace_name": true})
	if err != nil || !res.Changed {
		t.Fatalf("rewrite: %v %+v", err, res)
	}
	at := time.Now()
	if got := instant(t, lc, res.Expr, at); got != strconv.Itoa(cacheLike) {
		t.Fatalf("after enforcement the rewritten query returns %s, ground truth %d\n%s", got, cacheLike, res.Expr)
	}
	if got := instant(t, lc, orig, at); got == strconv.Itoa(cacheLike) && removed > 0 {
		t.Fatalf("the original query should have lost the %d removed lines", removed)
	}
	t.Logf("enforce: %d cache lines removed and stored as rollups with exact counts; the rewritten count equals the ground truth %d", removed, cacheLike)

	// A count whose filter the rollup records' text would pass (!= "/healthz"), rewritten for every
	// rolled-up rule, still equals the ground truth: rollup records are never counted as lines.
	var all []rewrite.Rule
	for _, r := range rf.Rules {
		if r.Action == "rollup" {
			all = append(all, rewrite.Rule{ID: r.ID, Language: r.Language, Scope: map[string]string{"service_name": r.Service}})
		}
	}
	notHealth := 0
	for _, r := range raw {
		if r.service == "checkout" && !strings.Contains(r.text, "/healthz") {
			notHealth++
		}
	}
	orig2 := "sum(count_over_time(" + sel + ` != "/healthz" [` + rng + "]))"
	res2, err := rewrite.Query(orig2, all, map[string]bool{"service_name": true, "k8s_namespace_name": true})
	if err != nil || !res2.Changed {
		t.Fatalf("rewrite: %v %+v", err, res2)
	}
	if got := instant(t, lc, res2.Expr, at); got != strconv.Itoa(notHealth) {
		t.Fatalf("!= \"/healthz\" after enforcement: rewritten %s, ground truth %d (original now %s)\n%s", got, notHealth, instant(t, lc, orig2, at), res2.Expr)
	}
	t.Logf("enforce: a != \"/healthz\" count rewritten for %d rolled-up rules equals the ground truth %d", len(all), notHealth)

	// Reconcile from Loki's own data: no rolled-up line is stored after enforcement, and the rollup
	// records carry the removed lines' count.
	window := func(a, b time.Time) string {
		return a.UTC().Format(time.RFC3339Nano) + "," + b.UTC().Format(time.RFC3339Nano)
	}
	recPath := filepath.Join(e.work, "rollup-reconcile.json")
	out, code = e.run(e.root, e.bin, "reconcile", "-c", cfgPath, "-rules", rulesPath, "-before", window(preStart, preEnd), "-after", window(batchStart, time.Now()), "-o", recPath)
	if code != 0 {
		t.Fatalf("reconcile (exit %d): %s", code, out)
	}
	var rec app.Reconciliation
	rb, _ := os.ReadFile(recPath)
	if err := json.Unmarshal(rb, &rec); err != nil {
		t.Fatal(err)
	}
	for _, r := range rec.Rules {
		if r.RuleID == cacheRule.ID && (r.Status != "ok" || !strings.Contains(r.Detail, "rollup records count "+strconv.Itoa(removed)+" lines")) {
			t.Fatalf("reconcile %s: %s, %s (removed %d)", r.RuleID, r.Status, r.Detail, removed)
		}
	}
	t.Logf("reconcile: no rolled-up line stored after enforcement; rollup records count the %d removed lines", removed)

	// 5. Verify passes against the deployed config; a new dashboard with the original query fails it.
	out, code = e.run(e.root, e.bin, "verify", "-c", cfgPath, "-rules", rulesPath, "-deployed", enforcePath)
	if code != 0 {
		t.Fatalf("verify after rollup should pass (exit %d): %s", code, out)
	}
	s, b = grafanaCall(t, grafanaURL, "POST", "/api/dashboards/db", 1, map[string]any{"overwrite": true, "dashboard": map[string]any{
		"uid": "rollup-old", "title": "Old cache count", "schemaVersion": 41,
		"panels": []any{map[string]any{"id": 1, "type": "stat", "datasource": map[string]any{"type": "loki", "uid": "loki"},
			"targets": []any{map[string]any{"refId": "A", "expr": alertExpr}}}}}})
	must(t, s, b, 200)
	defer grafanaCall(t, grafanaURL, "DELETE", "/api/dashboards/uid/rollup-old", 1, nil)
	keepPath := filepath.Join(e.work, "rollup-keep.json")
	out, code = e.run(e.root, e.bin, "verify", "-c", cfgPath, "-rules", rulesPath, "-drift=false", "-o", keepPath)
	if code != 3 || !strings.Contains(out, cacheRule.ID) || !strings.Contains(out, "rollup-old") {
		t.Fatalf("verify should fail on a new unrewritten counting query (exit %d): %s", code, out)
	}
	// The revert file keeps when the rewrites were applied, so verifying it does not count old
	// executions of the original queries as readers.
	if keep, err := app.LoadRules(keepPath); err != nil || !keep.RewritesAppliedAt.Equal(rf.RewritesAppliedAt) {
		t.Fatalf("revert file: %v, rewrites applied at %v, want %v", err, keep, rf.RewritesAppliedAt)
	}
	t.Logf("verify: passes after the rollup, fails once an unrewritten counting query appears")
}

// cacheRuleAndOthers lists every rewrite in the rules file.
func cacheRuleAndOthers(rf *app.RulesFile) []analyze.Rewrite {
	var out []analyze.Rewrite
	for _, r := range rf.Rules {
		out = append(out, r.Rewrites...)
	}
	return out
}

// instant evaluates a LogQL metric query and renders the result as sorted "labels=value" pairs, or
// only the value when the result is one series without labels.
func instant(t *testing.T, lc *loki.Client, q string, at time.Time) string {
	t.Helper()
	s, err := lc.Instant(context.Background(), q, at)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	var parts []string
	for _, x := range s {
		v := strconv.FormatFloat(x.Value, 'f', -1, 64)
		if len(x.Labels) == 0 {
			parts = append(parts, v)
			continue
		}
		lb, _ := json.Marshal(x.Labels)
		parts = append(parts, string(lb)+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
