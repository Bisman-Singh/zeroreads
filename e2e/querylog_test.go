//go:build e2e

package e2e

import (
	"context"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/Bisman-Singh/zeroreads/internal/source/loki"
)

// userQuery runs a query the way a person or dashboard would: untagged by the analyzer.
func userQuery(t *testing.T, base, q string) int {
	t.Helper()
	v := url.Values{}
	v.Set("query", q)
	v.Set("limit", "10")
	v.Set("start", strconv.FormatInt(time.Now().Add(-time.Hour).UnixNano(), 10))
	v.Set("end", strconv.FormatInt(time.Now().UnixNano(), 10))
	resp, err := http.Get(base + "/loki/api/v1/query_range?" + v.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestQueryLogCapturesEveryQuery(t *testing.T) {
	base := env(t, "LOKI_URL")
	recs, _ := groundTruth(t)
	client := &loki.Client{Base: base}
	ql := &loki.QueryLog{Logs: client, Selector: `{service_name="loki"}`}
	ctx := context.Background()

	if err := ql.ProveLive(ctx, client, 90*time.Second); err != nil {
		t.Fatalf("query log not live: %v", err)
	}
	// A negative control: a selector that does not match Loki's own logs cannot prove liveness.
	bad := &loki.QueryLog{Logs: client, Selector: `{service_name="nothing-here"}`}
	if err := bad.ProveLive(ctx, client, 10*time.Second); err == nil {
		t.Fatal("liveness proof passed with a selector that reads no query log")
	}

	start := time.Now()
	g := &queryGen{r: rand.New(rand.NewPCG(123, 456)), lines: recs}
	sent := map[string]bool{}
	for len(sent) < 150 {
		q := g.query()
		if userQuery(t, base, q) == http.StatusOK {
			sent[q] = true
		}
	}
	// A query the analyzer sends itself must never count as usage.
	own := `{service_name="checkout"} |= "zeroreads-own-marker"`
	if _, err := client.QueryRange(ctx, own, time.Now().Add(-time.Minute), time.Now(), 10); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Minute)
	var res loki.Result
	for {
		var err error
		res, err = ql.Read(ctx, start.Add(-time.Minute), time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, q := range res.Queries {
			got[q.Query] = true
		}
		missing := 0
		for q := range sent {
			if !got[q] {
				missing++
			}
		}
		if missing == 0 {
			if got[own] {
				t.Fatalf("the analyzer's own query was counted as usage")
			}
			break
		}
		if time.Now().After(deadline) {
			for q := range sent {
				if !got[q] {
					t.Errorf("never captured: %s", q)
				}
			}
			t.Fatalf("%d of %d user queries missing from the query log", missing, len(sent))
		}
		time.Sleep(3 * time.Second)
	}
	if res.Component != "frontend" {
		t.Fatalf("expected frontend query log lines, got %s", res.Component)
	}
	if res.Unparsed != 0 {
		t.Fatalf("%d query-log lines did not parse", res.Unparsed)
	}
	t.Logf("captured %d distinct user queries from %d query-log lines", len(res.Queries), res.Lines)
}

func TestRulerRules(t *testing.T) {
	base := env(t, "LOKI_URL")
	rules, err := (&loki.Client{Base: base}).Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"HealthzMissing":           `absent_over_time({service_name="checkout"} |= "healthz" [5m])`,
		"PaymentsDeclined":         `sum(count_over_time({service_name="checkout"} |= "declined" [5m])) > 100`,
		"checkout:requests:rate1m": `sum(rate({service_name="checkout"} |= "status" [1m]))`,
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules: %+v", len(rules), rules)
	}
	for _, r := range rules {
		if want[r.Name] != r.Expr {
			t.Fatalf("rule %s: expr %q, want %q", r.Name, r.Expr, want[r.Name])
		}
	}
}

// Live tails and pattern requests (Logs Drilldown) are not metrics.go lines; they must still be
// read as usage, and their visibility proven.
func TestQueryLogTailsAndPatterns(t *testing.T) {
	base := env(t, "LOKI_URL")
	client := &loki.Client{Base: base}
	ql := &loki.QueryLog{Logs: client, Selector: `{service_name="loki"}`}
	ctx := context.Background()
	if err := ql.ProveTail(ctx, client, 90*time.Second); err != nil {
		t.Fatalf("tail proof: %v", err)
	}
	if err := ql.ProvePatterns(ctx, client, 90*time.Second); err != nil {
		t.Fatalf("pattern proof: %v", err)
	}
	bad := &loki.QueryLog{Logs: client, Selector: `{service_name="nothing-here"}`}
	if err := bad.ProveTail(ctx, client, 8*time.Second); err == nil {
		t.Fatal("tail proof passed with a selector that reads no query log")
	}
	if err := bad.ProvePatterns(ctx, client, 8*time.Second); err == nil {
		t.Fatal("pattern proof passed with a selector that reads no query log")
	}

	start := time.Now()
	n := strconv.FormatInt(time.Now().UnixNano(), 10)
	tail := `{service_name="checkout"} |= "tail-user-` + n + `"`
	user := &loki.Client{Base: base}
	// A person tailing: sent without the analyzer's tag, like any client.
	if err := user.OpenTail(ctx, tail); err != nil {
		t.Fatal(err)
	}
	pattern := `{service_name="checkout", k8s_namespace_name="patterns-` + n + `"}`
	v := url.Values{}
	v.Set("query", pattern)
	v.Set("start", strconv.FormatInt(time.Now().Add(-time.Hour).UnixNano(), 10))
	v.Set("end", strconv.FormatInt(time.Now().UnixNano(), 10))
	resp, err := http.Get(base + "/loki/api/v1/patterns?" + v.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(3 * time.Second) {
		res, err := ql.Read(ctx, start.Add(-time.Minute), time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		types := map[string]string{}
		for _, q := range res.Queries {
			types[q.Query] = q.Type
		}
		if types[tail] == "tail" && types[pattern] == "patterns" {
			t.Logf("a live tail and a pattern request were read as usage (%d tails, %d pattern requests)", res.Tails, res.Patterns)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tail %q or pattern request %q missing: %v", types[tail], types[pattern], types)
		}
	}
}
