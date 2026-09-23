package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/emit"
)

// fakeLokiInstant answers instant metric queries from a table keyed by a substring of the query and
// whether the query's time is the after window's end.
func fakeLokiInstant(t *testing.T, afterEnd time.Time, values map[string][2]float64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		after := r.URL.Query().Get("time") == jsonTime(afterEnd)
		v := 0.0
		for k, pair := range values {
			if strings.Contains(q, k) {
				v = pair[0]
				if after {
					v = pair[1]
				}
			}
		}
		res := []any{}
		if v != 0 {
			res = append(res, map[string]any{"metric": map[string]string{}, "value": []any{1, jsonFloat(v)}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": res}})
	}))
}

func jsonTime(t time.Time) string { b, _ := json.Marshal(t.UnixNano()); return string(b) }
func jsonFloat(v float64) string  { b, _ := json.Marshal(v); return string(b) }

func TestReconcileStatuses(t *testing.T) {
	before := Window{Start: time.Unix(1000, 0), End: time.Unix(4600, 0)}
	after := Window{Start: time.Unix(5000, 0), End: time.Unix(8600, 0)}
	srv := fakeLokiInstant(t, after.End, map[string][2]float64{
		"count_over_time({service_name=\"svc\"} |~ `\\Adrop-ok\\z`":    {100, 0},
		"count_over_time({service_name=\"svc\"} |~ `\\Adrop-bad\\z`":   {100, 3},
		"count_over_time({service_name=\"svc\"} |~ `\\Asample-ok\\z`":  {1000, 310},
		"count_over_time({service_name=\"svc\"} |~ `\\Asample-bad\\z`": {1000, 900},
		"count_over_time({service_name=\"svc\"} |~ `\\Aquiet\\z`":      {0, 0},
	})
	defer srv.Close()
	c := &Config{Loki: LokiConfig{URL: srv.URL}, Scope: ScopeConfig{LokiLabel: "service_name"}}
	mk := func(id, lang, action string, keep int) EnforcedRule {
		return EnforcedRule{Rule: emit.Rule{ID: id, Language: lang, Action: action, Keep: keep}, Service: "svc"}
	}
	rf := &RulesFile{Rules: []EnforcedRule{
		mk("r-drop-ok", `\Adrop-ok\z`, "drop", 0),
		mk("r-drop-bad", `\Adrop-bad\z`, "aggregate", 0),
		mk("r-sample-ok", `\Asample-ok\z`, "sample", 30),
		mk("r-sample-bad", `\Asample-bad\z`, "sample", 30),
		mk("r-quiet", `\Aquiet\z`, "sample", 30),
	}}
	res, err := Reconcile(context.Background(), c, rf, before, after, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"r-drop-ok": "ok", "r-drop-bad": "mismatch", "r-sample-ok": "ok", "r-sample-bad": "mismatch", "r-quiet": "no-traffic"}
	for _, r := range res.Rules {
		if r.Status != want[r.RuleID] {
			t.Fatalf("%s: %s (%s), want %s", r.RuleID, r.Status, r.Detail, want[r.RuleID])
		}
	}
	if res.OK {
		t.Fatal("reconciliation with mismatches reported OK")
	}
}
