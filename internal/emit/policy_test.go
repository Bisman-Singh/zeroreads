package emit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPoliciesVerifiedAgainstPolicyGo(t *testing.T) {
	out, skips, err := Policies(testRules, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range skips {
		t.Logf("skipped %s: %s", s.RuleID, s.Reason)
	}
	var pf policyFile
	if err := json.Unmarshal(out, &pf); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pf.Policies {
		got[p.ID] = p.Log.Keep
	}
	t.Logf("emitted %v", got)
	// Structured, aggregate and dedupe rules are never expressible.
	for _, id := range []string{"r-route", "r-cache", "r-heartbeat"} {
		if _, ok := got[id]; ok {
			t.Fatalf("%s must not be emitted as a policy", id)
		}
	}
	reasons := map[string]string{}
	for _, s := range skips {
		reasons[s.RuleID] = s.Reason
	}
	for _, r := range testRules {
		_, emitted := got[r.ID]
		_, skipped := reasons[r.ID]
		if emitted == skipped {
			t.Fatalf("%s: emitted=%v skipped=%v; every rule must be exactly one", r.ID, emitted, skipped)
		}
	}
	if got["r-health"] != "none" || got["r-request"] != "30%" {
		t.Fatalf("keep values %v", got)
	}
	if !strings.Contains(string(out), `"log_field": "body"`) {
		t.Fatalf("unexpected format: %s", out)
	}
}

// The differential check must catch a policy whose regex does not mean what the rule says.
func TestPolicyCheckCatchesDivergence(t *testing.T) {
	r := Rule{ID: "r-x", ScopeAttr: "service.name", ScopeValue: "svc", Language: `\AINFO heartbeat ok\z`, Action: "drop"}
	wrong := policyFile{Policies: []policyDoc{{ID: r.ID, Name: r.ID, Enabled: true, Log: policyLog{Keep: "none", Match: []map[string]any{
		{"resource_attribute": map[string]any{"path": []string{"service.name"}}, "equals": "svc"},
		{"log_field": "body", "regex": `heartbeat`}, // unanchored: matches far more than the rule
	}}}}}
	b, _ := json.Marshal(wrong)
	bad, err := checkPolicies(b, []Rule{r}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if bad[r.ID] == "" {
		t.Fatal("a divergent policy passed the check")
	}
	t.Logf("caught: %s", bad[r.ID])
}

// Constructs where regex engines are known to differ. Each is either proven equal on the tested
// strings or left out; the outcome is pinned so a runtime upgrade that changes it fails loudly.
func TestPolicyEngineDialectProbe(t *testing.T) {
	probes := []Rule{
		{ID: "r-dollar", ScopeAttr: "service.name", ScopeValue: "svc", Language: `^INFO heartbeat ok$`, Action: "drop"},
		{ID: "r-space", ScopeAttr: "service.name", ScopeValue: "svc2", Language: `\Aa\sb\z`, Action: "drop"},
		{ID: "r-fold", ScopeAttr: "service.name", ScopeValue: "svc3", Language: `\A(?i)kelvin\z`, Action: "drop"},
		{ID: "r-dot", ScopeAttr: "service.name", ScopeValue: "svc4", Language: `\Aa.b\z`, Action: "drop"},
		{ID: "r-word", ScopeAttr: "service.name", ScopeValue: "svc5", Language: `\A\w+\z`, Action: "drop"},
	}
	_, skips, err := Policies(probes, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range skips {
		t.Logf("left out %s: %s", s.RuleID, s.Reason)
	}
	// Pinned: teroscan v1.10.3 agreed with Go's RE2 semantics on every probe string.
	if len(skips) != 0 {
		t.Fatalf("%d of %d probes now disagree; the runtime's regex dialect changed", len(skips), len(probes))
	}
}
