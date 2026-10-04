//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Bisman-Singh/zeroreads/internal/app"
)

// TestZDriftReportedExactly pushes lines of an enforced rule's template that the rule does not
// cover and checks verify reports exactly them. It runs after every test that analyses the loop's
// services: the pushed lines are real lines of those services and would change any later analysis.
func TestZDriftReportedExactly(t *testing.T) {
	e := &loopEnv{t: t, work: env(t, "E2E_WORK"), loki: env(t, "LOKI_URL")}
	e.root, _ = filepath.Abs("..")
	cfgPath := filepath.Join(e.work, "zeroreads.yaml")
	outDir := filepath.Join(e.work, "loop-out")
	e.bin = filepath.Join(e.work, "zeroreads")
	rf, err := app.LoadRules(filepath.Join(outDir, "rules.json"))
	if err != nil {
		t.Fatalf("needs the rules TestFullLoop wrote: %v", err)
	}
	langs := map[string]*regexp.Regexp{}
	for _, r := range rf.Rules {
		langs[r.ID] = regexp.MustCompile(r.Language)
	}
	var sampled *app.EnforcedRule
	for i := range rf.Rules {
		if rf.Rules[i].Action == "sample" {
			sampled = &rf.Rules[i]
		}
	}
	if sampled == nil {
		t.Fatalf("needs the sample rule TestFullLoop wrote; its rules.json has %d rules", len(rf.Rules))
	}
	driftLine := strings.ReplaceAll(sampled.Template, "<*>", "zz~drift~zz")
	if langs[sampled.ID].MatchString(driftLine) || !strings.Contains(sampled.Template, "<*>") {
		t.Fatalf("drift line %q must be in template %q and outside the rule", driftLine, sampled.Template)
	}
	driftOf := func() app.RuleDrift {
		p := filepath.Join(e.work, "loop-verify-drift.json")
		out, code := e.run(e.root, e.bin, "verify", "-c", cfgPath, "-rules", filepath.Join(outDir, "rules.json"), "-json", p)
		if code != 0 && code != 3 { // readers added by earlier tests may fail it; drift is reported either way
			t.Fatalf("verify (exit %d): %s", code, out)
		}
		var vr app.VerifyResult
		b, _ := os.ReadFile(p)
		json.Unmarshal(b, &vr)
		for _, d := range vr.Drift {
			if d.RuleID == sampled.ID {
				return d
			}
		}
		t.Fatalf("no drift entry for %s: %s", sampled.ID, b)
		return app.RuleDrift{}
	}
	before := driftOf()
	const drifted = 7
	lokiPush(t, e.loki, map[string]string{"service_name": sampled.Service, "k8s_namespace_name": "drift"}, driftLine, drifted)
	var after app.RuleDrift
	for i := 0; i < 30; i++ {
		if after = driftOf(); after.OutOfRule-before.OutOfRule >= drifted {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if after.OutOfRule-before.OutOfRule != drifted || after.Status != "drifting" || after.TemplateLines-before.TemplateLines != drifted {
		t.Fatalf("drift: before %+v after %+v, want exactly %d more out-of-rule lines", before, after, drifted)
	}
	t.Logf("drift: %d pushed out-of-rule lines of %q reported exactly (examples %q)", drifted, sampled.Template, after.Examples)

}
