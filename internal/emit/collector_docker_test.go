//go:build docker

package emit

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The real Collector resolves the emitted configuration with every value from the logs intact and
// no environment variable read.
func TestCollectorResolvesValuesLiterally(t *testing.T) {
	svc := "svc${env:SIEVELOG_TEST_SECRET}$${SIEVELOG_TEST_SECRET}$HOME"
	rules := []Rule{{ID: "r-dollar", ScopeAttr: "service.name", ScopeValue: svc, Language: `\Acost ` + regexp.QuoteMeta("${SIEVELOG_TEST_SECRET}") + `\z`, Action: "drop"}}
	cfg, err := Collector([][]byte{[]byte(userConfig)}, Target{Pipeline: "logs", After: "transform/prep", MeasureExporters: []string{"file/metrics"}}, rules, Enforce)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "c.yaml"), cfg, 0o644)
	out, err := exec.Command("docker", "run", "--rm", "-e", "SIEVELOG_TEST_SECRET=leaked", "-v", dir+":/w",
		"otel/opentelemetry-collector-contrib:0.161.0", "print-config", "--mode", "unredacted", "--config", "/w/c.yaml").CombinedOutput()
	if err != nil {
		t.Fatalf("print-config: %v\n%s", err, out)
	}
	resolved := string(out)
	if strings.Contains(resolved, "leaked") {
		t.Fatalf("the Collector expanded an environment variable in the emitted rules:\n%s", resolved)
	}
	for _, want := range []string{`resource.attributes["service.name"] == "` + svc + `"`, `\\$\\{SIEVELOG_TEST_SECRET\\}`} {
		if !strings.Contains(resolved, want) {
			t.Fatalf("resolved configuration lacks %s:\n%s", want, resolved)
		}
	}
}
