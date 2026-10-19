package main

import (
	"os"
	"regexp"
	"runtime/debug"
	"testing"
)

// The GitHub Action and the Helm chart must run the same released version.
func TestActionAndChartShareTheReleasedVersion(t *testing.T) {
	action, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	chart, err := os.ReadFile("../../charts/zeroreads/Chart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	a := regexp.MustCompile(`image: docker://ghcr\.io/bisman-singh/zeroreads:(\S+)`).FindSubmatch(action)
	c := regexp.MustCompile(`appVersion: "?([^"\s]+)"?`).FindSubmatch(chart)
	if a == nil || c == nil || string(a[1]) != string(c[1]) {
		t.Fatalf("action image %q, chart appVersion %q", a, c)
	}
}

// A binary from `go install ...@vX` names its release from the module version Go recorded, and a build
// in a git checkout the pseudo-version Go records for it; a release build's own version always wins,
// and without a recorded version it stays "dev".
func TestReleaseVersion(t *testing.T) {
	for _, c := range []struct {
		set, module string
		ok          bool
		want        string
	}{
		{"0.1.1", "v9.9.9", true, "0.1.1"},
		{"dev", "v0.1.1", true, "0.1.1"},
		{"dev", "v0.1.2-0.20261019120000-abcdef123456", true, "0.1.2-0.20261019120000-abcdef123456"},
		{"dev", "v0.1.2-0.20261019120000-abcdef123456+dirty", true, "0.1.2-0.20261019120000-abcdef123456+dirty"},
		{"dev", "(devel)", true, "dev"},
		{"dev", "", true, "dev"},
		{"dev", "", false, "dev"},
	} {
		var info *debug.BuildInfo
		if c.ok {
			info = &debug.BuildInfo{Main: debug.Module{Version: c.module}}
		}
		if got := releaseVersion(c.set, info, c.ok); got != c.want {
			t.Errorf("releaseVersion(%q, module %q, ok %v) = %q, want %q", c.set, c.module, c.ok, got, c.want)
		}
	}
}

// A bug report needs the release and the drain version the rules depend on.
func TestVersionString(t *testing.T) {
	if got := versionString(); !regexp.MustCompile(`\Azeroreads dev \(drain processor v[0-9.]+, go[0-9.]+\)\z`).MatchString(got) {
		t.Fatalf("version %q", got)
	}
}
