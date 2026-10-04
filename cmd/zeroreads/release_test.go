package main

import (
	"os"
	"regexp"
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

// A bug report needs the release and the drain version the rules depend on.
func TestVersionString(t *testing.T) {
	if got := versionString(); !regexp.MustCompile(`\Azeroreads dev \(drain processor v[0-9.]+, go[0-9.]+\)\z`).MatchString(got) {
		t.Fatalf("version %q", got)
	}
}
