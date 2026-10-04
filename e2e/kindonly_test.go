//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The e2e must reach nothing but its kind cluster. These cover the two ways it could reach something
// else: Helm's HELM_KUBE* overrides, and a local port that something else already holds.

func TestHelmRunsWithoutKubeOverrides(t *testing.T) {
	t.Setenv("HELM_KUBEAPISERVER", "https://127.0.0.1:1")
	t.Setenv("HELM_KUBETOKEN", "not-a-real-token")
	e := &loopEnv{t: t}
	out, code := e.run(".", "helm", "env")
	if code != 0 {
		t.Fatalf("helm env: %s", out)
	}
	if strings.Contains(out, "127.0.0.1:1") || strings.Contains(out, "not-a-real-token") {
		t.Fatalf("helm still sees the overrides:\n%s", out)
	}
}

func TestScriptsDropHelmOverrides(t *testing.T) {
	cmd := exec.Command("bash", "-c", `K=false; source lib.sh; env | grep '^HELM_KUBE' || true`)
	cmd.Env = append(os.Environ(), "HELM_KUBEAPISERVER=https://127.0.0.1:1", "HELM_KUBETOKEN=not-a-real-token")
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "" {
		t.Fatalf("lib.sh left Helm overrides in place (%v):\n%s", err, out)
	}
}

func TestForwardRefusesATakenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	taken := ln.Addr().(*net.TCPAddr).Port
	out, err := libScript(t, fmt.Sprintf(`forward zeroreads-system loki %d:3100; stop_forwards; echo started`, taken))
	if err == nil || strings.Contains(string(out), "started") || !strings.Contains(string(out), "already in use") {
		t.Fatalf("a forward on a taken port was not refused (%v):\n%s", err, out)
	}

	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	out, err = libScript(t, fmt.Sprintf(`forward zeroreads-system loki %d:3100; stop_forwards; echo started`, port))
	if err != nil || !strings.Contains(string(out), "started") {
		t.Fatalf("a forward on a free port was refused (%v):\n%s", err, out)
	}
}

// libScript runs a bash snippet after sourcing lib.sh, with a stand-in kubectl, within a deadline so a
// forward loop left running fails the test instead of hanging it.
func libScript(t *testing.T, snippet string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", "K=true; source lib.sh; "+snippet)
	cmd.WaitDelay = time.Second
	return cmd.CombinedOutput()
}
