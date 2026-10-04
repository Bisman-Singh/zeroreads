package app

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every complete zeroreads.yaml example in the documentation loads: an example that the validation
// refuses would teach a configuration that does not work.
func TestDocumentedConfigsLoad(t *testing.T) {
	block := regexp.MustCompile("(?s)```yaml\n(.*?)```")
	files, _ := filepath.Glob("../../docs/*.md")
	files = append(files, "../../README.md")
	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range block.FindAllStringSubmatch(string(b), -1) {
			if !strings.HasPrefix(m[1], "loki:") {
				continue // a fragment, or another tool's configuration
			}
			if _, err := LoadConfig(write(t, m[1])); err != nil {
				t.Errorf("%s: example does not load: %v\n%s", f, err, m[1])
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no complete example found")
	}
	t.Logf("%d documented configurations load", checked)
}
