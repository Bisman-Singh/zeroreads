package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sievelog.yaml")
	os.WriteFile(p, []byte(s), 0o644)
	return p
}

func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name, yaml, err string
	}{
		{"minimal collector", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", ""},
		{"no loki", "collector: {config_files: [c.yaml], pipeline: logs}\n", "loki.url"},
		{"unknown key", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\nbogus: 1\n", "bogus"},
		{"sink both", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs, sinks: {x: {loki: true, exempt: y}}}\n", "exactly one"},
		{"sink neither", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs, sinks: {x: {}}}\n", "exactly one"},
		{"vector ok", "loki: {url: http://l}\nruntime: vector\nvector: {config_files: [v.yaml], after: prep, scope_path: .service, text_path: .message, measure_sink: {type: blackhole}}\n", ""},
		{"vector missing", "loki: {url: http://l}\nruntime: vector\nvector: {config_files: [v.yaml]}\n", "required"},
		{"vector structured needs path", "loki: {url: http://l}\nruntime: vector\nscope: {structured: {orders: msg}}\nvector: {config_files: [v.yaml], after: prep, scope_path: .service, text_path: .message, measure_sink: {type: blackhole}}\n", "field_paths.orders"},
		{"bad runtime", "loki: {url: http://l}\nruntime: fluent\n", "runtime"},
		{"fluentbit ok", "loki: {url: http://l}\nruntime: fluentbit\nfluentbit: {config_files: [f.yaml], match: kube.*, scope_key: service, text_key: [log], metrics_tag: m}\n", ""},
		{"fluentbit missing", "loki: {url: http://l}\nruntime: fluentbit\nfluentbit: {config_files: [f.yaml]}\n", "required"},
		{"bad sample", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\npolicy: {sample_percent: 100}\n", "sample_percent"},
		{"days duration", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\nevidence: {window: 30d}\n", ""},
	}
	for _, c := range cases {
		cfg, err := LoadConfig(write(t, c.yaml))
		switch {
		case c.err == "" && err != nil:
			t.Fatalf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Fatalf("%s: got %v, want error containing %q", c.name, err, c.err)
		}
		if c.name == "days duration" && cfg.Evidence.Window.Hours() != 720 {
			t.Fatalf("30d parsed as %v", cfg.Evidence.Window)
		}
	}
}
