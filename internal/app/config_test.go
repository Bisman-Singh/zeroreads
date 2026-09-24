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
		{"opensearch sink", "loki: {url: http://l}\nevidence: {opensearch: [{name: os, url: https://o, indices: [logs-*]}]}\ncollector: {config_files: [c.yaml], pipeline: logs, sinks: {x: {opensearch: os}}}\n", ""},
		{"opensearch sink unknown", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs, sinks: {x: {opensearch: os}}}\n", "not in evidence.opensearch"},
		{"opensearch sink and loki", "loki: {url: http://l}\nevidence: {opensearch: [{name: os, url: https://o, indices: [logs-*]}]}\ncollector: {config_files: [c.yaml], pipeline: logs, sinks: {x: {opensearch: os, loki: true}}}\n", "exactly one"},
		{"opensearch no indices", "loki: {url: http://l}\nevidence: {opensearch: [{name: os, url: https://o}]}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", "indices is required"},
		{"opensearch duplicate", "loki: {url: http://l}\nevidence: {opensearch: [{name: os, url: https://o, indices: [a]}, {name: os, url: https://p, indices: [a]}]}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", "duplicate"},
		{"opensearch vector sink", "loki: {url: http://l}\nruntime: vector\nevidence: {opensearch: [{name: os, url: https://o, indices: [a]}]}\nvector: {config_files: [v.yaml], after: prep, scope_path: .service, text_path: .message, measure_sink: {type: blackhole}, sinks: {s: {opensearch: nope}}}\n", "not in evidence.opensearch"},
		{"grafana without datasources", "loki: {url: http://l}\nevidence: {grafana: [{url: http://g}]}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", "datasources"},
		{"rollup gated", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\npolicy: {actions: [rollup]}\n", "experimental"},
		{"rollup enabled", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\npolicy: {actions: [rollup], experimental_rollup: true}\n", ""},
		{"negative slices", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\ndiscovery: {slices: -1}\n", "discovery.slices"},
		{"negative samples", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\ndiscovery: {min_samples: -5}\n", "discovery.min_samples"},
		{"negative window", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\ndiscovery: {window: -1h}\n", "discovery.window"},
		{"bad dedupe interval", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs, dedupe_interval: soon}\n", "dedupe_interval"},
		{"negative min bytes", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\npolicy: {min_daily_bytes: -1}\n", "min_daily_bytes"},
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
		if c.name == "opensearch sink" && (cfg.Evidence.OpenSearch[0].AuditIndex != "security-auditlog-*" || cfg.Evidence.OpenSearch[0].DashboardsIndex != ".kibana*") {
			t.Fatalf("defaults: %+v", cfg.Evidence.OpenSearch[0])
		}
		if c.name == "days duration" && cfg.Evidence.Window.Hours() != 720 {
			t.Fatalf("30d parsed as %v", cfg.Evidence.Window)
		}
	}
}
