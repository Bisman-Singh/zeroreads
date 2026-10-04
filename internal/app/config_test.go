package app

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func write(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "zeroreads.yaml")
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
		// Found by the v1 audit: "%dd" accepted a prefix, so 7d12h read as 7 days and 5dxyz passed.
		{"days and hours", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\nevidence: {window: 7d12h}\n", "duration"},
		{"days trailing text", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\nevidence: {window: 5dxyz}\n", "duration"},
		{"too many days", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\nevidence: {window: 200000d}\n", "duration"},
		{"days over ten years", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\nevidence: {window: 3651d}\n", "at most"},
		// URLs are printed in reports and verify output, so credentials never go in them.
		{"credentials in loki url", "loki: {url: 'https://u:p@l'}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", "holds credentials"},
		{"credentials in grafana url", "loki: {url: http://l}\nevidence: {grafana: [{url: 'http://admin:pw@g', datasources: [l]}]}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", "holds credentials"},
		{"credentials in opensearch url", "loki: {url: http://l}\nevidence: {opensearch: [{name: os, url: 'https://a:b@o', indices: [a]}]}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", "holds credentials"},
		{"credentials in query log url", "loki: {url: http://l}\nevidence: {query_log: {url: 'http://a:b@m'}}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", "holds credentials"},
		{"url without scheme", "loki: {url: l:3100}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", "http or https"},
		{"url with query", "loki: {url: 'http://l?x=1'}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", "query"},
		{"url with path prefix", "loki: {url: http://gateway/loki}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", ""},
		// Values written into LogQL, VRL, Fluent Bit and Lua as they are.
		{"loki label", "loki: {url: http://l}\nscope: {loki_label: 'a\"}'}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", "label name"},
		{"dotted structured field", "loki: {url: http://l}\nscope: {structured: {orders: a.b}}\ncollector: {config_files: [c.yaml], pipeline: logs}\n", "plain field name"},
		{"vector path", "loki: {url: http://l}\nruntime: vector\nvector: {config_files: [v.yaml], after: prep, scope_path: '.service ${X}', text_path: .message, measure_sink: {type: blackhole}}\n", "VRL path"},
		{"vector quoted path", "loki: {url: http://l}\nruntime: vector\nvector: {config_files: [v.yaml], after: prep, scope_path: '.\"k8s.pod\"', text_path: .message, measure_sink: {type: blackhole}}\n", ""},
		{"fluent bit key", "loki: {url: http://l}\nruntime: fluentbit\nfluentbit: {config_files: [f.yaml], match: kube.*, scope_key: service, text_key: [\"lo'g\"], metrics_tag: m}\n", "record key"},
		{"fluent bit accessor", "loki: {url: http://l}\nruntime: fluentbit\nfluentbit: {config_files: [f.yaml], match: kube.*, scope_key: \"$kubernetes['container_name']\", text_key: [log], metrics_tag: m}\n", ""},
		// Prices are the operator's own: no vendor table, no negative or unprintable values.
		{"own prices", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\npricing: {per_gb: 0.67, per_million_lines: 1.7, currency: INR}\n", ""},
		{"negative price", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\npricing: {per_gb: -1}\n", "pricing.per_gb"},
		{"infinite price", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\npricing: {per_million_lines: .inf}\n", "pricing.per_million_lines"},
		{"bad currency", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\npricing: {per_gb: 1, currency: rupees}\n", "currency"},
		{"no built-in price lists", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\npricing: {backend: some-service}\n", "backend"},
		{"archive needs a destination", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\npolicy: {actions: [archive, aggregate]}\n", "collector.archive_exporters"},
		{"archive to its own exporter", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs, archive_exporters: [file/archive]}\npolicy: {actions: [archive, aggregate]}\n", ""},
		{"archive into the analysed loki", "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs, archive_exporters: [otlp_http/loki], sinks: {otlp_http/loki: {loki: true}}}\npolicy: {actions: [archive]}\n", "removes nothing"},
		{"vector archive needs a sink", "loki: {url: http://l}\nruntime: vector\nvector: {config_files: [v.yaml], after: a, scope_path: .s, text_path: .m, measure_sink: {type: blackhole}}\npolicy: {actions: [archive]}\n", "vector.archive_sinks"},
		{"fluent bit archive needs an output", "loki: {url: http://l}\nruntime: fluentbit\nfluentbit: {config_files: [f.yaml], match: kube.*, scope_key: service, text_key: [log], metrics_tag: m}\npolicy: {actions: [archive]}\n", "fluentbit.archive_outputs"},
		{"fluent bit bad accessor", "loki: {url: http://l}\nruntime: fluentbit\nfluentbit: {config_files: [f.yaml], match: kube.*, scope_key: \"${HOME}\", text_key: [log], metrics_tag: m}\n", "scope_key"},
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

// A setting that names an empty environment variable fails where the client is built, and the query
// log gets loki's credentials only when it is that same Loki.
func TestCredentials(t *testing.T) {
	t.Setenv("ZEROREADS_TEST_PW", "pw")
	t.Setenv("ZEROREADS_TEST_EMPTY", "")
	c := &Config{Loki: LokiConfig{URL: "http://l", Username: "u", PasswordEnv: "ZEROREADS_TEST_PW", OrgID: "t1"},
		Evidence: EvidenceConfig{QueryLog: QueryLogConfig{URL: "http://l/"}}}
	lc, err := c.lokiClient()
	if err != nil || lc.Username != "u" || lc.Password != "pw" || lc.OrgID != "t1" {
		t.Fatalf("%v %+v", err, lc)
	}
	ql, err := c.queryLogClient()
	if err != nil || ql.Username != "u" || ql.Password != "pw" || ql.OrgID != "t1" {
		t.Fatalf("same Loki: %v %+v", err, ql)
	}
	c.Evidence.QueryLog.OrgID = "meta"
	if ql, _ = c.queryLogClient(); ql.OrgID != "meta" || ql.Password != "pw" {
		t.Fatalf("tenant override: %+v", ql)
	}
	c.Evidence.QueryLog = QueryLogConfig{URL: "http://other"}
	if ql, _ = c.queryLogClient(); ql.Username != "" || ql.Password != "" || ql.OrgID != "" {
		t.Fatalf("another Loki received loki's credentials: %+v", ql)
	}
	c.Loki.BearerTokenEnv = "ZEROREADS_TEST_EMPTY"
	if _, err := c.lokiClient(); err == nil || !strings.Contains(err.Error(), "ZEROREADS_TEST_EMPTY") {
		t.Fatalf("empty token: %v", err)
	}
	if _, err := (GrafanaConfig{URL: "http://g", TokenEnv: "ZEROREADS_TEST_UNSET"}).client(); err == nil {
		t.Fatal("unset Grafana token accepted")
	}
	if _, err := (OpenSearchConfig{Name: "os", URL: "https://o", PasswordEnv: "ZEROREADS_TEST_UNSET"}).client(); err == nil {
		t.Fatal("unset OpenSearch password accepted")
	}
}

func TestScopeSeverityKeysKeepDefaults(t *testing.T) {
	cfg, err := LoadConfig(write(t, "loki: {url: http://l}\nscope: {severity_keys: []}\ncollector: {config_files: [c.yaml], pipeline: logs}\n"))
	if err != nil || !slices.Contains(cfg.Scope.SeverityKeys, "level") || !slices.Contains(cfg.Scope.SeverityKeys, "detected_level") {
		t.Fatalf("%v %v", err, cfg.Scope.SeverityKeys)
	}
	cfg, err = LoadConfig(write(t, "loki: {url: http://l}\nscope: {severity_keys: [sev]}\ncollector: {config_files: [c.yaml], pipeline: logs}\n"))
	if err != nil || !slices.Contains(cfg.Scope.SeverityKeys, "sev") || !slices.Contains(cfg.Scope.SeverityKeys, "level") {
		t.Fatalf("%v %v", err, cfg.Scope.SeverityKeys)
	}
}

func TestPricingDefaultsToVolumeOnly(t *testing.T) {
	cfg, err := LoadConfig(write(t, "loki: {url: http://l}\ncollector: {config_files: [c.yaml], pipeline: logs}\n"))
	if err != nil || cfg.Pricing.PerGB != 0 || cfg.Pricing.PerMillionLines != 0 || cfg.Pricing.Currency != "USD" {
		t.Fatalf("%v %+v", err, cfg.Pricing)
	}
}
