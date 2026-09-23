// Package app wires the evidence sources, the analyzer and the emitters into the commands the CLI
// runs.
package app

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"go.yaml.in/yaml/v3"
)

// Config is sievelog.yaml.
type Config struct {
	Loki      LokiConfig      `yaml:"loki"`
	Scope     ScopeConfig     `yaml:"scope"`
	Discovery DiscoveryConfig `yaml:"discovery"`
	Drain     DrainConfig     `yaml:"drain"`
	Evidence  EvidenceConfig  `yaml:"evidence"`
	// Runtime is the pipeline the rules are enforced in: collector (OpenTelemetry Collector) or vector.
	Runtime   string          `yaml:"runtime"`
	Collector CollectorConfig `yaml:"collector"`
	Vector    VectorConfig    `yaml:"vector"`
	FluentBit FluentBitConfig `yaml:"fluentbit"`
	Policy    PolicyConfig    `yaml:"policy"`
	Pricing   PricingConfig   `yaml:"pricing"`
}

// LokiConfig is the Loki that stores the logs being analysed.
type LokiConfig struct {
	URL            string `yaml:"url"`
	OrgID          string `yaml:"org_id"`
	Username       string `yaml:"username"`
	PasswordEnv    string `yaml:"password_env"`
	BearerTokenEnv string `yaml:"bearer_token_env"`
}

// ScopeConfig says how a rule's scope is named in the pipeline and in Loki.
type ScopeConfig struct {
	OTelAttribute string   `yaml:"otel_attribute"` // e.g. service.name
	LokiLabel     string   `yaml:"loki_label"`     // e.g. service_name
	Services      []string `yaml:"services"`       // empty: every value of the label
	// Structured maps a service to the body field its records are templated on. Records of these
	// services reach the enforcement point as map bodies.
	Structured map[string]string `yaml:"structured"`
}

// DiscoveryConfig bounds template discovery and volume measurement.
type DiscoveryConfig struct {
	Window                Duration `yaml:"window"`
	Slices                int      `yaml:"slices"`
	SampleLinesPerService int      `yaml:"sample_lines_per_service"`
	MinSamples            int      `yaml:"min_samples"`
}

// DrainConfig configures the embedded drain processor.
type DrainConfig struct {
	MaskingRules []struct {
		Name    string `yaml:"name"`
		Pattern string `yaml:"pattern"`
	} `yaml:"masking_rules"`
	SeedTemplates []string `yaml:"seed_templates"`
}

// EvidenceConfig lists every usage source.
type EvidenceConfig struct {
	Window   Duration        `yaml:"window"`
	QueryLog QueryLogConfig  `yaml:"query_log"`
	Ruler    bool            `yaml:"ruler"`
	Grafana  []GrafanaConfig `yaml:"grafana"`
	// OpenSearch clusters that receive the analysed logs, referenced by sinks.
	OpenSearch []OpenSearchConfig `yaml:"opensearch"`
}

// QueryLogConfig is where Loki's own logs (with its query log) can be read.
type QueryLogConfig struct {
	Enabled   bool   `yaml:"enabled"`
	URL       string `yaml:"url"` // default: loki.url
	Selector  string `yaml:"selector"`
	ProveLive bool   `yaml:"prove_live"`
}

// GrafanaConfig is one Grafana.
type GrafanaConfig struct {
	URL         string   `yaml:"url"`
	Username    string   `yaml:"username"`
	PasswordEnv string   `yaml:"password_env"`
	TokenEnv    string   `yaml:"token_env"`
	Datasources []string `yaml:"datasources"` // Loki datasource UIDs that point at loki.url
}

// CollectorConfig is the collector the rules are enforced in.
type CollectorConfig struct {
	ConfigFiles        []string          `yaml:"config_files"`
	Pipeline           string            `yaml:"pipeline"`
	After              string            `yaml:"after"`
	MeasureExporters   []string          `yaml:"measure_exporters"`
	AggregateExporters []string          `yaml:"aggregate_exporters"`
	DedupeInterval     string            `yaml:"dedupe_interval"`
	Sinks              map[string]Sink   `yaml:"sinks"`
	Derived            map[string]string `yaml:"derived_exempt"` // connector -> reason it may change
}

// VectorConfig is the Vector instance the rules are enforced in.
type VectorConfig struct {
	ConfigFiles []string          `yaml:"config_files"`
	After       string            `yaml:"after"`
	ScopePath   string            `yaml:"scope_path"` // VRL path of the scope value, e.g. .service
	TextPath    string            `yaml:"text_path"`  // VRL path of the plain log text, e.g. .message
	FieldPaths  map[string]string `yaml:"field_paths"`
	GroupBy     []string          `yaml:"dedupe_group_by"`
	DedupeMS    int               `yaml:"dedupe_ms"`
	MeasureSink map[string]any    `yaml:"measure_sink"`
	Sinks       map[string]Sink   `yaml:"sinks"`
	Derived     map[string]string `yaml:"derived_exempt"`
}

// FluentBitConfig is the Fluent Bit instance the rules are enforced in (YAML configuration).
type FluentBitConfig struct {
	ConfigFiles []string            `yaml:"config_files"`
	Match       string              `yaml:"match"`
	After       string              `yaml:"after"`
	ScopeKey    string              `yaml:"scope_key"`
	TextKey     []string            `yaml:"text_key"`
	FieldKeys   map[string][]string `yaml:"field_keys"`
	MetricsTag  string              `yaml:"metrics_tag"`
	Sinks       map[string]Sink     `yaml:"sinks"`
	Derived     map[string]string   `yaml:"derived_exempt"`
}

// Sink says what an exporter downstream of the enforcement point is.
type Sink struct {
	Loki       bool   `yaml:"loki"`       // the analysed Loki: its usage is covered by the evidence sources
	OpenSearch string `yaml:"opensearch"` // name of the evidence.opensearch cluster this sink writes to
	Exempt     string `yaml:"exempt"`     // reason the operator accepts removal there without evidence
}

// check requires exactly one kind and a known OpenSearch cluster.
func (s Sink) check(path string, clusters map[string]bool) error {
	n := 0
	for _, set := range []bool{s.Loki, s.OpenSearch != "", s.Exempt != ""} {
		if set {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("%s: set exactly one of loki: true, opensearch: <name> or exempt: <reason>", path)
	}
	if s.OpenSearch != "" && !clusters[s.OpenSearch] {
		return fmt.Errorf("%s: opensearch %q is not in evidence.opensearch", path, s.OpenSearch)
	}
	return nil
}

// PolicyConfig maps to analyze.Policy.
type PolicyConfig struct {
	Actions       []string `yaml:"actions"`
	SamplePercent int      `yaml:"sample_percent"`
	Acknowledge   []string `yaml:"acknowledge"`
	Exempt        []string `yaml:"exempt"`
	ErrorPattern  string   `yaml:"error_pattern"`
	MinDailyBytes float64  `yaml:"min_daily_bytes"`
}

// PricingConfig selects the price table.
type PricingConfig struct {
	Backend string `yaml:"backend"`
}

// Duration parses Go and day-suffixed durations ("720h", "30d").
type Duration struct{ time.Duration }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	if len(s) > 1 && s[len(s)-1] == 'd' {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil {
			d.Duration = time.Duration(days) * 24 * time.Hour
			return nil
		}
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("duration %q: %w", s, err)
	}
	d.Duration = v
	return nil
}

// LoadConfig reads and validates sievelog.yaml.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) defaults() {
	if c.Scope.OTelAttribute == "" {
		c.Scope.OTelAttribute = "service.name"
	}
	if c.Scope.LokiLabel == "" {
		c.Scope.LokiLabel = "service_name"
	}
	if c.Discovery.Window.Duration == 0 {
		c.Discovery.Window.Duration = 24 * time.Hour
	}
	if c.Discovery.Slices == 0 {
		c.Discovery.Slices = 48
	}
	if c.Discovery.SampleLinesPerService == 0 {
		c.Discovery.SampleLinesPerService = 20000
	}
	if c.Discovery.MinSamples == 0 {
		c.Discovery.MinSamples = 20
	}
	if c.Evidence.Window.Duration == 0 {
		c.Evidence.Window.Duration = 30 * 24 * time.Hour
	}
	for i := range c.Evidence.OpenSearch {
		o := &c.Evidence.OpenSearch[i]
		if o.AuditIndex == "" {
			o.AuditIndex = "security-auditlog-*"
		}
		if o.DashboardsIndex == "" {
			o.DashboardsIndex = ".kibana*"
		}
	}
	if c.Evidence.QueryLog.URL == "" {
		c.Evidence.QueryLog.URL = c.Loki.URL
	}
	if c.Runtime == "" {
		c.Runtime = "collector"
	}
	if c.Collector.DedupeInterval == "" {
		c.Collector.DedupeInterval = "10s"
	}
	if len(c.Policy.Actions) == 0 {
		c.Policy.Actions = []string{"aggregate", "dedupe", "sample"}
	}
	if c.Policy.SamplePercent == 0 {
		c.Policy.SamplePercent = 10
	}
}

func (c *Config) validate() error {
	if c.Loki.URL == "" {
		return fmt.Errorf("loki.url is required")
	}
	if c.Evidence.QueryLog.Enabled && c.Evidence.QueryLog.Selector == "" {
		return fmt.Errorf("evidence.query_log.selector is required when the query log is enabled")
	}
	clusters := map[string]bool{}
	for i, o := range c.Evidence.OpenSearch {
		switch {
		case o.Name == "" || o.URL == "":
			return fmt.Errorf("evidence.opensearch[%d]: name and url are required", i)
		case clusters[o.Name]:
			return fmt.Errorf("evidence.opensearch[%d]: duplicate name %q", i, o.Name)
		case len(o.Indices) == 0:
			return fmt.Errorf("evidence.opensearch.%s: indices is required", o.Name)
		}
		clusters[o.Name] = true
	}
	switch c.Runtime {
	case "collector":
		if len(c.Collector.ConfigFiles) == 0 || c.Collector.Pipeline == "" {
			return fmt.Errorf("collector.config_files and collector.pipeline are required")
		}
		for id, s := range c.Collector.Sinks {
			if err := s.check("collector.sinks."+id, clusters); err != nil {
				return err
			}
		}
	case "vector":
		v := c.Vector
		if len(v.ConfigFiles) == 0 || v.After == "" || v.ScopePath == "" || v.TextPath == "" || v.MeasureSink == nil {
			return fmt.Errorf("vector.config_files, after, scope_path, text_path and measure_sink are required")
		}
		for id, s := range v.Sinks {
			if err := s.check("vector.sinks."+id, clusters); err != nil {
				return err
			}
		}
		for svc := range c.Scope.Structured {
			if v.FieldPaths[svc] == "" {
				return fmt.Errorf("vector.field_paths.%s is required for a structured service", svc)
			}
		}
	case "fluentbit":
		f := c.FluentBit
		if len(f.ConfigFiles) == 0 || f.Match == "" || f.ScopeKey == "" || len(f.TextKey) == 0 || f.MetricsTag == "" {
			return fmt.Errorf("fluentbit.config_files, match, scope_key, text_key and metrics_tag are required")
		}
		for id, s := range f.Sinks {
			if err := s.check("fluentbit.sinks."+id, clusters); err != nil {
				return err
			}
		}
		for svc := range c.Scope.Structured {
			if len(f.FieldKeys[svc]) == 0 {
				return fmt.Errorf("fluentbit.field_keys.%s is required for a structured service", svc)
			}
		}
	default:
		return fmt.Errorf("runtime must be collector, vector or fluentbit, got %q", c.Runtime)
	}
	if c.Policy.SamplePercent < 1 || c.Policy.SamplePercent > 99 {
		return fmt.Errorf("policy.sample_percent must be 1..99")
	}
	return nil
}
