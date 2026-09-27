// Package app wires the evidence sources, the analyzer and the emitters into the commands the CLI
// runs.
package app

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/source/grafana"

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
	// SeverityKeys are the fields that carry a line's level in Loki (labels, structured metadata) and
	// in structured records. Sampled lines at warning or above there block their template's rule.
	SeverityKeys []string `yaml:"severity_keys"`
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
	// Credentials for url. When url is loki.url, loki's credentials are the default; another Loki
	// never receives them.
	OrgID          string `yaml:"org_id"`
	Username       string `yaml:"username"`
	PasswordEnv    string `yaml:"password_env"`
	BearerTokenEnv string `yaml:"bearer_token_env"`
}

// GrafanaConfig is one Grafana.
type GrafanaConfig struct {
	URL         string   `yaml:"url"`
	Username    string   `yaml:"username"`
	PasswordEnv string   `yaml:"password_env"`
	TokenEnv    string   `yaml:"token_env"`
	Datasources []string `yaml:"datasources"` // Loki datasource UIDs that point at loki.url
	// OtherDatasources are Loki datasource UIDs that point at a different Loki: their queries cannot
	// read the analysed lines. A Loki datasource in neither list counts as the analysed one and is
	// reported as a gap.
	OtherDatasources []string `yaml:"other_datasources"`
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
	// SeverityKeys are the log attributes (and structured body fields) that carry a level, in addition
	// to the defaults. A record at warning or above is never removed, whatever the rules say.
	SeverityKeys []string `yaml:"severity_keys"`
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
	// SeverityPaths are VRL paths of level fields, in addition to the defaults.
	SeverityPaths []string `yaml:"severity_paths"`
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
	// SeverityKeys are record paths of level fields, in addition to the defaults.
	SeverityKeys [][]string `yaml:"severity_keys"`
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
	// ExperimentalRollup must be true for rollup to be allowed in actions: it rewrites dashboards and
	// alerts, and is newer and less proven in the field than the other actions.
	ExperimentalRollup bool `yaml:"experimental_rollup"`
}

// PricingConfig selects the price table.
type PricingConfig struct {
	Backend string `yaml:"backend"`
}

// Duration parses Go and day-suffixed durations ("720h", "30d").
type Duration struct{ time.Duration }

// days matches a whole number of days, at most ten years: the longest window that makes sense.
var days = regexp.MustCompile(`\A([0-9]{1,4})d\z`)

const maxDays = 3650

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	if m := days.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1]) // at most four digits
		if n > maxDays {
			return fmt.Errorf("duration %q: at most %dd", s, maxDays)
		}
		d.Duration = time.Duration(n) * 24 * time.Hour
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("duration %q: a Go duration such as 720h, or a number of days such as 30d", s)
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
	// Configured level fields add to the defaults: an empty or partial list must never hide a level.
	for _, k := range []string{"level", "severity", "severity_text", "detected_level", "lvl", "loglevel", "log.level"} {
		if !slices.Contains(c.Scope.SeverityKeys, k) {
			c.Scope.SeverityKeys = append(c.Scope.SeverityKeys, k)
		}
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

// labelName matches a Loki label name, which sievelog writes into LogQL unquoted.
var labelName = regexp.MustCompile(`\A[a-zA-Z_][a-zA-Z0-9_]*\z`)

// fieldName matches a structured field name. Loki's json parser reads a dotted name as a path into
// nested objects while the pipelines read it as one key, so only plain names are allowed.
var fieldName = regexp.MustCompile(`\A[A-Za-z_][A-Za-z0-9_]*\z`)

// vrlPath matches a VRL path of plain or quoted segments. Paths are written into VRL programs as
// they are, so nothing that VRL or Vector's configuration would interpret may appear in them.
var vrlPath = regexp.MustCompile(`\A(?:\.(?:[A-Za-z0-9_@]+|"[^"\\${}]+"))+\z`)

// recordKey matches one Fluent Bit record key, and recordAccessor a key or a record accessor
// ($a['b']). Both are written into Fluent Bit configuration and Lua as they are.
var (
	recordKey      = regexp.MustCompile(`\A[A-Za-z0-9_.@/-]+\z`)
	recordAccessor = regexp.MustCompile(`\A(?:[A-Za-z0-9_.@/-]+|\$[A-Za-z0-9_.@/-]+(?:\['[A-Za-z0-9_.@/-]+'\])*)\z`)
	tagPattern     = regexp.MustCompile(`\A[A-Za-z0-9_.*/-]+\z`)
)

func (c *Config) validate() error {
	for _, check := range []func() error{c.validateSources, c.validateScope, c.validateBounds, c.validateRuntime, c.validatePolicy} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// checkURL requires an http or https URL with a host and nothing a base URL cannot carry. URLs are
// printed in reports, gaps and verify output, so credentials in one are refused: they belong in
// username and the *_env settings.
func checkURL(field, raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return fmt.Errorf("%s is not a URL", field) // the parse error would repeat the URL
	case u.User != nil:
		return fmt.Errorf("%s holds credentials; use username and password_env or the token setting instead", field)
	case (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		return fmt.Errorf("%s must be an http or https URL with a host", field)
	case u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("%s must not have a query or fragment", field)
	}
	return nil
}

func (c *Config) validateSources() error {
	if c.Loki.URL == "" {
		return fmt.Errorf("loki.url is required")
	}
	if err := checkURL("loki.url", c.Loki.URL); err != nil {
		return err
	}
	ql := c.Evidence.QueryLog
	if err := checkURL("evidence.query_log.url", ql.URL); err != nil {
		return err
	}
	if ql.Enabled && ql.Selector == "" {
		return fmt.Errorf("evidence.query_log.selector is required when the query log is enabled")
	}
	for i, g := range c.Evidence.Grafana {
		if g.URL == "" || len(g.Datasources) == 0 {
			return fmt.Errorf("evidence.grafana[%d]: url and datasources (the Loki datasource UIDs of loki.url) are required", i)
		}
		if err := checkURL(fmt.Sprintf("evidence.grafana[%d].url", i), g.URL); err != nil {
			return err
		}
	}
	names := map[string]bool{}
	for i, o := range c.Evidence.OpenSearch {
		switch {
		case o.Name == "" || o.URL == "":
			return fmt.Errorf("evidence.opensearch[%d]: name and url are required", i)
		case names[o.Name]:
			return fmt.Errorf("evidence.opensearch[%d]: duplicate name %q", i, o.Name)
		case len(o.Indices) == 0:
			return fmt.Errorf("evidence.opensearch.%s: indices is required", o.Name)
		}
		if err := checkURL("evidence.opensearch."+o.Name+".url", o.URL); err != nil {
			return err
		}
		names[o.Name] = true
	}
	return nil
}

func (c *Config) validateScope() error {
	if !labelName.MatchString(c.Scope.LokiLabel) {
		return fmt.Errorf("scope.loki_label %q is not a Loki label name", c.Scope.LokiLabel)
	}
	for svc, f := range c.Scope.Structured {
		if !fieldName.MatchString(f) {
			return fmt.Errorf("scope.structured.%s: %q is not a plain field name (letters, digits and _)", svc, f)
		}
	}
	return nil
}

func (c *Config) validateBounds() error {
	for name, v := range map[string]int64{
		"discovery.window": int64(c.Discovery.Window.Duration), "discovery.slices": int64(c.Discovery.Slices),
		"discovery.sample_lines_per_service": int64(c.Discovery.SampleLinesPerService), "discovery.min_samples": int64(c.Discovery.MinSamples),
		"evidence.window": int64(c.Evidence.Window.Duration), "vector.dedupe_ms": int64(c.Vector.DedupeMS),
	} {
		if v < 0 || (v == 0 && name != "vector.dedupe_ms") {
			return fmt.Errorf("%s must be positive", name)
		}
	}
	if c.Policy.MinDailyBytes < 0 {
		return fmt.Errorf("policy.min_daily_bytes must not be negative")
	}
	if c.Discovery.Slices > 10000 {
		return fmt.Errorf("discovery.slices must be at most 10000")
	}
	if d, err := time.ParseDuration(c.Collector.DedupeInterval); err != nil || d <= 0 {
		return fmt.Errorf("collector.dedupe_interval %q must be a positive duration", c.Collector.DedupeInterval)
	}
	return nil
}

func (c *Config) validateRuntime() error {
	clusters := map[string]bool{}
	for _, o := range c.Evidence.OpenSearch {
		clusters[o.Name] = true
	}
	switch c.Runtime {
	case "collector":
		return c.validateCollector(clusters)
	case "vector":
		return c.validateVector(clusters)
	case "fluentbit":
		return c.validateFluentBit(clusters)
	}
	return fmt.Errorf("runtime must be collector, vector or fluentbit, got %q", c.Runtime)
}

func checkSinks(prefix string, sinks map[string]Sink, clusters map[string]bool) error {
	for id, s := range sinks {
		if err := s.check(prefix+"."+id, clusters); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateCollector(clusters map[string]bool) error {
	if len(c.Collector.ConfigFiles) == 0 || c.Collector.Pipeline == "" {
		return fmt.Errorf("collector.config_files and collector.pipeline are required")
	}
	return checkSinks("collector.sinks", c.Collector.Sinks, clusters)
}

func (c *Config) validateVector(clusters map[string]bool) error {
	v := c.Vector
	if len(v.ConfigFiles) == 0 || v.After == "" || v.ScopePath == "" || v.TextPath == "" || v.MeasureSink == nil {
		return fmt.Errorf("vector.config_files, after, scope_path, text_path and measure_sink are required")
	}
	paths := map[string]string{"vector.scope_path": v.ScopePath, "vector.text_path": v.TextPath}
	for svc, p := range v.FieldPaths {
		paths["vector.field_paths."+svc] = p
	}
	for i, p := range v.SeverityPaths {
		paths[fmt.Sprintf("vector.severity_paths[%d]", i)] = p
	}
	for field, p := range paths {
		if !vrlPath.MatchString(p) {
			return fmt.Errorf("%s: %q is not a VRL path such as .service or .\"k8s.pod\"", field, p)
		}
	}
	for i, g := range v.GroupBy {
		if !recordKey.MatchString(g) {
			return fmt.Errorf("vector.dedupe_group_by[%d]: %q is not a field name", i, g)
		}
	}
	for svc := range c.Scope.Structured {
		if v.FieldPaths[svc] == "" {
			return fmt.Errorf("vector.field_paths.%s is required for a structured service", svc)
		}
	}
	return checkSinks("vector.sinks", v.Sinks, clusters)
}

func (c *Config) validateFluentBit(clusters map[string]bool) error {
	f := c.FluentBit
	if len(f.ConfigFiles) == 0 || f.Match == "" || f.ScopeKey == "" || len(f.TextKey) == 0 || f.MetricsTag == "" {
		return fmt.Errorf("fluentbit.config_files, match, scope_key, text_key and metrics_tag are required")
	}
	if !recordAccessor.MatchString(f.ScopeKey) {
		return fmt.Errorf("fluentbit.scope_key: %q is not a record key or accessor such as $kubernetes['container_name']", f.ScopeKey)
	}
	for field, t := range map[string]string{"fluentbit.match": f.Match, "fluentbit.metrics_tag": f.MetricsTag} {
		if !tagPattern.MatchString(t) {
			return fmt.Errorf("%s: %q is not a tag pattern", field, t)
		}
	}
	keys := map[string][]string{"fluentbit.text_key": f.TextKey}
	for svc, k := range f.FieldKeys {
		keys["fluentbit.field_keys."+svc] = k
	}
	for i, k := range f.SeverityKeys {
		keys[fmt.Sprintf("fluentbit.severity_keys[%d]", i)] = k
	}
	for field, path := range keys {
		for _, k := range path {
			if !recordKey.MatchString(k) {
				return fmt.Errorf("%s: %q is not a record key", field, k)
			}
		}
	}
	for svc := range c.Scope.Structured {
		if len(f.FieldKeys[svc]) == 0 {
			return fmt.Errorf("fluentbit.field_keys.%s is required for a structured service", svc)
		}
	}
	return checkSinks("fluentbit.sinks", f.Sinks, clusters)
}

func (c *Config) validatePolicy() error {
	for _, a := range c.Policy.Actions {
		if a == "rollup" && !c.Policy.ExperimentalRollup {
			return fmt.Errorf("policy.actions: rollup is experimental; set policy.experimental_rollup: true to allow it")
		}
	}
	if c.Policy.SamplePercent < 1 || c.Policy.SamplePercent > 99 {
		return fmt.Errorf("policy.sample_percent must be 1..99")
	}
	return nil
}

// client is a Grafana client with the credentials the config names.
func (g GrafanaConfig) client() (*grafana.Client, error) {
	password, err := secret("evidence.grafana.password_env", g.PasswordEnv)
	if err != nil {
		return nil, err
	}
	token, err := secret("evidence.grafana.token_env", g.TokenEnv)
	if err != nil {
		return nil, err
	}
	return &grafana.Client{Base: g.URL, Username: g.Username, Password: password, Token: token}, nil
}

// secret returns the value of the environment variable a setting names. A named variable that is
// empty is an error: sending no credentials would surface far from its cause, as a permission
// problem.
func secret(setting, env string) (string, error) {
	if env == "" {
		return "", nil
	}
	if v := os.Getenv(env); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%s names the environment variable %s, which is empty or unset", setting, env)
}
