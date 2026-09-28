# Configuration

`sievelog.yaml` configures one analysis. Unknown keys are rejected. Credentials never go in a URL
(URLs appear in reports and verify output): name an environment variable in a `*_env` setting, and
set it; a named variable that is empty is an error. Values that sievelog writes into queries and
pipeline programs are checked: label and field names are plain names, Vector paths are VRL paths
and Fluent Bit keys are plain record keys.

```yaml
loki:
  url: http://loki:3100          # the Loki that stores the logs being analysed
  org_id: ""                     # X-Scope-OrgID for multi-tenant Loki
  username: ""                   # basic auth
  password_env: ""               # environment variable holding the password
  bearer_token_env: ""           # environment variable holding a bearer token

scope:
  otel_attribute: service.name   # resource attribute naming a rule's scope in the pipeline
  loki_label: service_name       # how Loki stores it
  services: []                   # empty: every value of the label
  structured:                    # services whose records reach the pipeline as maps,
    orders: msg                  #   and the field their templates are built from
  severity_keys: []              # where a sampled line's level is read (Loki labels and structured
                                 # metadata, and record fields), in addition to level, severity,
                                 # severity_text, detected_level, lvl, loglevel and log.level;
                                 # warning or above blocks the rule

discovery:
  window: 24h                    # sample and measure over this window
  slices: 48                     # the window is counted in this many slices first,
  sample_lines_per_service: 20000 #  then this budget is spread over them by volume
  min_samples: 20                # fewest lines a template needs before it gets a rule

drain:
  masking_rules:                 # the same masking rules as the pipeline's drain processor
    - {name: ip, pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'}
  seed_templates: []

evidence:
  window: 30d
  query_log:
    enabled: true                # requires frontend.log_queries_longer_than: -1ns in Loki
    url: ""                      # a Loki that stores Loki's own logs (default: loki.url)
    selector: '{service_name="loki"}'
    prove_live: true             # send a marker query and wait until it shows up
    org_id: ""                   # credentials for url, as under loki; when url is loki.url, loki's
    username: ""                 # are the default, and another Loki never receives them
    password_env: ""
    bearer_token_env: ""
  ruler: true
  grafana:
    - url: http://grafana:3000
      token_env: GRAFANA_TOKEN   # or username + password_env
      datasources: [loki]        # required: Grafana datasource UIDs that point at loki.url
      other_datasources: []      # Loki datasources that point at a different Loki; any Loki datasource
                                 # in neither list counts as loki.url and is reported as a gap
  opensearch:                    # clusters the pipeline also ships to, referenced by sinks
    - name: search
      url: https://opensearch:9200
      username: sievelog
      password_env: OPENSEARCH_PASSWORD
      ca_file: ""                # or insecure_skip_verify: true for a self-signed test cluster
      audit_index: security-auditlog-*  # the security plugin's audit indices
      dashboards_index: .kibana*        # OpenSearch Dashboards saved objects
      prove_live: true           # send a marker search and wait until it is audited
      indices: ["logs-{service}*"]      # where a service's documents land; {service} is replaced
      service_field: service.name       # keyword field naming the service; "" to not rely on one

runtime: collector               # collector, vector or fluentbit

collector:
  config_files: [collector.yaml] # merged in order, like repeated --config flags
  pipeline: logs
  after: transform/prep          # rules act after this processor
  measure_exporters: [prometheus] # receive the per-rule measurement metrics
  aggregate_exporters: [prometheus] # receive the counters that replace aggregated lines
  dedupe_interval: 10s
  severity_keys: []              # log attributes (and structured body fields) holding a level, in
                                 # addition to level, severity, lvl, loglevel and log.level; a record
                                 # at warning or above there, or by severity_number/severity_text, is
                                 # never measured as removable and never removed
  sinks:                         # every exporter downstream of the enforcement point
    otlp_http/loki: {loki: true}
    opensearch/logs: {opensearch: search}
    kafka/archive: {exempt: "archive only, never queried"}
  derived_exempt: {}             # connectors turning these logs into metrics, with the reason

vector:
  config_files: [vector.yaml]
  after: prep                    # rules act on this component's output
  scope_path: .service           # VRL path of the scope value
  text_path: .message            # VRL path of the plain text
  field_paths: {orders: .body.msg}
  dedupe_group_by: [kubernetes.pod_name]
  dedupe_ms: 10000
  measure_sink: {type: prometheus_exporter, address: "0.0.0.0:9598"}
  severity_paths: []             # VRL paths of level fields, checked in addition to the defaults at
                                 # the top level and beside every structured field, and severity_number
  sinks: {loki: {loki: true}}
  derived_exempt: {}

fluentbit:
  config_files: [fluent-bit.yaml]
  match: kube.*                  # tag pattern of the records rules apply to
  after: prep                    # alias of the filter after which rules run
  scope_key: service
  text_key: [log]
  field_keys: {orders: [body, msg]}
  metrics_tag: sievelog.metrics  # outputs matching this tag receive the measurement metrics
  severity_keys: []              # record paths of level fields, e.g. [[custom]], checked in addition
                                 # to the defaults at the top level and beside every structured field
  sinks: {loki: {loki: true}}
  derived_exempt: {}

policy:
  actions: [aggregate, dedupe, sample]  # in order of preference; add drop to allow it, and
                                        # rollup to allow rewriting counting queries (Collector only)
  experimental_rollup: false     # rollup is experimental: it is refused unless this is true
  sample_percent: 10
  acknowledge: []                # evidence gap keys accepted deliberately, from the report
  exempt: []                     # rule IDs (r-...) or template regexes never acted on
  error_pattern: ""              # default: a case-insensitive list of error-like words
  min_daily_bytes: 0

pricing:                         # what you pay your log service; the report shows volume only without it
  per_gb: 0                      # per gigabyte ingested, from your own invoice or contract
  per_million_lines: 0           # per million lines (events) indexed, if you are billed for that
  currency: USD                  # printed beside every amount
```

The saving is reported in money only at prices you give. List prices differ by region, plan,
retention and discount, so no price is built in: take the per-gigabyte (and, if billed, per-event)
price from your own invoice.

## Evidence gap keys

Acknowledging a key in `policy.acknowledge` accepts every gap with exactly that key. A gap about one
object names the object in its key, so acknowledging it never accepts another object's gap. A gap
about a whole source (a query log that is not proven, query history, OpenSearch plugins) is accepted
for every instance of that source.

| Key | Meaning |
|---|---|
| `querylog-disabled` | the query log is not read |
| `querylog-not-live` | the marker query never appeared in the query log |
| `grafana-datasource-unmapped` | a Grafana Loki datasource is in neither `datasources` nor `other_datasources`; its queries count as reading loki.url |
| `querylog-not-proven` | `prove_live` is off, so it is not proven that queries, tails and pattern requests are logged |
| `querylog-tail-not-visible` | a marker live tail never appeared in Loki's logs (tails need info-level querier logs) |
| `querylog-patterns-not-visible` | a marker pattern request never appeared (set `frontend.query_stats_enabled: true`) |
| `querylog-window` | the query log starts after the evidence window starts |
| `querylog-unreadable`, `querylog-unparsed` | the query log could not be read, or lines did not parse |
| `ruler-not-checked`, `ruler-unreadable` | Loki ruler rules were not read |
| `grafana-not-configured`, `grafana-unreadable` | no Grafana, or it could not be read |
| `grafana-queryhistory` | only the credentials' own Explore history is readable |
| `grafana-orgs` | the credentials cannot list organisations (a service account token never can), so only their own org was read |
| `grafana-<kind>` | a kind of Grafana object (alert rules, library panels, ...) could not be listed |
| `grafana-<kind>:<grafana>/org<n>/<object>` | one Grafana object could not be read; the key names it, so acknowledging it accepts only that object |
| `opensearch-unreadable` | the cluster, or its index catalog, could not be read |
| `opensearch-audit-config-unreadable` | the audit configuration could not be read |
| `opensearch-audit-disabled` | audit logging, REST auditing or the AUTHENTICATED category is off |
| `opensearch-audit-not-live` | the marker search never appeared in the audit log |
| `opensearch-audit-ignored-users`, `-requests`, `-headers` | the audit log skips these users, requests or headers |
| `opensearch-audit-window` | the audit log starts after the evidence window starts, or is empty |
| `opensearch-audit-unreadable`, `opensearch-audit-unparsed` | the audit log could not be read, or entries did not parse |
| `opensearch-monitors-unreadable`, `opensearch-monitors-unparsed` | alerting monitors could not be read |
| `opensearch-dashboards-unreadable`, `opensearch-dashboards-unparsed` | Dashboards saved objects could not be read |
| `opensearch-saved-queries` | Dashboards saved queries exist; they can be applied to any index pattern |
| `opensearch-plugins` | queries stored by notebooks, reporting, anomaly detection and observability are not read |
| `opensearch-transport-reads` | searches from other clusters arrive over the transport layer, which the REST audit log does not record |
| `opensearch-scope-empty` | no document of the service is in its configured indices |
| `opensearch-scope-outside` | some of the service's documents are outside its configured indices |
| `opensearch-scope-unverified` | it could not be checked that the service's documents stay in its indices |
| `sink:<id>` | a destination downstream of the enforcement point has no evidence |
| `derived:<id>` | a connector or transform turns these logs into metrics |
