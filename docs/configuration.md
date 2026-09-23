# Configuration

`sievelog.yaml` configures one analysis. Unknown keys are rejected.

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
  ruler: true
  grafana:
    - url: http://grafana:3000
      token_env: GRAFANA_TOKEN   # or username + password_env
      datasources: [loki]        # Grafana datasource UIDs that point at loki.url

runtime: collector               # collector, vector or fluentbit

collector:
  config_files: [collector.yaml] # merged in order, like repeated --config flags
  pipeline: logs
  after: transform/prep          # rules act after this processor
  measure_exporters: [prometheus] # receive the per-rule measurement metrics
  aggregate_exporters: [prometheus] # receive the counters that replace aggregated lines
  dedupe_interval: 10s
  sinks:                         # every exporter downstream of the enforcement point
    otlp_http/loki: {loki: true}
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
  sinks: {loki: {loki: true}}
  derived_exempt: {}

policy:
  actions: [aggregate, dedupe, sample]  # in order of preference; add drop to allow it
  sample_percent: 10
  acknowledge: []                # evidence gap keys accepted deliberately, from the report
  exempt: []                     # rule IDs (r-...) or template regexes never acted on
  error_pattern: ""              # default: a case-insensitive list of error-like words
  min_daily_bytes: 0

pricing:
  backend: none                  # none, or a built-in list price
```

## Evidence gap keys

| Key | Meaning |
|---|---|
| `querylog-disabled` | the query log is not read |
| `querylog-not-live` | the marker query never appeared in the query log |
| `querylog-window` | the query log starts after the evidence window starts |
| `querylog-unreadable`, `querylog-unparsed` | the query log could not be read, or lines did not parse |
| `ruler-not-checked`, `ruler-unreadable` | Loki ruler rules were not read |
| `grafana-not-configured`, `grafana-unreadable` | no Grafana, or it could not be read |
| `grafana-queryhistory` | only the credentials' own Explore history is readable |
| `grafana-<kind>` | a Grafana object of that kind could not be read |
| `sink:<id>` | a destination downstream of the enforcement point has no evidence |
| `derived:<id>` | a connector or transform turns these logs into metrics |
