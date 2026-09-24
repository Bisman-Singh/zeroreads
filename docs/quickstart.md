# Quickstart

From nothing to a shadow-mode report you can trust. Nothing here removes a single log line.

## 1. Install

Download a release binary, or run the image:

```sh
docker run --rm -v "$PWD:/w" -w /w ghcr.io/bisman-singh/sievelog:0.1.0 analyze -c sievelog.yaml -o out/
```

Or build from source: `go build ./cmd/sievelog` (Go 1.27.1).

## 2. Let Loki record what is read

sievelog's strongest evidence is Loki's own query log. In Loki's configuration:

```yaml
frontend:
  log_queries_longer_than: -1ns   # log every query, not only slow ones
  query_stats_enabled: true       # also log pattern requests (Grafana Logs Drilldown)
```

Ship Loki's own logs into a Loki that sievelog can query, at info level. sievelog proves all of this
works by sending marker queries and waiting until they show up.

## 3. Write sievelog.yaml

The smallest useful configuration, for an OpenTelemetry Collector pipeline:

```yaml
loki:
  url: http://loki:3100
evidence:
  window: 30d
  query_log: {enabled: true, selector: '{service_name="loki"}', prove_live: true}
  ruler: true
  grafana:
    - url: http://grafana:3000
      token_env: GRAFANA_TOKEN
      datasources: [loki]          # the UIDs of every Grafana datasource that points at loki.url
collector:
  config_files: [collector.yaml]   # your collector config, unchanged
  pipeline: logs
  after: batch                     # rules act after this processor
  measure_exporters: [prometheus]  # receive the per-rule measurements
  sinks:
    otlp_http/loki: {loki: true}   # every exporter after the enforcement point, accounted for
```

[configuration.md](configuration.md) documents every setting, including Vector and Fluent Bit.

## 4. Analyze

```sh
sievelog analyze -c sievelog.yaml -o out/
```

Read `out/report.md`. Every template has a section: the exact pattern a rule would remove, the volume
it would save, and either an action or the reasons it is blocked, with the query that reads it and a
sample line that query would return.

## 5. Shadow

```sh
sievelog emit -c sievelog.yaml -rules out/rules.json -mode shadow -o collector-shadow.yaml
```

Deploy `collector-shadow.yaml` in place of your collector config. It removes nothing: it adds metrics
`sievelog.rule.lines.<rule>` and `sievelog.rule.bytes.<rule>` with exactly what each rule would remove,
measured at the point where enforcement would act. Run `sievelog verify` on a schedule (the Helm chart
in `charts/sievelog` does this) and leave it for a period that covers your normal weekly traffic.

Only then consider `-mode enforce`, and keep `verify` running.

## Why is everything blocked?

sievelog blocks every rule while any evidence is missing, because a rule can only be safe if nothing
that reads its lines went unseen. Each missing piece is an evidence gap with a stable key, listed at
the top of the report. For each one, either fix it, or accept it deliberately by adding its key to
`policy.acknowledge`. Acknowledging a gap is a decision that the unseen readers do not exist or do not
matter; write down why.

| Gap key | What is missing | How to resolve it |
|---|---|---|
| `querylog-disabled` | the query log is not read | set `evidence.query_log.enabled: true` |
| `querylog-not-live` | the marker query never appeared | set `frontend.log_queries_longer_than: -1ns` in Loki, and check the selector finds Loki's own logs |
| `querylog-not-proven` | `prove_live` is off | set `evidence.query_log.prove_live: true` |
| `querylog-tail-not-visible` | a marker live tail never appeared | Loki's queriers must log at info level, and their logs must be collected |
| `querylog-patterns-not-visible` | a marker pattern request never appeared | set `frontend.query_stats_enabled: true` in Loki |
| `querylog-window` | the query log is younger than the evidence window | wait until it covers the window, or shorten `evidence.window` |
| `querylog-unreadable`, `querylog-unparsed` | the query log could not be read or parsed | check the Loki URL and credentials in `evidence.query_log` |
| `ruler-not-checked`, `ruler-unreadable` | Loki ruler rules were not read | set `evidence.ruler: true`, check ruler API access |
| `grafana-not-configured` | no Grafana is configured | add every Grafana under `evidence.grafana`, or acknowledge if none reads this Loki |
| `grafana-unreadable` | a Grafana could not be read | check its URL and credentials; the token needs read access to every org |
| `grafana-datasource-unmapped` | a Grafana Loki datasource is in neither `datasources` nor `other_datasources` | list it in `datasources` if it points at `loki.url`, otherwise in `other_datasources` |
| `grafana-queryhistory` | only the credentials' own Explore history is readable | acknowledge, or accept that other users' history is invisible through the API |
| `grafana-<kind>` | one kind of Grafana object could not be read | grant the credentials access to it |
| `sink:<id>` | an exporter after the enforcement point has no evidence | map it under `collector.sinks` as `loki: true`, `opensearch: <name>`, or `exempt: <reason>` |
| `derived:<id>` | a connector turns these logs into metrics | removing lines changes that metric; exempt it only if that is acceptable |
| `opensearch-*` | an OpenSearch cluster's evidence is incomplete | see the OpenSearch keys in [configuration.md](configuration.md) |

When the gaps are resolved and a rule is still blocked, its section in the report names the exact
query, dashboard or alert that reads its lines. That reader is real: the rule stays blocked until the
reader stops reading those lines.
