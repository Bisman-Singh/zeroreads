# Changelog

## Unreleased

First release candidate. Everything below is new.

### Decides

- Templates from Loki with the OpenTelemetry drain processor, and one exact, anchored removal pattern
  per rule.
- Usage evidence from Loki's query log (queries, live tails and pattern requests, each proven visible
  with a marker), the Loki ruler, every Grafana object that stores a Loki query, and OpenSearch (beta).
- Every evidence gap blocks every rule until fixed or acknowledged.
- A Grafana Loki datasource that is not classified counts as the analysed Loki and is reported.
- Warning and error lines are never acted on: at analysis, and by a runtime guard in every emitted
  rule (Collector, Vector, Fluent Bit).
- A rule that would empty a stream is blocked.

### Enforces

- OpenTelemetry Collector, Vector and Fluent Bit configuration, in shadow (measure only) and enforce
  mode, each checked against the real engine. Collector measurement runs where enforcement acts.
- Telemetry Policy files, only with `-allow-no-severity-guard`: the format cannot express the guard.
- Actions: aggregate, dedupe, sample, drop (opt-in), and rollup (experimental, opt-in with
  `policy.experimental_rollup`) with rewrites of the Grafana and Loki ruler queries that count the
  rolled-up lines.

### Guards

- `verify`: new readers, gaps, drain configuration changes, drift, and deployed-config differences;
  exit code 3 and the rules that remain safe, printed for the scheduled Job's log.
- `reconcile`: stored volume before and after enforcement, from Loki.
- Helm chart for a scheduled `verify`, and a GitHub Action running the released image.

### Supported versions

See the table in the README. The test suites run against exactly those versions.
