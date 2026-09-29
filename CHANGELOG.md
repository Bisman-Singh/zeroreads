# Changelog

## 0.1.0

The first release. Everything below is new.

### Decides

- Templates from Loki with the OpenTelemetry drain processor, and one exact, anchored removal pattern
  per rule.
- Usage evidence from Loki's query log (queries, live tails and pattern requests, each proven visible
  with a marker), the Loki ruler, every Grafana object that stores a Loki query, and OpenSearch (beta).
- Every evidence gap blocks every rule until fixed or acknowledged.
- A Grafana Loki datasource that is not classified counts as the analysed Loki and is reported.
- Warning and error lines are never acted on: at analysis, and by a runtime guard in every Collector,
  Vector and Fluent Bit rule. Telemetry Policy output cannot carry the guard and needs
  `-allow-no-severity-guard`.
- A rule that would empty a stream is blocked.
- Every reader in the report is exact (a line it reads is shown) or assumed to read more than it may,
  with what was assumed; the report counts both, so over-blocking can be seen and fixed.

### Enforces

- OpenTelemetry Collector, Vector and Fluent Bit configuration, in shadow (measure only) and enforce
  mode, each checked against the real engine. Collector measurement runs where enforcement acts.
- Telemetry Policy files, only with `-allow-no-severity-guard`: the format cannot express the guard.
- Actions: archive (opt-in: the lines move to an archive you name and stay retrievable), aggregate,
  dedupe, sample, drop (opt-in), and rollup (experimental, opt-in with `policy.experimental_rollup`)
  with rewrites of the Grafana and Loki ruler queries that count the rolled-up lines.

### Guards

- `verify`: new readers, gaps, drain configuration changes, drift, and deployed-config differences;
  exit code 3 and the rules that remain safe, printed for the scheduled Job's log.
- `reconcile`: stored volume before and after enforcement, from Loki.
- Helm chart for a scheduled `verify`, and a GitHub Action running the released image.

### Hardened before the first release

- Found by measuring the public dashboard corpus: a panel on a Prometheus datasource variable was read
  as a Loki query and blocked every rule; datasource variables now resolve by their plugin type.
  Template variables naming a matcher's label parse.
- Found while measuring: Grafana 13.2.2's dashboard list can answer empty with a success status right
  after writes. Every dashboard the search API finds is now listed, read on its own, or a gap, and
  short links are listed until two lists agree.
- Found on the realistic run: with no rule to act, emit wrote a measurement step the Collector refuses
  at startup; the configuration now stays exactly the user's. And a Prometheus exporter restarts its
  totals at nearly every batch of the per-rule delta counts, so emit refuses it for measurement and
  aggregate counters; an exporter that accepts delta temporality is required.
- Rollup rewrites stay linear in size for any number of rules, and count each line once when two
  services share a language.
- Values from logs are written literally into every runtime's configuration (the Collector and Vector
  expand `${...}`, VRL reads `{{ }}`), and emitters refuse unsafe rule IDs and actions they cannot
  enforce.
- Default deny tightened: only the ruler's own 404 means no rules; credentials that cannot list
  Grafana organisations leave a `grafana-orgs` gap; OpenSearch requests on names the cluster no longer
  has count as reads, and cross-cluster reads are a gap; a gap about one Grafana object names that
  object, so acknowledging it accepts nothing else; configured level fields add to the defaults, so an
  empty list can never switch the severity guard off.
- `rules.json` is validated on load (a hand-edited rule no longer matches its ID) and written
  atomically; emitted runtime configurations are readable by their owner only.
- Configuration: credentials in URLs and empty secret variables are refused, durations are exact,
  names written into queries and pipeline programs are checked, and the query log has its own
  credentials.
- Robustness: every HTTP answer is bounded, transient failures of reads are retried, Loki paging always
  moves forward, query text is bounded at 256 KiB, and every regular-expression question is bounded in
  work as well as states.
- `sievelog version`, documented exit codes, CI with lint and vulnerability scans, actions and base
  images pinned to digests.
- Money is reported only at your own prices (`pricing.per_gb`, `pricing.per_million_lines`,
  `pricing.currency`); no list prices are built in, since region, plan and discounts change them.

### Supported versions

See the table in the README. The test suites run against exactly those versions.
