# sievelog

sievelog finds the log lines nobody reads, proves it, and writes the pipeline configuration that
removes them.

> **Before you enforce anything:** deploy the shadow configuration first and let it run, with
> `sievelog verify` on a schedule, for a period that covers your normal weekly traffic and on-call
> usage. Shadow mode removes nothing; it measures, per rule, exactly what enforcement would remove.
> Enforce only rules whose shadow numbers and verify results you have looked at.

Most log volume is a handful of repetitive patterns: health checks, heartbeats, cache chatter. Paid
tools can tell you which ones are safe to drop. sievelog does the same job in the open, on your own
infrastructure, and shows its evidence for every decision.

Start with [docs/quickstart.md](docs/quickstart.md): from nothing to a shadow-mode report, and what to
do when every rule is blocked.

## How it decides

1. **Templates.** It samples your logs from Loki and groups them into templates with the Drain
   algorithm, using the same drain processor code as the OpenTelemetry Collector.
2. **An exact language per rule.** For each template it infers a precise pattern of the lines a rule
   would remove: fixed words stay fixed, variable parts are limited to the values actually seen.
   A rule removes exactly the lines matching that pattern, never whatever else a template might absorb
   later.
3. **Usage evidence.** It reads everything that can read those lines:
   - Loki's query log: every query actually run, live tails and Logs Drilldown pattern requests, each
     proven visible with a marker first
   - Loki ruler alerts and recording rules
   - Grafana dashboards (both schemas), library panels, annotations, alert and recording rules,
     Explore short links, query history and correlations, across every organisation
   - OpenSearch (beta), when the pipeline also ships there: every search in the security audit log
     (proven live with a marker search first), alerting monitors, and Dashboards saved searches and
     visualizations in every tenant
4. **Proof, not guesses.** For every query it decides whether the query can select any line the rule
   would remove, and shows a sample line when it can. Anything it cannot model exactly counts as
   reading everything. An unparseable query blocks every rule. Missing evidence is a gap that blocks
   every rule until fixed or deliberately acknowledged.
5. **Every destination.** It follows the pipeline from the enforcement point to every exporter. A
   removal counts only if every destination is the analysed Loki, a connected OpenSearch, or
   explicitly exempted.
6. **The least lossy action.** A rule nobody reads gets, in order of preference: aggregate (lines
   become a counter), dedupe (identical lines collapse into one with a count), or sample. Drop only
   when your policy allows it.
7. **Warnings and errors are kept.** A rule whose pattern could match an error-like word, or whose
   sampled lines carry a warning or error level, gets no action. And every emitted rule carries a
   runtime guard: a record whose `severity_number`, `severity_text` or level field says warning or
   worse is never measured as removable and never removed, whatever the rule matched. (The Telemetry
   Policy format cannot express that guard; see below.)
8. **Rollup (experimental).** When the only readers of a rule's lines are stored queries that count
   them, the lines can roll up into one record per interval carrying the count, and those queries
   are rewritten to return the same numbers before, during and after the switch. It is off unless
   `policy.experimental_rollup` is set.

## Where it enforces

| Runtime | Output | Verified against |
|---|---|---|
| OpenTelemetry Collector | `filter`, `logdedup`, `transform`, `signal_to_metrics`, `forward` config | contrib 0.161.0, full loop on Kubernetes |
| Vector | VRL `remap`, `route`, `reduce`, `log_to_metric` config | Vector 0.58.0, full loop on Kubernetes, every event compared |
| Fluent Bit | `modify`, `grep`, `lua`, `log_to_metrics` config | Fluent Bit 5.1.2, full loop on Kubernetes, every record compared |
| Telemetry Policy | policy file for policy-go based runtimes | policy-go 1.12.1 with teroscan; no severity guard, emitted only with `-allow-no-severity-guard` |

Every regular expression is rewritten for the target engine's dialect and checked against that engine
on thousands of generated strings, including Unicode traps. Sampling is deterministic: each runtime
keeps a line exactly when a SHA-256 of its text and timestamp falls under a threshold, so the kept
share is exact and every decision can be reproduced.

## Supported versions

These are the versions the test suites run against. Other versions may work; these are the ones
proven.

| Component | Version |
|---|---|
| Go (build) | 1.27.1 |
| Loki | 3.7.8 |
| Grafana | 13.2.2 |
| OpenTelemetry Collector contrib | 0.161.0 |
| Vector | 0.58.0 |
| Fluent Bit | 5.1.2 |
| OpenSearch and OpenSearch Dashboards (beta) | 3.8.0 |
| policy-go (Telemetry Policy) | 1.12.1, teroscan 1.10.3 |

## Use

```sh
sievelog analyze -c sievelog.yaml -o out/          # report.md, report.json, rules.json
sievelog emit -c sievelog.yaml -rules out/rules.json -mode shadow  -o collector.yaml
# deploy the shadow config, run verify on a schedule, and read the numbers before going further
sievelog emit -c sievelog.yaml -rules out/rules.json -mode enforce -o collector.yaml
sievelog rewrite -c sievelog.yaml -rules out/rules.json -o rewrites/ -apply   # only for rollups
sievelog verify -c sievelog.yaml -rules out/rules.json -deployed collector.yaml
# exit code 3 when a rule is no longer safe or the deployed config is not the emitted one
```

Exit codes: 0 success, 1 error, 2 usage, 3 `verify` found a rule that is no longer safe or a
deployed configuration that differs from the emitted one, 4 `reconcile` found stored volume that does
not match the rules, 5 `rewrite` could not rewrite every object. `sievelog version` prints the release
and the embedded drain version.

sievelog sends nothing anywhere except to the Loki, Grafana and OpenSearch you configure: no
telemetry, no update checks.

Run `verify` on a schedule with the Helm chart in `charts/sievelog`, or in CI with the GitHub Action in
this repository. When someone adds a dashboard or alert that reads removed lines, `verify` fails, says
why, and prints the rules that remain safe: emit and deploy those to revert. It also reports drift:
lines of a rule's template that the rule no longer covers. Those pass through untouched, so drift never
fails `verify`; it means the template is worth re-analysing.

See [docs/configuration.md](docs/configuration.md) for every setting,
[docs/safety.md](docs/safety.md) for exactly what is guaranteed and what is not, and
[CHANGELOG.md](CHANGELOG.md) for what changed.

## Build

```sh
go build ./cmd/sievelog
./scripts/check.sh            # formatting, vet, unit tests
./scripts/check-runtimes.sh   # dialect and runtime tests against real Vector, Fluent Bit and the Collector (docker)
./e2e/run.sh                  # on kind: Loki, Grafana, OpenSearch and Dashboards; the full loop through
                              # the Collector, Vector and Fluent Bit; rollups with rewrites; the Helm
                              # chart; a million-line scale run
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
