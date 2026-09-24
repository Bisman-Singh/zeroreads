# sievelog

sievelog finds the log lines nobody reads, proves it, and writes the pipeline configuration that
removes them.

Most log volume is a handful of repetitive patterns: health checks, heartbeats, cache chatter. Paid
tools can tell you which ones are safe to drop. sievelog does the same job in the open, on your own
infrastructure, and shows its evidence for every decision.

## How it decides

1. **Templates.** It samples your logs from Loki and groups them into templates with the Drain
   algorithm, using the same drain processor code as the OpenTelemetry Collector.
2. **An exact language per rule.** For each template it infers a precise pattern of the lines a rule
   would remove: fixed words stay fixed, variable parts are limited to the values actually seen.
   A rule removes exactly the lines matching that pattern, never whatever else a template might absorb
   later.
3. **Usage evidence.** It reads everything that can read those lines:
   - Loki's query log (every query actually run, proven live with a marker query first)
   - Loki ruler alerts and recording rules
   - Grafana dashboards (both schemas), library panels, annotations, alert and recording rules,
     Explore short links, query history and correlations, across every organisation
   - OpenSearch, when the pipeline also ships there: every search in the security audit log (proven
     live with a marker search first), alerting monitors, and Dashboards saved searches and
     visualizations
4. **Proof, not guesses.** For every query it decides whether the query can select any line the rule
   would remove, and shows a sample line when it can. Anything it cannot model exactly counts as
   reading everything. An unparseable query blocks every rule.
5. **Every destination.** It follows the pipeline from the enforcement point to every exporter. A
   removal counts only if every destination is the analysed Loki, a connected OpenSearch, or
   explicitly exempted.
6. **The least lossy action.** A rule nobody reads gets, in order of preference: aggregate (lines
   become a counter), dedupe (identical lines collapse into one with a count), or sample. Drop only
   when your policy allows it. Error and warning lines are never touched.
7. **Rollup keeps counting queries working.** When the only readers of a rule's lines are alerts,
   recording rules or panels that count them, the lines can roll up into one record per interval
   carrying the count, and those queries are rewritten so they return the same numbers before,
   during and after the switch. Every rewrite is re-checked before it is offered, and proven
   against real Loki and Grafana in the end-to-end suite.

## Where it enforces

| Runtime | Output | Verified against |
|---|---|---|
| OpenTelemetry Collector | `filter`, `logdedup`, `signal_to_metrics`, `forward` config | contrib 0.161.0, end to end on Kubernetes |
| Vector | VRL `remap`, `route`, `reduce`, `log_to_metric` config | Vector 0.58.0, every event compared |
| Fluent Bit | `modify`, `grep`, `lua`, `log_to_metrics` config | Fluent Bit 5.1.2, every record compared |
| Telemetry Policy | policy file for policy-go based runtimes | policy-go 1.12.1 with teroscan |

Every regular expression is rewritten for the target engine's dialect and checked against that engine
on thousands of generated strings, including Unicode traps. Sampling is deterministic: each runtime
keeps a line exactly when a SHA-256 of its text and timestamp falls under a threshold, so the kept
share is exact and every decision can be reproduced.

## Use

```sh
sievelog analyze -c sievelog.yaml -o out/          # report.md, report.json, rules.json
sievelog emit -c sievelog.yaml -rules out/rules.json -mode shadow  -o collector.yaml
# deploy the shadow config: it only measures, per rule, what would be removed
sievelog emit -c sievelog.yaml -rules out/rules.json -mode enforce -o collector.yaml
sievelog rewrite -c sievelog.yaml -rules out/rules.json -o rewrites/ -apply   # only for rollups
sievelog verify -c sievelog.yaml -rules out/rules.json -deployed collector.yaml
# exit code 3 when a rule is no longer safe or the deployed config is not the emitted one
```

Run `verify` on a schedule with the Helm chart in `charts/sievelog`, or in CI with the GitHub Action in
this repository. When someone adds a dashboard or alert that reads removed lines, `verify` fails and
writes the rules that are still safe, which is the revert. It also reports drift: lines of a rule's
template that the rule no longer covers. Those pass through untouched, so drift never fails `verify`; it
means the template is worth re-analysing.

See [docs/configuration.md](docs/configuration.md) for every setting and
[docs/safety.md](docs/safety.md) for exactly what is guaranteed and what is not.

## Build

```sh
go build ./cmd/sievelog
./scripts/check.sh            # formatting, vet, unit tests
./scripts/check-runtimes.sh   # dialect and runtime tests against real Vector and Fluent Bit (docker)
./e2e/run.sh                  # full loop on kind: Loki, Grafana, OpenSearch, the Collector, the Helm chart
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
