# zeroreads

zeroreads finds the log lines that no logged query, alert, dashboard or stored query reads, proves it
for each rule, and writes the pipeline configuration that removes, shrinks or archives them.

> **Before you enforce anything:** deploy the shadow configuration first and let it run, with
> `zeroreads verify` on a schedule, for a period that covers your normal weekly traffic and on-call
> usage. Shadow mode removes nothing; it measures, per rule, exactly what enforcement would remove.
> Enforce only rules whose shadow numbers and verify results you have looked at.

## What it is

- An open-source tool that finds the log lines no logged query, alert, dashboard or stored query
  reads, proves that for each rule, and writes the pipeline configuration that removes, shrinks or
  archives them, in the OpenTelemetry Collector, Vector or Fluent Bit.
- It runs on your infrastructure and sends nothing anywhere except to the Loki, Grafana and
  OpenSearch you configure: no telemetry, no update checks.
- Default deny: whatever it cannot model counts as reading everything, and missing evidence blocks
  every rule until it is fixed or deliberately acknowledged.

## What has been measured

Every number below comes from the test suites, run against the real engines listed under [Supported
versions](#supported-versions).

- **"Nobody reads this" was never wrong.** 9,114 such answers were checked against what Loki
  actually returned, over three generated query sets (random, fuzzed from real rules, and
  adversarial members of hard patterns): none was wrong. On those query distributions that bounds
  the error rate below 0.03% at 95% confidence (3/n). 144 OpenSearch answers were each confirmed by
  OpenSearch itself; with that few, the bound is only 2.1%.
- **Over-blocking, the other side, is measured too.** Of the "reads" answers on the same query sets,
  38% were exact, and every exact one was confirmed (388 of 388: the line shown was stored in Loki
  and the query returned it). The rest were assumed readers, which can block a rule that is in fact
  safe; the report names each assumption, so an install can see its own.
- **Real dashboards.** 358 public Loki dashboards (the Grafana dashboard directory and the Loki
  mixin, downloaded at test time), 2,365 Loki queries: 90.3% parse, and every one that does not is
  rejected by Loki 3.7.8 as well; the line filters of 40% are modelled exactly; with the scope label
  set to the label each query selects by, 30% are exact end to end. 52% pick their streams with
  template variables, which count as reading every service they could name.
- **A realistic app.** The OpenTelemetry demo (13 services, its own load generator) on a local kind
  cluster, logging through its own Collector into Loki, with a small set of dashboards, one alert
  and a few ad-hoc queries written for it: 29 of 46 rules acted. In a 15-minute shadow window their
  lines were 42.7% of the stored lines (23.8% of the bytes), and the Collector's own measurement
  counted 2,328 lines where Loki stored 2,322 (the windows' edges differ by seconds); while enforcing,
  none of them was stored (reconcile: 29 ok), and verify passed. No production cluster has been
  measured yet.
- **Scale.** 999,999 log lines and 300,000 query executions analysed in 2m27s at 70 MB peak; a
  Grafana with 5,000 dashboards (20,008 queries) in 2m54s at 382 MB; 1,000,000 OpenSearch audit
  entries read in 2m4s.
- **Removal is exact.** Each runtime's output, shadow and enforce, archive included, was compared
  record by record with the prediction on the real Collector, Vector and Fluent Bit.

Most log volume is a handful of repetitive patterns: health checks, heartbeats, cache chatter. Paid
tools can tell you which ones are safe to drop. zeroreads does the same job in the open, on your own
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
   when your policy allows it. With an archive, put archive first: the lines leave Loki for storage
   you choose and stay retrievable, each marked with the rule that moved it.
7. **Warnings and errors are kept.** A rule whose pattern could match an error-like word, or whose
   sampled lines carry a warning or error level, gets no action. And every Collector, Vector and
   Fluent Bit rule carries a runtime guard: a record whose `severity_number`, `severity_text` or level
   field says warning or worse is never measured as removable and never removed, whatever the rule
   matched. The one exception is Telemetry Policy output: the format cannot express the guard, so it
   is written only when you pass `-allow-no-severity-guard` (see below).
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

The archive action, when chosen, sends a rule's lines to an archive destination you name in all three
runtimes instead of removing them. Every regular expression is rewritten for the target engine's dialect and checked against that engine
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
zeroreads analyze -c zeroreads.yaml -o out/          # report.md, report.json, rules.json
zeroreads emit -c zeroreads.yaml -rules out/rules.json -mode shadow  -o collector.yaml
# deploy the shadow config, run verify on a schedule, and read the numbers before going further
zeroreads emit -c zeroreads.yaml -rules out/rules.json -mode enforce -o collector.yaml
zeroreads rewrite -c zeroreads.yaml -rules out/rules.json -o rewrites/ -apply   # only for rollups
zeroreads verify -c zeroreads.yaml -rules out/rules.json -deployed collector.yaml
# exit code 3 when a rule is no longer safe or the deployed config is not the emitted one
```

Exit codes: 0 success, 1 error, 2 usage, 3 `verify` found a rule that is no longer safe or a
deployed configuration that differs from the emitted one, 4 `reconcile` found stored volume that does
not match the rules, 5 `rewrite` could not rewrite every object. `zeroreads version` prints the release
and the embedded drain version.

zeroreads sends nothing anywhere except to the Loki, Grafana and OpenSearch you configure: no
telemetry, no update checks.

Run `verify` on a schedule with the Helm chart in `charts/zeroreads`, or in CI with the GitHub Action in
this repository. When someone adds a dashboard or alert that reads removed lines, `verify` fails, says
why, and prints the rules that remain safe: emit and deploy those to revert. It also reports drift:
lines of a rule's template that the rule no longer covers. Those pass through untouched, so drift never
fails `verify`; it means the template is worth re-analysing.

Run the Action on pushes and on a schedule, not on pull requests with your credentials: the Action
reads `zeroreads.yaml` from the checkout, and a pull request can change where it sends them.

See [docs/configuration.md](docs/configuration.md) for every setting,
[docs/safety.md](docs/safety.md) for exactly what is guaranteed and what is not, and
[CHANGELOG.md](CHANGELOG.md) for what changed.

## Build

```sh
go build ./cmd/zeroreads
./scripts/check.sh            # formatting, vet, unit tests
./scripts/check-runtimes.sh   # dialect and runtime tests against real Vector, Fluent Bit and the Collector (docker)
./e2e/run.sh                  # on kind: Loki, Grafana, OpenSearch and Dashboards; the full loop through
                              # the Collector, Vector and Fluent Bit; rollups with rewrites; the Helm
                              # chart; a million-line scale run; a Grafana with thousands of dashboards
E2E_CORPUS=1 ./e2e/run.sh     # also measures the public Loki dashboard corpus (downloaded, not stored)
./e2e/demo/run.sh             # after e2e/run.sh: the OpenTelemetry demo as a realistic workload
```

## Verify a release

Each release's checksums and image are signed keylessly by the release workflow at the release's tag.
With cosign:

```sh
V=0.1.0
ID=https://github.com/Bisman-Singh/zeroreads/.github/workflows/release.yml@refs/tags/v$V
ISSUER=https://token.actions.githubusercontent.com
cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" checksums.txt
sha256sum -c checksums.txt --ignore-missing
cosign verify --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" ghcr.io/bisman-singh/zeroreads:$V
```

The archives also hold `THIRD_PARTY_LICENSES`, and rebuilding a commit gives the same archive bytes. To
run exactly the verified image, set `image.digest` in the Helm chart,
and in a workflow use the image by digest (`uses: docker://ghcr.io/bisman-singh/zeroreads@sha256:...`
with the `verify` arguments) instead of the Action's tag.

## Security

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
