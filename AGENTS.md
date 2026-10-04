# Working on sievelog

Guidance for anyone changing this repository, people and coding agents alike.

## What it is

A Go CLI (plus a Helm chart and a GitHub Action) that decides which log lines nobody reads, proves it
from usage evidence, and writes pipeline configuration that removes them. It is a safety tool first:
a wrong "unread" removes logs someone needs.

## Stack

- Go 1.27.1 (the exact version in `go.mod`), module `github.com/Bisman-Singh/sievelog`.
- Evidence: Loki 3.7.8 (query log, ruler), Grafana 13.2.2, OpenSearch and Dashboards 3.8.0 (beta).
- Enforcement: OpenTelemetry Collector contrib 0.161.0, Vector 0.58.0, Fluent Bit 5.1.2, policy-go 1.12.1.
- Tests: unit tests, differential tests against the real runtimes in docker, and end-to-end tests on a
  dedicated kind cluster.

## Layout

- `cmd/sievelog`: the CLI. `internal/app`: commands wired to sources, analysis and emitters.
- `internal/analyze`: the decision per rule. `internal/usage`, `internal/automaton`: whether a query
  can read a rule's lines, decided on automata. `internal/logql`: the LogQL parser.
- `internal/source/{loki,grafana,opensearch}`: evidence readers. `internal/fetch`: their HTTP.
- `internal/emit`, `internal/dialect`, `internal/topology`: runtime configuration and regex dialects.
- `internal/rewrite`: rollup query rewrites. `e2e/`: kind suites. `docs/`: user documentation.

## Commands

```sh
./scripts/check.sh            # gofmt, vet (all build tags), unit tests: run before every commit
golangci-lint run --build-tags e2e,docker ./...   # v2.14.0 built with the module's Go
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
gitleaks git --config .gitleaks.toml --redact .   # v8.30.1, every commit, as CI scans them
./scripts/check-runtimes.sh   # real Vector, Fluent Bit and Collector in docker
./e2e/run.sh                  # everything on kind (about 90 minutes); REUSE=1 E2E_RUN=<regexp> for one suite;
                              # E2E_CORPUS=1 also measures the public dashboard corpus (needs the internet)
./e2e/demo/run.sh             # after e2e/run.sh: the OpenTelemetry demo as a realistic workload (about an hour)
```

## Conventions

- Default deny. Anything that cannot be modelled exactly counts as reading everything; missing
  evidence is a gap that blocks every rule until fixed or acknowledged by its key.
- A behaviour change comes with a test that fails without it (check by reverting the change once),
  and, when it touches a runtime or an evidence source, with a check against the real one.
- Small functions with one job, early returns instead of nesting, names that say what a value is.
  Comments say why, not what.
- State lives in values passed around, not in package variables. Errors are returned with context,
  never dropped; an error that is deliberately ignored says why on the same line.
- Every string written into another system's configuration or query language is escaped for that
  system and tested against the real system.
- One change per commit, with a one-line message `area: what changed`. Branch per change, fast-forward
  merge.

## Definition of done

1. The change is covered by a test that fails without it.
2. `./scripts/check.sh` passes, and golangci-lint reports 0 issues.
3. Anything touching an evidence source, a runtime or an emitted configuration passes its docker or
   kind suite.
4. Documentation says what the change means for a user: `docs/`, the gap key tables, `CHANGELOG.md`.
5. No TODOs, stubs, placeholder data or skipped tests left behind.

## Never

- Never weaken default deny: no guessing that a query reads nothing, no silent fallbacks, no gap
  hidden or downgraded by matching its text.
- Never emit a rule without the severity guard (the Telemetry Policy format needs the explicit flag).
- Never let a value from logs or queries reach a runtime configuration unescaped.
- Never put real log data, credentials or hostnames in tests, fixtures or examples.
- Never run tests against any cluster but the kind cluster the e2e creates, and always name its
  context explicitly. A new e2e script sources `e2e/lib.sh`, which drops Helm's `HELM_KUBE*`
  overrides and refuses a local port that something else already holds.
- Never disable a check, a linter rule or a test to make a change pass; fix the cause, or document an
  exclusion with its reason in `.golangci.yml`.
- Never release without the full e2e, the runtime suite and a goreleaser snapshot passing. The release
  workflow refuses a tag whose commit is not on main or has no passing CI run; rehearse it first by
  running it by hand, which builds everything and signs and publishes nothing.
