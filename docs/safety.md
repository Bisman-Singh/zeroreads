# What sievelog guarantees, and what it does not

## Guarantees

**A rule removes only its own lines.** Every rule carries an exact, anchored pattern inferred from the
lines it was built from, scoped to one service. Enforcement matches that pattern and that service,
nothing else. Lines of the same template that fall outside the pattern pass through untouched.

**No two rules overlap.** Before any configuration is written, every pair of rules in the same scope
is proven disjoint with an automaton intersection. Output is refused otherwise.

**A rule acts only when nothing known reads its lines.** Every query from every connected source is
checked against the rule's pattern. The check models Loki's real matching behaviour, including its
case-insensitive shortcut and its rewriting of regular expressions. Whatever cannot be modelled
exactly is treated as reading more, never less:

- a query that does not parse reads and counts every line
- a template variable in a filter or matcher reads every line
- label filters and parsers never narrow what a query reads, and a filter after `line_format`,
  `decolorize` or `unpack` (which replace the line) is not used to exclude anything
- pattern (`|>`) and `ip()` filters, and case-insensitive negative regex filters, are ignored
- a line filter on a structured (JSON) record reads every line of that service

OpenSearch requests and stored queries are modelled per service, more coarsely. A request reads every
line of a service unless its target indices provably cannot hold that service's documents (after
resolving aliases, data streams and wildcards against the cluster), or its DSL query provably selects
other services through an exact `term` or `terms` filter on the service field (in `filter`, `must`,
`constant_score`, or a `must_not` naming the service). That filter is only trusted after the cluster
confirms the field is a plain `keyword` everywhere in scope, with no normalizer, no document missing
it and no document holding several values. SQL, PPL, Lucene query strings, KQL, `_msearch` and every
unknown endpoint read everything. A request denied after authentication still counts as a read,
because the REST audit entry is written before the denial.

Besides range and instant queries, the query log is read for live tails and for pattern requests
(Grafana Logs Drilldown), which Loki logs on other lines and under other settings; each is proven
visible with its own marker or reported as a gap. Label, series and stats requests read only the index
and are not readers; a rule that would empty a stream is blocked instead. Query-log lines from every
Loki component count: the frontend, queriers (which log time-split copies, or queries that bypassed the
frontend) and the ruler; a copy folds into the frontend query it came from, and so does a leg of it
(each side of a binary operation is logged separately) logged within two minutes of its execution.
Anything else is a reader of its own.

When a query can read a rule's lines, the report shows a sample line it would read. That line is
re-checked with the real regular expression engine before it is shown.

**Missing evidence blocks everything.** If the query log is not enabled, not proven live, or does not
cover the evidence window; if a source cannot be read; if a destination downstream of the enforcement
point has no evidence; or if a connector turns these logs into metrics, every rule is blocked until
the gap is fixed or explicitly acknowledged in `policy.acknowledge`.

**A rollup keeps every counting reader's numbers (experimental).** Rollup is refused unless
`policy.experimental_rollup` is set. A rule may roll up only when each of its readers
is a stored `sum [by (stream labels)] (count_over_time|rate(...))` whose line filters provably keep
every line of the rule, in a Grafana dashboard, library panel or alert rule, or a Loki ruler group.
Each is rewritten as the original minus the rule's lines, plus the rollup records' counts, plus any
of the rule's lines still stored, and the rewritten query is analysed again: it must not read the
rule's lines except through that last compensating term. The first term also excludes every rollup
record (`| sievelog_rule=""`), because a record's marker text can pass the original filters
(`!= "/healthz"` does). An executed query counts only when it is the same query as one of those stored
queries, compared in a canonical form that ignores formatting and time-split offsets. Anything else
that reads the lines keeps blocking, and so does any other query that could select the rollup records
themselves (`!~ "DEBUG"` would count them once they appear); `verify` checks both again after
enforcing. Rollup
records carry the stream's labels but not the lines' structured metadata, so grouping by structured
metadata is not rewritten. A rollup record's timestamp is when its interval flushes, so a count over
a window can shift by up to one interval at the window's edges.

**No stream disappears.** A rule that would remove every line of some stream in the window is
blocked, because the stream would vanish from label, series and volume results. Dedupe and rollup
always leave a record, so they are not affected.

**Errors and warnings are never touched.** A rule whose pattern can contain an error-like word, or
whose sampled lines carry a warning or error level (from Loki labels, structured metadata or record
fields named in `scope.severity_keys`), gets no action. And every emitted rule carries a runtime guard,
whatever the analysis saw: a record whose `severity_number` is WARN or above, whose `severity_text`
says warning or worse, or whose configured level field does, never matches a rule, so it is neither
measured as removable nor removed. The Collector checks `severity_number`, `severity_text`, log
attributes and structured body fields; Vector checks the configured paths and `severity_number`;
Fluent Bit checks the configured record keys. Each is tested against the real engine.

**Measure before removing.** Shadow mode adds only measurement: per rule, the lines (and, where the
runtime can count them, bytes) that enforcement would remove. In the Collector, measurement runs after
every processor that follows the enforcement point, on exactly the records enforcement acts on, so the
shadow numbers are what enforce removes. Enforce mode keeps measuring.

**Removal is exact and reproducible.** Every runtime's output is checked against that runtime's real
engine: every event or record delivered, removed, sampled or collapsed is compared with the
prediction. Sampling keeps a line exactly when the SHA-256 of its text and timestamp falls below a
threshold, so the decision for any line can be recomputed. A Collector record without a timestamp is
keyed by its observed time, which is the time Loki stores for it.

**New readers are caught.** `verify` re-reads every source and exits with code 3 when any enforced
rule gains a reader or loses its evidence, and writes the rules that remain safe: the revert. It also
fails when the drain version, masking rules or seed templates differ from the ones the rules were made
under, and, given `-deployed`, when the deployed pipeline config is not exactly what `emit` produces.

## Limits

- **Evidence covers what is connected and what happened in the window.** A query run before the
  window, from a Grafana that is not configured, or against a backend that is not analysed, is not
  seen. Grafana only exposes the query history of the user the credentials belong to.
- **A line nobody reads today may matter in a future incident.** Severity floors and the preference for
  aggregation over dropping reduce this. Nothing removes it.
- **Structured records rarely qualify.** Because a line filter on a JSON line can match any field,
  most queries against structured services count as reading every line.
- **Only the scope label can exclude a stream.** A query matching other labels (namespace, pod) is
  assumed to read the rule's service.
- **Drain has accuracy limits** on lines with many variable parts. Such templates get no rule or a
  narrow one.
- **Fluent Bit cannot collapse lines while keeping a count**, so dedupe is not offered there.
- **The Telemetry Policy format** can express only drop and sample on a plain body, and each policy is
  verified against policy-go with the teroscan engine only. It cannot express the severity guard
  (policy-go 1.12.1 treats a negated matcher on an absent field as no match, and the most restrictive
  policy wins), so `emit -format policy` refuses unless `-allow-no-severity-guard` is passed.
- **OpenSearch evidence is beta.** It is tested against OpenSearch and Dashboards 3.8.0 in kind, not yet
  across real clusters of other versions and layouts.
- **Measured bytes are not billed bytes.** Vendors bill on their own encoding. Compare the measured
  removal with the backend's own usage meters before and after enforcing.
- **OpenSearch evidence depends on the audit log.** The security plugin does not log successful
  requests by default, ignores `kibanaserver` by default, and keeps audit indices only as long as its
  retention allows. Each of these is reported as a gap. Queries stored by notebooks, reporting,
  anomaly detection and observability are not read, and saved queries can apply to any index pattern;
  both are gaps too.
- **Not yet connected as evidence sources:** other log services. A pipeline that also sends logs
  there reports those destinations as gaps until they are exempted.
