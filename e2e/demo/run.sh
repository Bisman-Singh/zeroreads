#!/usr/bin/env bash
# Runs zeroreads against the OpenTelemetry demo, a multi-service app with its own load generator, on
# the e2e kind cluster: the demo's own Collector sends its logs to the e2e Loki, readers written for
# the app are stored in a Grafana org of their own, and zeroreads analyses, shadows and enforces
# inside that Collector. It needs a finished ./e2e/run.sh (the cluster and its stack). Every kubectl
# and helm call names the e2e kubeconfig and context; no other cluster is touched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${ROOT}/.e2e/demo"
KUBECONFIG_E2E="${ROOT}/.e2e/kubeconfig"
CTX=kind-zeroreads
NS=zeroreads-demo
K="kubectl --kubeconfig ${KUBECONFIG_E2E} --context ${CTX}"
H="helm --kubeconfig ${KUBECONFIG_E2E} --kube-context ${CTX}"
# shellcheck source=e2e/lib.sh
source "${ROOT}/e2e/lib.sh"
CHART_VERSION=0.42.1
CHART_SHA256=1f10de3d899fc36385c1b624793c95bc9cd86e436ef728f63f22e1728aeec777
BASELINE="${DEMO_BASELINE:-1800}" # seconds of traffic before the analysis
# Evidence covers the readers, which run just before the analysis, and not the setup: a query run to
# check the setup (say, every line of the namespace) is a reader like any other and would block every
# rule. DEMO_REUSE=1 keeps an installed demo, its traffic and the demo itself when it ends.
EVIDENCE="${DEMO_EVIDENCE:-600}"
SHADOW="${DEMO_SHADOW:-900}"
ENFORCE="${DEMO_ENFORCE:-900}"
GRAFANA_PASSWORD='e2e-only-password'
BIN="${WORK}/zeroreads"

log() { printf '[demo] %s %s\n' "$(date +%H:%M:%S)" "$*"; }
iso() { python3 -c 'import datetime,sys;print(datetime.datetime.fromtimestamp(int(sys.argv[1]),datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$1"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

mkdir -p "${WORK}/out"
${K} -n zeroreads-system get deployment/loki deployment/grafana >/dev/null

log "chart opentelemetry-demo ${CHART_VERSION}, checked against its SHA-256"
CHART="${WORK}/opentelemetry-demo-${CHART_VERSION}.tgz"
[ -f "${CHART}" ] || curl -fsSLo "${CHART}" "https://github.com/open-telemetry/opentelemetry-helm-charts/releases/download/opentelemetry-demo-${CHART_VERSION}/opentelemetry-demo-${CHART_VERSION}.tgz"
echo "${CHART_SHA256}  ${CHART}" | sha256 -c - >/dev/null

restore() {
  local rc=$?
  if [ "${rc}" = 0 ] && [ "${DEMO_KEEP:-${DEMO_REUSE:-0}}" != "1" ]; then
    # the readers' org goes with the demo, while the forward to Grafana is still open
    python3 "${ROOT}/e2e/demo/readers.py" http://localhost:13000 http://localhost:13100 "${GRAFANA_PASSWORD}" remove ||
      log "could not empty the readers' Grafana org"
  fi
  stop_forwards
  if [ "${rc}" != 0 ]; then
    log "failed (exit ${rc}): the demo stays installed to look at; DEMO_REUSE=1 runs again on it"
    return
  fi
  if [ "${DEMO_KEEP:-${DEMO_REUSE:-0}}" != "1" ]; then
    ${H} -n "${NS}" uninstall demo >/dev/null 2>&1 || true
    ${K} delete namespace "${NS}" --wait=false >/dev/null 2>&1 || true
    ${K} -n zeroreads-system scale deployment/opensearch deployment/opensearch-dashboards --replicas=1 >/dev/null 2>&1 || true
  fi
}
trap restore EXIT

log "OpenSearch is not an evidence source here: scaled to zero to make room"
${K} -n zeroreads-system scale deployment/opensearch deployment/opensearch-dashboards --replicas=0 >/dev/null

if [ "${DEMO_REUSE:-0}" != "1" ]; then
  log "installing the demo into ${NS}"
  ${H} upgrade --install demo "${CHART}" -n "${NS}" --create-namespace -f "${ROOT}/e2e/demo/values.yaml" --wait --timeout 30m >/dev/null
fi
${K} -n "${NS}" get pods --no-headers | awk '{print $3}' | sort | uniq -c | sed 's/^/[demo]   /'

forward zeroreads-system loki 13100:3100
forward zeroreads-system grafana 13000:3000
for url in localhost:13100/ready localhost:13000/api/health; do
  for _ in $(seq 1 120); do curl -sf "${url}" >/dev/null && break; sleep 1; done
done

if [ "${DEMO_REUSE:-0}" != "1" ]; then
  log "baseline: ${BASELINE}s of the load generator's traffic"
  sleep "${BASELINE}"
fi

log "readers written for the app: a Grafana org with dashboards and an alert, and ad-hoc queries"
TOKEN=$(python3 "${ROOT}/e2e/demo/readers.py" http://localhost:13000 http://localhost:13100 "${GRAFANA_PASSWORD}")
export DEMO_GRAFANA_TOKEN="${TOKEN}"
sleep 60 # the ad-hoc queries reach the query log

log "analyze"
( cd "${ROOT}" && go build -o "${BIN}" ./cmd/zeroreads )
[ "${DEMO_REUSE:-0}" = "1" ] || ${K} -n "${NS}" get configmap otel-collector -o jsonpath='{.data.relay}' > "${WORK}/collector.yaml"
# The app's own services, as they appear in Loki; Loki's own logs are evidence, not the app.
SERVICES=$(curl -sf "localhost:13100/loki/api/v1/label/service_name/values" --data-urlencode "query={k8s_namespace_name=\"${NS}\"}" \
  --data-urlencode "start=$(( ($(date +%s) - BASELINE) * 1000000000 ))" | python3 -c 'import json,sys;print(", ".join(json.load(sys.stdin)["data"]))')
log "services: ${SERVICES}"
cat > "${WORK}/zeroreads.yaml" <<EOF
loki:
  url: http://localhost:13100
scope:
  otel_attribute: service.name
  loki_label: service_name
  services: [${SERVICES}]
discovery:
  window: ${BASELINE}s
evidence:
  window: ${EVIDENCE}s
  query_log: {enabled: true, selector: '{service_name="loki"}', prove_live: true}
  ruler: true
  grafana:
    - url: http://localhost:13000
      token_env: DEMO_GRAFANA_TOKEN
      datasources: [demo-loki]
collector:
  config_files: [${WORK}/collector.yaml]
  pipeline: logs
  after: transform/sanitize_logs
  measure_exporters: [file/zeroreads]
  aggregate_exporters: [file/zeroreads]
  sinks:
    otlp_http/loki: {loki: true}
policy:
  acknowledge: ["grafana-orgs:localhost:13000", "grafana-queryhistory:localhost:13000"]
EOF
( cd "${WORK}" && "${BIN}" analyze -c zeroreads.yaml -o out ) | tail -3

# The Collector writes zeroreads's measurement, as delta sums, to the e2e host mount.
MEASURE="${ROOT}/.e2e/out/demo-metrics.json"
measured() { # copy to: fails unless the Collector has measured something
  for _ in $(seq 1 30); do
    grep -q 'zeroreads.rule.lines' "${MEASURE}" 2>/dev/null && cp "${MEASURE}" "$1" && return 0
    sleep 2
  done
  log "no zeroreads measurement from the Collector in ${MEASURE}"
  return 1
}
deploy() { # config file
  ${K} -n "${NS}" create configmap otel-collector --from-file=relay="$1" --dry-run=client -o yaml | ${K} apply -f - >/dev/null
  ${K} -n "${NS}" rollout restart deployment/otel-collector >/dev/null
  ${K} -n "${NS}" rollout status deployment/otel-collector --timeout=300s >/dev/null
  sleep 5
}
loki_total() { # function (count_over_time or bytes_over_time), window seconds, at unix time
  curl -sf "localhost:13100/loki/api/v1/query" --data-urlencode "query=sum($1({k8s_namespace_name=\"${NS}\"}[$2s]))" \
    --data-urlencode "time=$3" | python3 -c 'import json,sys;r=json.load(sys.stdin)["data"]["result"];print(r[0]["value"][1] if r else 0)'
}

log "shadow: ${SHADOW}s measuring what enforcement would remove"
( cd "${WORK}" && "${BIN}" emit -c zeroreads.yaml -rules out/rules.json -mode shadow -o shadow.yaml )
rm -f "${MEASURE}"
deploy "${WORK}/shadow.yaml"
S0=$(date +%s)
sleep 30
measured "${WORK}/metrics-check.json" # fail within a minute, not after the whole window
sleep $((SHADOW - ($(date +%s) - S0)))
S1=$(date +%s)
measured "${WORK}/metrics-shadow.json"

log "enforce: ${ENFORCE}s"
( cd "${WORK}" && "${BIN}" emit -c zeroreads.yaml -rules out/rules.json -mode enforce -o enforce.yaml )
deploy "${WORK}/enforce.yaml"
E0=$(date +%s); sleep "${ENFORCE}"; E1=$(date +%s)
sleep 30 # the last batches reach Loki

# verify first: every query after it (reconcile's, the totals below) would be a reader of its own.
log "verify and reconcile"
set +e
( cd "${WORK}" && "${BIN}" verify -c zeroreads.yaml -rules out/rules.json -deployed enforce.yaml -json verify.json >/dev/null )
echo $? > "${WORK}/verify.exit"
set -e
( cd "${WORK}" && "${BIN}" reconcile -c zeroreads.yaml -rules out/rules.json -before "$(iso "${S0}"),$(iso "${S1}")" \
  -after "$(iso "${E0}"),$(iso "${E1}")" -o reconcile.json >/dev/null ) || true

python3 - "${WORK}/totals.json" "$((S1 - S0))" "$((E1 - E0))" \
  "$(loki_total count_over_time $((S1 - S0)) "${S1}")" "$(loki_total bytes_over_time $((S1 - S0)) "${S1}")" \
  "$(loki_total count_over_time $((E1 - E0)) "${E1}")" "$(loki_total bytes_over_time $((E1 - E0)) "${E1}")" <<'EOF'
import json, sys
out, ss, es, sl, sb, el, eb = sys.argv[1:]
json.dump({"shadow_seconds": int(ss), "enforce_seconds": int(es), "shadow_lines": float(sl), "shadow_bytes": float(sb),
           "enforce_lines": float(el), "enforce_bytes": float(eb)}, open(out, "w"))
EOF

python3 "${ROOT}/e2e/demo/summary.py" "${WORK}" | tee "${WORK}/results.md"
