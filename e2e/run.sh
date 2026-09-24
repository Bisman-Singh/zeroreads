#!/usr/bin/env bash
# Runs the pipeline e2e on a dedicated kind cluster. Every kubectl call names the context
# explicitly; no other cluster is ever touched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER=sievelog
CTX="kind-${CLUSTER}"
WORK="${ROOT}/.e2e"
SEED="${SEED:-11}"
COUNT="${COUNT:-3000}"
SERVICES=(checkout auth orders)
COLLECTOR_IMAGE=otel/opentelemetry-collector-contrib:0.161.0
KUBECONFIG_E2E="${WORK}/kubeconfig" # never touches ~/.kube/config
K="kubectl --kubeconfig ${KUBECONFIG_E2E} --context ${CTX}"
# Each run gets its own namespace and the collector reads only that namespace's pod logs, so log
# files left behind by earlier runs can never be counted again.
RUN_NS="sievelog-gen-$(date +%s)"

log() { printf '[e2e] %s\n' "$*"; }

mkdir -p "${WORK}/out"

# REUSE=1 re-runs only the assertions against the stack and data of the previous run.
if [ "${REUSE:-0}" = "1" ]; then
  # shellcheck disable=SC1091
  source "${WORK}/last-run.env"
else

if ! kind get clusters | grep -qx "${CLUSTER}"; then
  log "creating kind cluster ${CLUSTER}"
  cat > "${WORK}/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: ${WORK}
        containerPath: /e2e
EOF
  kind create cluster --name "${CLUSTER}" --config "${WORK}/kind.yaml" --kubeconfig "${KUBECONFIG_E2E}" --wait 120s
fi
kind export kubeconfig --name "${CLUSTER}" --kubeconfig "${KUBECONFIG_E2E}" >/dev/null 2>&1

log "building loggen image"
( cd "${ROOT}" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${WORK}/loggen" ./cmd/loggen )
cat > "${WORK}/Dockerfile" <<'EOF'
FROM scratch
COPY loggen /loggen
ENTRYPOINT ["/loggen"]
EOF
docker build -q -t sievelog/loggen:e2e "${WORK}" >/dev/null
kind load docker-image --name "${CLUSTER}" sievelog/loggen:e2e >/dev/null
log "building sievelog image"
docker build -q -t sievelog/sievelog:e2e "${ROOT}" >/dev/null
kind load docker-image --name "${CLUSTER}" sievelog/sievelog:e2e >/dev/null
# The multi-platform collector image fails "kind load" (ctr digest not found); the node pulls it.

log "resetting previous run"
for ns in $(${K} get ns -o name | grep '^namespace/sievelog-gen' || true); do ${K} delete "${ns}" --wait=true >/dev/null; done
${K} delete daemonset collector -n sievelog-system --ignore-not-found --wait=true >/dev/null
${K} wait --for=delete pod -l app=collector -n sievelog-system --timeout=60s >/dev/null 2>&1 || true
rm -f "${WORK}/out/"*.json

log "deploying loki"
${K} apply -f "${ROOT}/e2e/k8s/collector.yaml" >/dev/null # creates the namespace
${K} apply -f "${ROOT}/e2e/k8s/loki.yaml" >/dev/null
${K} rollout restart deployment/loki -n sievelog-system >/dev/null
${K} rollout status deployment/loki -n sievelog-system --timeout=180s >/dev/null

log "deploying grafana"
${K} apply -f "${ROOT}/e2e/k8s/grafana.yaml" >/dev/null
${K} rollout restart deployment/grafana -n sievelog-system >/dev/null
${K} rollout status deployment/grafana -n sievelog-system --timeout=240s >/dev/null

log "deploying opensearch"
${K} apply -f "${ROOT}/e2e/k8s/opensearch.yaml" >/dev/null
# A fresh cluster every run: audit indices and scale data from earlier runs would otherwise pile up.
${K} rollout restart deployment/opensearch deployment/opensearch-dashboards -n sievelog-system >/dev/null
${K} rollout status deployment/opensearch -n sievelog-system --timeout=600s >/dev/null
${K} rollout status deployment/opensearch-dashboards -n sievelog-system --timeout=900s >/dev/null

log "deploying vector and fluent bit"
${K} -n sievelog-system create configmap vector-config --from-file=vector.yaml="${ROOT}/e2e/runtimes/vector.yaml" --dry-run=client -o yaml | ${K} apply -f - >/dev/null
${K} -n sievelog-system create configmap fluent-bit-config --from-file=fluent-bit.yaml="${ROOT}/e2e/runtimes/fluent-bit.yaml" --dry-run=client -o yaml | ${K} apply -f - >/dev/null
${K} apply -f "${ROOT}/e2e/k8s/vector.yaml" -f "${ROOT}/e2e/k8s/fluent-bit.yaml" >/dev/null
${K} rollout restart daemonset/vector daemonset/fluent-bit -n sievelog-system >/dev/null
${K} rollout status daemonset/vector -n sievelog-system --timeout=300s >/dev/null
${K} rollout status daemonset/fluent-bit -n sievelog-system --timeout=300s >/dev/null

log "deploying collector"
# Only the current Loki pod's logs: kubelet keeps earlier pods' log files, and their query-log
# lines would otherwise be re-shipped as usage evidence from a previous run.
LOKI_POD=$(${K} get pods -n sievelog-system -l app=loki --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')
( cd "${ROOT}" && go run ./e2e/render "${RUN_NS}" "${LOKI_POD}" ) > "${WORK}/config.yaml"
docker run --rm -v "${WORK}:/cfg" "${COLLECTOR_IMAGE}" validate --config=/cfg/config.yaml
${K} apply -f "${ROOT}/e2e/k8s/collector.yaml" >/dev/null
${K} create namespace "${RUN_NS}" >/dev/null
${K} create configmap collector-config -n sievelog-system --from-file=config.yaml="${WORK}/config.yaml" \
  --dry-run=client -o yaml | ${K} apply -f - >/dev/null
${K} rollout restart daemonset/collector -n sievelog-system >/dev/null
${K} rollout status daemonset/collector -n sievelog-system --timeout=120s >/dev/null

log "running generators (seed=${SEED}, count=${COUNT} per service)"
for s in "${SERVICES[@]}"; do
  cat <<EOF | ${K} apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: gen-${s}
  namespace: ${RUN_NS}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: ${s}
          image: sievelog/loggen:e2e
          imagePullPolicy: Never
          args: ["--service=${s}", "--seed=${SEED}", "--count=${COUNT}", "--rate=2000"]
EOF
done
for s in "${SERVICES[@]}"; do
  ${K} wait --for=condition=complete job/gen-${s} -n "${RUN_NS}" --timeout=120s >/dev/null
done

want=$(( COUNT * ${#SERVICES[@]} ))
log "waiting for ${want} records in the collector output"
for _ in $(seq 1 60); do
  got=$(python3 - "${WORK}/out/logs.json" <<'EOF'
import json,sys
n=0
try:
    for line in open(sys.argv[1]):
        d=json.loads(line)
        for rl in d.get("resourceLogs",[]):
            for sl in rl.get("scopeLogs",[]):
                n+=len(sl.get("logRecords",[]))
except FileNotFoundError:
    pass
print(n)
EOF
)
  [ "${got}" -ge "${want}" ] && break
  sleep 2
done
log "collector wrote ${got} records"
sleep 3 # let the metrics file flush the last payloads

printf 'SEED=%s\nCOUNT=%s\nRUN_NS=%s\n' "${SEED}" "${COUNT}" "${RUN_NS}" > "${WORK}/last-run.env"
fi

log "port-forwarding loki"
${K} -n sievelog-system port-forward svc/loki 13100:3100 >/dev/null 2>&1 &
PF=$!
${K} -n sievelog-system port-forward svc/grafana 13000:3000 >/dev/null 2>&1 &
PF2=$!
${K} -n sievelog-system port-forward svc/opensearch 19200:9200 >/dev/null 2>&1 &
PF3=$!
${K} -n sievelog-system port-forward svc/opensearch-dashboards 15601:5601 >/dev/null 2>&1 &
PF4=$!
trap 'kill ${PF} ${PF2} ${PF3} ${PF4} 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -sf localhost:13100/ready >/dev/null && break; sleep 1; done
for _ in $(seq 1 30); do curl -sf localhost:13000/api/health >/dev/null && break; sleep 1; done
for _ in $(seq 1 30); do curl -skf -u 'admin:E2e-only-Passw0rd!' https://localhost:19200/ >/dev/null && break; sleep 1; done
for _ in $(seq 1 60); do curl -sf -u 'admin:E2e-only-Passw0rd!' localhost:15601/api/status >/dev/null && break; sleep 1; done

log "running assertions"
( cd "${ROOT}" && E2E_OUT="${WORK}/out" E2E_SEED="${SEED}" E2E_COUNT="${COUNT}" LOKI_URL="http://localhost:13100" GRAFANA_URL="http://localhost:13000" OPENSEARCH_URL="https://localhost:19200" DASHBOARDS_URL="http://localhost:15601" OPENSEARCH_PASSWORD='E2e-only-Passw0rd!' E2E_WORK="${WORK}" E2E_NS="${RUN_NS}" \
  go test -tags e2e ./e2e/ -count=1 -v -timeout 30m ${E2E_RUN:+-run "${E2E_RUN}"} )
