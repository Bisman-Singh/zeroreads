#!/usr/bin/env bash
# Runs the repository's GitHub Action with act against the e2e stack (after e2e/run.sh): it must pass,
# then fail with exit code 3 once a dashboard reads a removed template.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"
W=.e2e/act
mkdir -p "${W}"
sed 's#http://loki.sievelog-system.svc:3100#http://host.docker.internal:13100#; s#http://grafana.sievelog-system.svc:3000#http://host.docker.internal:13000#' e2e/action/sievelog.yaml > "${W}/sievelog.yaml"
cp .e2e/loop-user.yaml "${W}/collector.yaml"
cp .e2e/loop-out/rules.json "${W}/rules.json"
K="kubectl --kubeconfig .e2e/kubeconfig --context kind-sievelog -n sievelog-system"
${K} port-forward svc/loki 13100:3100 >/dev/null 2>&1 & P1=$!
${K} port-forward svc/grafana 13000:3000 >/dev/null 2>&1 & P2=$!
trap 'kill ${P1} ${P2} 2>/dev/null || true; curl -s -X DELETE "http://admin:e2e-only-password@localhost:13000/api/dashboards/uid/act-cache" >/dev/null || true' EXIT
sleep 3
# The action runs the released image; build this checkout under that tag so act uses it locally.
IMAGE=$(sed -n 's#.*image: docker://##p' action.yml)
docker build -q -t "${IMAGE}" . >/dev/null
run() { act push -W e2e/action/verify.yml --bind -P ubuntu-latest=node:20-bookworm-slim --pull=false 2>&1; }
out=$(run) || true
echo "${out}" | grep -q "Job succeeded" || { echo "${out}"; echo "FAIL: expected the action to pass"; exit 1; }
curl -sf -X POST "http://admin:e2e-only-password@localhost:13000/api/dashboards/db" -H 'Content-Type: application/json' \
  -d '{"overwrite":true,"dashboard":{"uid":"act-cache","title":"act cache","schemaVersion":41,"panels":[{"id":1,"type":"logs","datasource":{"type":"loki","uid":"loki"},"targets":[{"refId":"A","expr":"{service_name=\"checkout\"} |= \"cache hit\""}]}]}}' >/dev/null
out=$(run) || true
# shellcheck disable=SC2016 # the backquotes are act's own output, matched literally
echo "${out}" | grep -q 'exit with `FAILURE`: 3' || { echo "${out}"; echo "FAIL: expected exit code 3"; exit 1; }
echo "${out}" | grep -q 'dashboard:act-cache' || { echo "${out}"; echo "FAIL: expected the dashboard in the reasons"; exit 1; }
echo "PASS: the action passes on clean evidence and fails with exit code 3 on a new reader"
