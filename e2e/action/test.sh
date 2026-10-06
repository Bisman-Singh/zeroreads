#!/usr/bin/env bash
# Runs the repository's GitHub Action with act against the e2e stack (after e2e/run.sh): it must pass,
# then fail with exit code 3 once a dashboard reads a removed template.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"
W=.e2e/act
mkdir -p "${W}"
sed 's#loki.zeroreads-system.svc:3100#host.docker.internal:13100#g; s#grafana.zeroreads-system.svc:3000#host.docker.internal:13000#g' e2e/action/zeroreads.yaml > "${W}/zeroreads.yaml"
cp .e2e/loop-user.yaml "${W}/collector.yaml"
cp .e2e/loop-out/rules.json "${W}/rules.json"
K="kubectl --kubeconfig .e2e/kubeconfig --context kind-zeroreads"
# shellcheck source=e2e/lib.sh
source "${ROOT}/e2e/lib.sh"
forward zeroreads-system loki 13100:3100
forward zeroreads-system grafana 13000:3000
trap 'curl -s -X DELETE "http://admin:e2e-only-password@localhost:13000/api/dashboards/uid/act-cache" >/dev/null || true; stop_forwards' EXIT # delete through the forward before closing it
sleep 3
# The action runs the released image. This checkout is built under a local name instead, and act runs a
# copy of the action that names it, so the release tag on this machine always means the released image.
docker build -q -t zeroreads/zeroreads:act . >/dev/null
mkdir -p "${W}/action"
sed 's#image: docker://.*#image: docker://zeroreads/zeroreads:act#' action.yml > "${W}/action/action.yml"
grep -q 'docker://zeroreads/zeroreads:act' "${W}/action/action.yml" || { echo "FAIL: the action's image line was not rewritten"; exit 1; }
sed "s#uses: ./\$#uses: ./${W}/action#" e2e/action/verify.yml > "${W}/verify.yml"
grep -q "uses: ./${W}/action" "${W}/verify.yml" || { echo "FAIL: the workflow does not use the local action copy"; exit 1; }
run() { act push -W "${W}/verify.yml" --bind --rm -P ubuntu-latest=node:20-bookworm-slim --pull=false 2>&1; } # --rm: the second run fails on purpose, and act keeps a failed job's container
out=$(run) || true
echo "${out}" | grep -q "Job succeeded" || { echo "${out}"; echo "FAIL: expected the action to pass"; exit 1; }
curl -sf -X POST "http://admin:e2e-only-password@localhost:13000/api/dashboards/db" -H 'Content-Type: application/json' \
  -d '{"overwrite":true,"dashboard":{"uid":"act-cache","title":"act cache","schemaVersion":41,"panels":[{"id":1,"type":"logs","datasource":{"type":"loki","uid":"loki"},"targets":[{"refId":"A","expr":"{service_name=\"checkout\"} |= \"cache hit\""}]}]}}' >/dev/null
out=$(run) || true
# shellcheck disable=SC2016 # the backquotes are act's own output, matched literally
echo "${out}" | grep -q 'exit with `FAILURE`: 3' || { echo "${out}"; echo "FAIL: expected exit code 3"; exit 1; }
echo "${out}" | grep -q 'dashboard:act-cache' || { echo "${out}"; echo "FAIL: expected the dashboard in the reasons"; exit 1; }
echo "PASS: the action passes on clean evidence and fails with exit code 3 on a new reader"
