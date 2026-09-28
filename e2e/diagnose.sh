#!/usr/bin/env bash
# Prints what the e2e cluster and this machine looked like, for a failed run. It only reads, and
# names the e2e cluster's kubeconfig and context explicitly, like run.sh.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
K="kubectl --kubeconfig ${ROOT}/.e2e/kubeconfig --context kind-sievelog"
echo "== machine"
nproc 2>/dev/null || sysctl -n hw.ncpu
free -m 2>/dev/null || vm_stat
df -h /
echo "== node conditions"
${K} describe nodes | sed -n '/Conditions:/,/Addresses:/p'
echo "== pods"
${K} get pods -A -o wide
echo "== recent events"
${K} get events -A --sort-by=.lastTimestamp | tail -60
echo "== docker"
docker system df
