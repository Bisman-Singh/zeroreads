# shellcheck shell=bash
# Sourced by the e2e scripts, after they set K (kubectl with the e2e kubeconfig and context), so that
# nothing they start can reach anything but the kind cluster's stack.

# Helm applies HELM_KUBE* variables over --kube-context: an exported HELM_KUBEAPISERVER and
# HELM_KUBETOKEN would send an install to that server instead. Every one of them is dropped here.
for v in $(env | sed -n 's/^\(HELM_KUBE[A-Z_]*\)=.*/\1/p'); do unset "${v}"; done

# port_in_use PORT succeeds when something already accepts connections on the local PORT.
port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null || (exec 3<>"/dev/tcp/::1/$1") 2>/dev/null; }

# forward NAMESPACE SERVICE LOCAL:REMOTE keeps a port-forward to the kind cluster open and restarts it
# when it drops. A local port that is already taken is refused: the tests would talk to whatever holds
# it, a forward to a real Loki or Grafana for example, instead of the kind stack.
PFS=()
forward() {
  local port=${3%%:*}
  if port_in_use "${port}"; then
    echo "local port ${port} is already in use: free it, so that the tests reach only the kind cluster" >&2
    exit 1
  fi
  while true; do ${K} -n "$1" port-forward "svc/$2" "$3" >/dev/null 2>&1; sleep 1; done &
  PFS+=($!)
}
# stop_forwards ends each loop before its port-forward: killed the other way round, the loop could start
# a new port-forward that outlives the script.
stop_forwards() {
  local p kids
  for p in "${PFS[@]}"; do
    kids=$(pgrep -P "${p}" | tr '\n' ' ' || true)
    kill "${p}" 2>/dev/null || true
    # shellcheck disable=SC2086 # one PID per word
    [ -z "${kids// /}" ] || kill ${kids} 2>/dev/null || true
  done
}
