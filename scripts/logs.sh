#!/usr/bin/env bash
# hush's structured logs out of VictoriaLogs.
#
# VictoriaLogs has no read-path ingress (the only ingress, telemetry.threesix.ai,
# fronts vmauth-WRITE and is bearer-gated), and its NetworkPolicy admits only
# vector, vmauth-write, vmagent and grafana. So a laptop reads it through a
# port-forward, which goes node→apiserver→pod and bypasses the pod-to-pod policy.
#
# Usage:
#   ./scripts/logs.sh                            # hush, last hour
#   ./scripts/logs.sh 'service:hush level:error'  # any LogsQL
#   LIMIT=200 ./scripts/logs.sh 'service:hush category:secret'
set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/orchard9-k3sf.yaml}"
PORT="${PORT:-9428}"
QUERY="${1:-service:hush _time:1h}"
LIMIT="${LIMIT:-50}"

kubectl -n observability port-forward svc/victoria-logs "$PORT:9428" >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
for _ in $(seq 1 40); do
  curl -sf -o /dev/null -G "http://localhost:$PORT/select/logsql/query" \
    --data-urlencode 'query=*' --data-urlencode 'limit=1' && break
  sleep 0.25
done

curl -sS -G "http://localhost:$PORT/select/logsql/query" \
  --data-urlencode "query=$QUERY" --data-urlencode "limit=$LIMIT" \
  > /tmp/hush-logs.$$

python3 "$(dirname "$0")/format-logs.py" < /tmp/hush-logs.$$
rm -f /tmp/hush-logs.$$
