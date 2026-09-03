#!/usr/bin/env bash
# Confirm vmalert has LOADED hush's rules and can evaluate them.
#
# Reading the ConfigMap is not verification: vmalert has no auto-discovery, so a
# rules file can be applied and committed and still be absent because
# victoria-metrics.yaml lacks the matching -rule=, volumeMount and volume. This
# asks vmalert what it actually has.
#
# It also checks each rule's series EXISTS. A rule whose expression references a
# metric nothing exports is a rule that can never fire, which reads identically
# to a healthy service.
set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/orchard9-k3sf.yaml}"

kubectl -n observability port-forward svc/vmalert 8880:8880 >/dev/null 2>&1 &
PFA=$!
kubectl -n observability port-forward svc/vmsingle 8428:8428 >/dev/null 2>&1 &
PFS=$!
trap 'kill $PFA $PFS 2>/dev/null || true' EXIT
sleep 3

echo "=== rules vmalert has loaded for hush ==="
curl -sS http://localhost:8880/api/v1/rules \
| python3 -c '
import json, sys
d = json.load(sys.stdin)
groups = [g for g in d["data"]["groups"] if g["name"] == "hush"]
if not groups:
    print("  NO hush group loaded — check the -rule=, volumeMount and volume in victoria-metrics.yaml")
    sys.exit(1)
for g in groups:
    print("  group {} (file {})".format(g["name"], g.get("file", "?")))
    for r in g["rules"]:
        print("    {:32} state={:8} health={} for={}".format(
            r.get("name", "?"), r.get("state", "?"), r.get("health", "?"), r.get("duration", "?")))
        if r.get("lastError"):
            print("      lastError:", r["lastError"])
'

echo
echo "=== do the series each rule reads actually exist? ==="
for metric in hush_store_up hush_secrets_created_total hush_secrets_revealed_total \
              hush_secrets_rejected_total hush_rate_limited_total http_requests_total; do
  n=$(curl -sS -G http://localhost:8428/prometheus/api/v1/query \
        --data-urlencode "query=count(${metric}{service=\"hush\"}) or count(${metric})" \
      | python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(int(float(r[0]["value"][1])) if r else 0)')
  if [ "$n" -gt 0 ]; then printf '  ok   %-32s %s series\n' "$metric" "$n"
  else printf '  MISSING %-29s 0 series — a rule on this can never fire\n' "$metric"; fi
done
