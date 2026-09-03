#!/usr/bin/env bash
# Build the current commit in-cluster and roll it out. No CI credential needed.
#
# This exists because Woodpecker is not activated for this repo (its API token
# in rdev returns 401, and minting a new one needs a browser login). Rather than
# leave "git push does not deploy" as a trap for whoever pushes next, this does
# exactly what the pipeline's build+deploy steps do: a Kaniko Job for an amd64
# image, then `kubectl set image`, then a real end-to-end check.
#
# When Woodpecker is activated this becomes redundant, and that is fine — it is
# also the manual path for a rollback or a hotfix when CI is down.
#
#   ./scripts/release.sh
set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/orchard9-k3sf.yaml}"
NS="${NS:-projects}"
HOST="${HOST:-hush.threesix.ai}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Kaniko builds from the GIT CONTEXT, not from this working tree. So a dirty or
# unpushed tree would silently build something other than what you are looking
# at — the single most confusing failure this script can have. Refuse instead.
if [ -n "$(git status --porcelain)" ]; then
  echo "refusing: working tree is dirty. Kaniko builds from the pushed git ref," >&2
  echo "so uncommitted changes would NOT be in the image." >&2
  git status --short >&2
  exit 1
fi
if [ -n "$(git log --oneline @{upstream}..HEAD 2>/dev/null)" ]; then
  echo "refusing: HEAD is not pushed to origin (Gitea). Kaniko clones from there." >&2
  git log --oneline '@{upstream}..HEAD' >&2
  exit 1
fi

SHA="$(git rev-parse --short=8 HEAD)"
IMAGE="registry.threesix.ai/hush/api:$SHA"
JOB="hush-build-$SHA"
echo "releasing $SHA"

# A previous attempt at the same SHA leaves a completed Job that cannot be
# re-created; replacing it is the idempotent thing to do.
kubectl -n "$NS" delete job "$JOB" --ignore-not-found >/dev/null

kubectl -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: $JOB
  labels: { app: hush, component: build }
spec:
  backoffLimit: 1
  ttlSecondsAfterFinished: 3600
  template:
    metadata:
      labels: { app: hush, component: build }
    spec:
      restartPolicy: Never
      containers:
        - name: kaniko
          image: gcr.io/kaniko-project/executor:v1.23.2
          args:
            # The Gitea repo is public, so the git context needs no credential.
            - --context=git://git.threesix.ai/jordan/hush.git#refs/heads/main
            - --dockerfile=Dockerfile
            - --destination=$IMAGE
            # The internal Zot registry serves a self-signed cert.
            - --skip-tls-verify
            - --skip-tls-verify-pull
            - --single-snapshot
          resources:
            requests: { cpu: 500m, memory: 1Gi }
            limits: { cpu: "2", memory: 3Gi }
EOF

echo "  building (amd64, in-cluster)…"
if ! kubectl -n "$NS" wait --for=condition=complete "job/$JOB" --timeout=900s >/dev/null 2>&1; then
  echo "build FAILED — last lines:" >&2
  kubectl -n "$NS" logs "job/$JOB" --tail=30 >&2
  exit 1
fi
echo "  built $IMAGE"

kubectl -n "$NS" set image deployment/hush "hushd=$IMAGE" >/dev/null
kubectl -n "$NS" rollout status deployment/hush --timeout=180s | sed 's/^/  /'

# Prove the rolled pod is the image we just built. `set image` matching nothing
# is silent, and the rollout would "succeed" on the old pod.
LIVE="$(kubectl -n "$NS" get deployment hush -o jsonpath='{.spec.template.spec.containers[0].image}')"
[ "$LIVE" = "$IMAGE" ] || { echo "live image is $LIVE, expected $IMAGE" >&2; exit 1; }
echo "  live image: $LIVE"

echo
echo "verifying end to end against https://$HOST"
BASE="https://$HOST" "$ROOT/scripts/smoke.sh"
