#!/usr/bin/env bash
# Build the current commit in-cluster and roll it out. No CI credential needed.
#
# Woodpecker IS activated for this repo, so a push to main builds and deploys.
# This is the path for when you do not want to wait for CI, when CI is down, or
# when you are rolling back — and it is how the first deploy happened, before
# activation. It does exactly what the pipeline's build and deploy steps do: a
# Kaniko Job for an amd64 image from the pushed git ref, then
# `kubectl set image`, then a real end-to-end check.
#
# Credentials: none. The Gitea repo is public so the Kaniko git context needs no
# token, and the rollout uses your kubeconfig.
#
#   ./scripts/release.sh
set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/orchard9-k3sf.yaml}"
NS="${NS:-projects}"
HOST="${HOST:-hush.threesix.ai}"
# The Gitea repo Kaniko clones, and the remote that points at it. Both are
# named once: the guard below has to check the ref that gets BUILT, and a
# guard that checks a different remote is worse than no guard.
GIT_CONTEXT="${GIT_CONTEXT:-git://git.threesix.ai/jordan/hush.git#refs/heads/main}"
GIT_REMOTE="${GIT_REMOTE:-origin}"
GIT_BRANCH="${GIT_BRANCH:-main}"
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
# `@{upstream}` is NOT the right comparison: this checkout tracks a mirror, so
# HEAD can be pushed there while Gitea — the repo Kaniko clones — is behind,
# and the build would silently produce the previous commit. Compare against the
# branch that actually gets built.
git fetch --quiet "$GIT_REMOTE" "$GIT_BRANCH"
if [ "$(git rev-parse HEAD)" != "$(git rev-parse FETCH_HEAD)" ]; then
  echo "refusing: HEAD is not what $GIT_REMOTE/$GIT_BRANCH points at, and Kaniko clones from there." >&2
  echo "  HEAD                    $(git rev-parse --short=8 HEAD) $(git log -1 --format=%s HEAD)" >&2
  echo "  $GIT_REMOTE/$GIT_BRANCH $(git rev-parse --short=8 FETCH_HEAD) $(git log -1 --format=%s FETCH_HEAD)" >&2
  echo "Push to $GIT_REMOTE first: git push $GIT_REMOTE $GIT_BRANCH" >&2
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
            - --context=$GIT_CONTEXT
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
