# Deploying hush

Live at <https://hush.threesix.ai>, one replica in the `projects` namespace on
the orchard9 k3s cluster.

```
git push origin main → Gitea webhook → Woodpecker → Kaniko (amd64, in-cluster)
  → Zot registry → kubectl set image → projects/hush
```

`origin` **must** be Gitea (`git.threesix.ai`); that remote carries the webhook.
The GitHub mirror is a backup and pushing there deploys nothing.

## Never build the image locally

Two reasons, both of which cost real time to discover:

1. A laptop build on Apple Silicon produces **arm64**; the cluster runs amd64.
2. `registry.threesix.ai` accepts **only OCI image manifests** — not Docker
   schema2, and not an OCI *index*. `docker push` and `crane push` both fail
   `MANIFEST_INVALID`, and buildx wraps even a single-platform build in an index.

Kaniko sidesteps both. If you must build outside the pipeline, use a Job — see
"Bootstrap" below, which is exactly what the first deploy did.

## Dependencies are vendored, deliberately

`github.com/orchard9/go-chassis` is a **private** module. Neither the Woodpecker
test container nor the Kaniko build holds a git credential, so a build that
resolved dependencies from the network would fail:

```
$ curl https://proxy.golang.org/github.com/orchard9/go-chassis/@v/list
404  ... could not read Username for 'https://github.com'
```

So `vendor/` is committed and both CI and the Dockerfile run `-mod=vendor` with
`GOPROXY=off`. `GOPROXY=off` is the important half: it turns "silently fetched
from somewhere" into a hard failure. `make vendor` is the only way versions
move, and `make verify` proves the tree still builds with no network.

## One-time setup, already done

Recorded because it is what a rebuild would need, and none of it is in git.

### 1. Redis ACL user

hush connects as its own ACL user, scoped to `~hush:*`, on **db 5** (0 and 3 and
4 are taken by pantheon/rdev, reel, and jit):

```bash
redis-cli ACL SETUSER hush on '>PASSWORD' '~hush:*' resetchannels \
  -@all +ping +set +getdel +incr +pexpire +pttl +select
redis-cli ACL SAVE     # persists to /data/users.acl
```

**`+getdel` is the one to notice.** No other service's ACL user has it, because
no other service needs an atomic read-and-destroy. Omit it and creates keep
working while every reveal fails `NOPERM` — a service that accepts secrets and
cannot deliver them. `+incr +pexpire +pttl` are the rate limiter.

### 2. The credential

A JSON object in GCP Secret Manager, pulled into the namespace by ESO:

```bash
gcloud secrets create k3sf-hush-credentials --project orchard9 \
  --replication-policy=automatic --data-file=- <<< \
  '{"REDIS_URL":"redis://hush:PASSWORD@redis.databases.svc.cluster.local:6379/5"}'
```

`ExternalSecret/hush-credentials` (in `deployments/k8s/hush.yaml`) syncs it to a
Secret of the same name. Confirm with:

```bash
kubectl -n projects get externalsecret hush-credentials \
  -o jsonpath='{.status.conditions[0].reason}'   # want SecretSynced
```

### 3. DNS

`hush.threesix.ai` → `208.122.204.172`, A record, **DNS-only** (not proxied),
TTL 120 — matching every other `*.threesix.ai` service. There is no wildcard on
the zone, so each host needs its own record. cert-manager then issues TLS over
HTTP-01 with no DNS credential needed.

> `hush.orchard9.ai` was the original intent and is **not** what shipped.
> `orchard9.ai` is on GoDaddy and no GoDaddy credential exists in rdev, the
> cluster, or `~/.squiddy-dns`. Moving the host there needs that credential;
> everything else is a one-line Ingress change plus a new record.

### 4. Alert rules

vmalert has **no ConfigMap auto-discovery**. Three coordinated edits in
`orchard9-k3sf`, and missing any one leaves the rules silently absent:

1. `observability/hush-alerting-rules.yaml` — the ConfigMap
2. `observability/kustomization.yaml` — list it under `resources:`
3. `observability/victoria-metrics.yaml` — vmalert needs a matching
   `-rule=/etc/rules-hush/*.yaml`, `volumeMount` and `volume`

`make alerts-check` asks vmalert what it actually loaded, and separately checks
that every series the rules reference exists — a rule reading a metric nothing
exports can never fire and looks exactly like a healthy service.

## Bootstrap (what the first deploy did)

The pipeline's deploy step runs `kubectl set image`, so a Deployment must exist
first. But the committed image tag cannot be `:latest`: the cluster's
`stable-controller-images.orchard9.ai` admission policy refuses
`latest|main|master|dev|edge|canary|nightly|snapshot`, because a floating tag
cannot pin a rollback.

So the manifest carries `:bootstrap`, which is policy-legal and does not exist.
Apply it, then build once by hand:

```bash
make deploy-manifests        # pod sits in ImagePullBackOff — expected

SHA=$(git rev-parse --short=8 HEAD)
kubectl -n projects create job hush-build-$SHA --dry-run=client -o yaml ... # see below
kubectl -n projects set image deployment/hush hushd=registry.threesix.ai/hush/api:$SHA
```

The build Job, which is what Woodpecker's Kaniko step does by hand:

```yaml
apiVersion: batch/v1
kind: Job
metadata: { name: hush-build, namespace: projects }
spec:
  backoffLimit: 1
  ttlSecondsAfterFinished: 3600
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: kaniko
          image: gcr.io/kaniko-project/executor:v1.23.2
          args:
            - --context=git://git.threesix.ai/jordan/hush.git#refs/heads/main
            - --dockerfile=Dockerfile
            - --destination=registry.threesix.ai/hush/api:SHA
            - --skip-tls-verify
            - --skip-tls-verify-pull
            - --single-snapshot
          resources:
            requests: { cpu: 500m, memory: 1Gi }
            limits: { cpu: "2", memory: 3Gi }
```

The git context needs no credential because the Gitea repo is public.

## Woodpecker is NOT yet activated

The repo exists on Gitea and `.woodpecker.yml` is committed, but activation
failed: the `WOODPECKER_API_TOKEN` in `rdev/rdev-credentials` returns
`401 User not authorized`.

Until a valid token replaces it, **pushes do not deploy** — use the Kaniko Job
above and `kubectl set image`. To finish it:

```bash
WP=$(curl -s -H "X-API-Key: $RDEV_API_KEY" "$RDEV_API_URL/credentials/WOODPECKER_API_TOKEN" | jq -r '.data.value')
curl -X POST "https://ci.threesix.ai/api/repos?forge_remote_id=jordan/hush" -H "Authorization: Bearer $WP"
```

A fresh token comes from Woodpecker → User Settings → Token, and belongs back in
rdev rather than anywhere else.

## Rollback

Every build is SHA-tagged, so rollback is naming the previous one:

```bash
kubectl -n projects rollout undo deployment/hush
# or explicitly
kubectl -n projects set image deployment/hush hushd=registry.threesix.ai/hush/api:<older-sha>
```

Nothing to migrate and no schema: Redis holds only TTL'd ciphertext, and a
rollback cannot invalidate an outstanding link because the id and the wire
format are stable.

## Verifying a deploy

```bash
make deploy-status                       # rollout, pods, ingress, certificate
BASE=https://hush.threesix.ai make smoke  # real crypto, create → reveal → gone
make logs                                # the lifecycle in VictoriaLogs
make alerts-check                        # rules loaded, series present
```

`make smoke` is the one that matters. It encrypts with a real AES-256-GCM key,
posts only ciphertext, reveals once, decrypts, and then asserts the second
reveal is `410`, that three `GET`s did not consume the secret, that missing and
malformed ids are indistinguishable, and that a plaintext field is refused.
