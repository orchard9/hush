# Operating hush

hush is a stateless Go process in front of TTL'd Redis keys. There is no
schema, no queue, no background worker and no durable state of its own, so
almost every incident is one of: Redis is unreachable, the pod is not being
scraped, or someone is abusing anonymous create.

## Reading the logs

```bash
make logs                                          # hush, last hour
./scripts/logs.sh 'service:hush level:error'
./scripts/logs.sh 'service:hush category:secret'   # the create/reveal/gone lifecycle
./scripts/logs.sh 'service:hush sid:fb26b024452a'  # one secret, end to end
```

Vector collects pod stdout cluster-wide with no annotation, so hush's JSON lands
in VictoriaLogs automatically. Indexed stream fields are `service`, `level`,
`host`, `unit` — everything else (`request_id`, `sid`, `category`, `error_type`)
is exact-match queryable and deliberately not indexed.

`level` is lowercase in the corpus. `{level="ERROR"}` matches nothing.

### `sid`, and why no id is ever logged

The secret id is the capability: anyone holding it can reveal the secret. It is
never logged. The correlation handle is `sid = sha256(id)[:12]`, which follows
one secret across `secret.created` → `secret.revealed` → `secret.gone` and is
useless for opening it.

Verified rather than asserted: creating a secret and searching the whole corpus
for its raw id returns zero hits, while its `sid` returns the lifecycle. If you
ever see a 43-character base64url string in a hush log line, that is a **P1
capability leak** — the id type is built so it cannot happen (see
`internal/secret/id.go`) and a regression means someone added a `Value()` call
at a log site.

## Alerts

Routing (`alertmanager.yaml`): `critical` and `high` reach Discord **and** open a
Pantheon incident; `warning` is Discord only.

### HushRedisUnreachable — critical

`hush_store_up == 0` for 2m. hush can neither store nor deliver a secret;
readiness fails and the pod has left the Service.

Nothing is lost — Redis owns the secrets and hush fails closed — but the URL is
down. In order:

```bash
kubectl -n databases get pod -l app=redis          # is Redis up?
kubectl -n projects logs -l app=hush --tail=50     # what does hushd say?
kubectl -n databases exec redis-0 -- redis-cli --no-auth-warning -a "$PW" ACL LIST | grep hush
```

That last check matters more than it looks: the Redis pod's init container
reconciles the `default` ACL user on every start. If a change ever dropped the
`hush` user, or dropped `+getdel` from it, the symptom is identical to an
outage — and a missing `+getdel` specifically breaks *only* reveal while create
keeps succeeding, so the service looks half-healthy.

### HushMetricsAbsent — high

`absent(hush_store_up)` for 10m. Every other rule reads a hush metric, so
absence silently disables the whole group.

Most likely cause is not a dead pod but a **dropped scrape target**. vmagent
gates on `prometheus.io/scrape=true` AND a `prometheus.io/port` that *equals* a
declared `containerPort` — via `keepequal`, which drops a mismatch **silently**:
no error, no `up=0`, the target simply never appears.

```bash
kubectl -n projects get pod -l app=hush -o jsonpath='{.items[0].metadata.annotations}'
kubectl -n projects get pod -l app=hush -o jsonpath='{.items[0].spec.containers[0].ports}'
# the annotation value and the containerPort number must be identical strings
```

Then confirm the NetworkPolicy still admits `observability` on 18500; without
it vmagent discovers the target and every scrape is connection-refused.

### Hush5xxRateHigh — warning

>5% 5xx over 15m on non-trivial traffic. A 5xx means a secret was
accepted-but-not-stored, or a reveal failed **without** destroying the secret.
Neither loses data, but a caller who saw a 500 on create does not know whether
their link exists. Check `error_type` in the logs.

### HushRateLimitSustained — warning

Steady create refusals for 30m. hush is anonymous-create by design, so this is
how bulk automation shows up; a single user retrying cannot sustain it, because
the limit is per IP.

If it is abuse rather than a busy NAT:

```bash
kubectl -n projects set env deployment/hush HUSH_REQUIRE_AUTH=true HUSH_CREATE_TOKEN=<token>
```

Reveal stays anonymous either way — the recipient is external and holds no
credential. That asymmetry is the design, not an oversight.

### HushCreateRejectionsHigh — warning

More than half of creates failing validation. Break down by reason:

```bash
./scripts/logs.sh 'service:hush level:warn' 
# or in Grafana: hush_secrets_rejected_total by (reason)
```

`ciphertext_invalid` in bulk means a client is posting something that is not
base64url — either a broken page deploy or someone treating hush as a plaintext
API. `ciphertext_too_large` means someone is trying to use it as a file host.

## Failure modes that are not alerts

### A user says "the link says gone" and swears they never opened it

Three possible causes and hush deliberately cannot tell them apart, because
distinguishing them would leak whether a given link was real:

1. Someone else opened it — **treat the secret as compromised and rotate it.**
2. It expired.
3. Redis evicted it early (below).

Assume (1) unless the TTL clearly elapsed. That is the conservative reading and
it is cheap: rotating a credential costs less than a leaked one.

### Redis evicted a secret before its TTL

The shared Redis runs `maxmemory-policy allkeys-lru` at 256 MiB, so under memory
pressure it can drop a hush key **before** its TTL fires.

This is an **availability** risk and never a confidentiality one: eviction only
deletes. A secret can become unavailable early; it can never outlive its TTL and
can never be read twice. For a secret courier that is the correct direction to
fail, which is why `410 gone` does not distinguish it — the user-visible
contract is identical.

If it starts happening, the fix is upstream (Redis memory, or `volatile-lru`,
which is a cluster-wide change affecting every tenant) rather than anything in
hush.

### The pod restarts

Nothing is lost. All state is in Redis. In-flight requests get the two-phase
drain: readiness flips to 503, the load balancer stops sending traffic, then the
process shuts down. `terminationGracePeriodSeconds: 45` exceeds the chassis's
5s drain + 25s shutdown, so the kubelet does not SIGKILL mid-drain.

### Someone reports a link that "lost its #"

Chat and email clients truncate URL fragments. The secret is **intact and
unopened** — the fragment never reaches the server, so nothing was consumed. The
reveal page and the MCP tool both say this explicitly rather than reporting a
generic failure. Ask the sender to re-send the whole link.

## Routine checks

```bash
make deploy-status                        # rollout, pods, ingress, certificate
BASE=https://hush.threesix.ai make smoke  # end-to-end with real crypto
make alerts-check                         # rules loaded AND their series exist
```

`make smoke` creates and burns a real secret against production. It is safe to
run any time; it touches nothing but its own secret.

## What has no runbook because it cannot happen

- **Reading a stored secret as an operator.** There is no key. `kubectl exec` into
  Redis and you get ciphertext.
- **Restoring a revealed secret.** `GETDEL` is atomic and there is no backup of
  a value that existed for one read.
- **Listing outstanding secrets.** The store contract has no `List` and no
  `Exists`. `--scan` in Redis yields opaque keys and opaque values.
