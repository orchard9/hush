# Architecture

One Go binary, one Redis key per secret, no database. The interesting parts are
all about *where the key sits* and *what destroys the ciphertext*.

## Components

```
browser ──► Traefik ──► hushd (projects ns, 1 replica) ──► Redis (databases ns, db 5)
                            │
                            ├─ stdout JSON ──► Vector (DaemonSet) ──► VictoriaLogs
                            └─ /metrics ─────► vmagent ──► vmsingle ──► vmalert ──► Alertmanager
```

`hushd` holds no durable state. Redis holds every secret and nothing else.

## The zero-knowledge split

```
create:   plaintext ──[AES-256-GCM in the browser]──► ciphertext ──► POST /api/secrets
          key ──────────────────────────────────────► URL fragment, never sent

reveal:   POST /api/secrets/{id}/reveal ──► ciphertext ──[decrypt in browser]──► plaintext
          key read from location.hash
```

The fragment is the whole trick. Per RFC 3986 §3.5 the fragment is a client-side
construct: browsers do not put it in the request line, so it never reaches
Traefik, hushd, Redis, an access log, or a proxy. hushd receives a 256-bit AES-GCM
ciphertext with a prepended 96-bit nonce and has no key material at any point.

Consequences worth stating plainly:

- A Redis dump is worthless. A hushd core dump is worthless. Our own operators
  cannot read a secret, and neither can anyone who compromises the service.
- **A URL in someone's browser history contains the key.** The fragment is not
  transmitted, but it *is* stored locally. This is the residual exposure and it
  is why TTLs are short.
- There is deliberately no server-side-encryption fallback mode. A second mode
  where the server sees plaintext would mean nobody could tell, from a link,
  which guarantee they had.

## Why GET never touches storage

`GET /s/{id}` renders a static page and makes zero calls to Redis. It does not
even check whether the id exists.

That is not laziness — it is the only way to be correct in the presence of link
previewers. Slack, Teams, WhatsApp, iMessage and Outlook Safe Links fetch URLs
before a human sees them. Any design that destroys on `GET` destroys most secrets
in transit. Bot user-agent detection is a losing arms race; removing the
side effect from `GET` is not.

A secondary benefit: because `GET` does not look the id up, the reveal page cannot
leak whether an id exists. Existence is only ever answered by a `POST`, and that
answer is identical for missing, revealed and expired.

## Storage and destruction

One key per secret:

```
key    hush:s:<id>            id = 256 bits from crypto/rand, base64url (43 chars)
value  <ciphertext>           opaque bytes, ≤ 64 KiB
write  SET key val EX <ttl> NX
read   GETDEL key
```

`GETDEL` (Redis 6.2+; the cluster runs 7.4.8) is atomic, which is the reason it
is used instead of `GET` followed by `DEL`. Two people opening the same link
simultaneously cannot both receive the plaintext — exactly one `GETDEL` returns
the value and the other returns nil. A `GET`+`DEL` pair has a window between the
two commands where both callers succeed, and for a one-time secret that window is
the entire product.

`NX` on write means an id collision never overwrites an existing secret. At 256
bits of entropy a collision will not happen; the flag costs nothing and turns a
theoretical silent overwrite into a visible error.

TTL is Redis-native, so expiry needs no sweeper, no cron and nothing to wedge.

### Eviction is an availability risk, not a confidentiality one

The shared Redis runs `maxmemory-policy allkeys-lru` with `maxmemory 256MiB`.
Under memory pressure Redis may evict a hush key **before** its TTL fires. That
means a secret can become unavailable early.

It cannot become *more* available: eviction only ever deletes. So the failure mode
is "your recipient has to ask you again", never "the secret outlived its TTL" and
never "someone read it twice". For a secret courier that is the correct direction
to fail, and it is why `410 gone` deliberately does not distinguish causes — the
user-visible contract is identical either way.

Operationally this is watched via `HushRedisUnreachable` and the Redis memory
alerts, not by trying to tell eviction and reveal apart. See
[OPERATIONS.md](OPERATIONS.md).

## Identifiers and what gets logged

The id **is** the capability. Anyone holding it can reveal the secret, so it is
treated like a bearer token:

- Never logged. Not at debug, not in an error, not in a panic.
- The log correlation handle is `sid = sha256(id)[:12]` — enough to follow one
  secret's create → reveal → gone across a corpus, useless for revealing it.
- Never in a metric label (that would put it in the time series index forever).

`internal/secret.ID.LogHandle()` is the only way to get a loggable form, and the
`ID` type does not implement `String()` or `MarshalText()`, so it cannot be
accidentally interpolated into a log line or JSON body. That is enforced by
`internal/secret/id_test.go`.

The chassis logger additionally redacts any field *named* `secret`, `token`,
`password`, `api_key`, `authorization` and friends. Field names here avoid those
words entirely (`ciphertext`, `sid`, `ttl_seconds`) so nothing depends on that
backstop.

## Request path

```
GET  /                     create page (static HTML+JS, no storage access)
GET  /s/{id}               reveal page (static HTML+JS, no storage access)
POST /api/secrets          store ciphertext                    rate limited
POST /api/secrets/{id}/reveal   GETDEL, destroy, return once   rate limited
GET  /healthz              liveness — 200 while draining
GET  /readyz               readiness — Redis PING, 503 while draining
GET  /metrics              Prometheus
```

Built on `github.com/orchard9/go-chassis`, which supplies routing, request ids,
the panic recovery envelope, RED metrics, secure headers, the two-phase drain,
and `/healthz`, `/readyz`, `/metrics`. hush contributes handlers, a store, a
rate limiter and templates — not a framework.

The public Ingress routes `/` (exact), `/s/` and `/api/` only. `/metrics`,
`/healthz` and `/readyz` share the port but are unreachable from the internet;
vmagent scrapes the pod IP directly. This is why there is no metrics basic-auth
middleware to maintain.

## Abuse posture

Create is anonymous by design, which makes the service a free blob host and a
phishing kit borrowing a `threesix.ai` name. Mitigations, all cheap:

| Control | Value |
|---|---|
| Ciphertext cap | 64 KiB, enforced before Redis |
| Request body cap | 128 KiB, enforced by the chassis at the edge |
| TTL clamp | 5m … 7d, out-of-range is a 422, not a silent clamp |
| Rate limit | 30 creates / 10 min / IP, Redis fixed-window |
| Id entropy | 256 bits — enumeration is not a threat model |
| No listing route | there is no way to ask "what secrets exist" |
| Identical `gone` | missing, revealed and expired are one response |

If it is ever abused, `HUSH_REQUIRE_AUTH=true` puts create behind the chassis
authenticator while leaving reveal anonymous — the asymmetry the design assumes.
Reveal must stay anonymous: the recipient is external and has no credential.

## Failure modes

| Failure | Behaviour |
|---|---|
| Redis down | `/readyz` 503, pod leaves the Service, creates and reveals 503. No secret is lost that was already written. |
| Redis evicts a key early | That link returns `410 gone`. Sender must re-send. |
| hushd restarts | Nothing lost; all state is in Redis. |
| Two simultaneous reveals | Exactly one wins, atomically. |
| Body over 128 KiB | 413 at the edge, never reaches a handler. |
| Ciphertext over 64 KiB | 422 `ciphertext_too_large`. |
| Malformed base64 | 422 `ciphertext_invalid`. hushd validates the encoding but cannot validate the plaintext. |
| Clock skew | TTL is Redis-relative, so skew between hushd and the browser cannot extend a secret's life. |

## What is deliberately absent

Accounts. Passphrases on top of the link. File uploads. Multi-read links. An
audit UI. Email delivery. Each is a real request and each doubles the surface.

The one with a genuine argument is **notify-on-read**: it confirms delivery and,
if it fires before the recipient says they opened it, that is a compromise
signal. It needs an email path, `notify` already exists to provide one, and it is
the first thing to add if hush proves useful.
