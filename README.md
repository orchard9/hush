# hush

Send someone a secret over a link that works once.

**Production:** <https://hush.threesix.ai>

Paste a secret, get a link, send the link. The first person to open it and press
**Reveal** sees the secret; the link is dead from that moment. Nobody needs an
account, a client, or anything installed — a browser is the whole requirement.

The server cannot read what you sent. Encryption happens in your browser and the
key lives in the URL *fragment* (`…/s/ID#KEY`), which browsers never transmit.
hush stores ciphertext it has no way to open. That is not a promise about our
operational discipline; it is a property of where the key sits.

## What one-time actually buys you

Worth being precise, because "one-time link" is often oversold:

- **Bounded exposure.** The secret is fetchable once, for at most its TTL, then it
  is gone. A credential sitting in a Slack thread is fetchable forever by anyone
  who later gains access to that thread.
- **Tamper evidence.** If your recipient says "already used", someone else opened
  it. You have learned something a plain paste never tells you.
- **Nothing at rest to steal.** A dump of hush's Redis yields ciphertext and no keys.

And what it does not buy you:

- **It does not protect the link.** Whatever channel carries the link could be read
  by whoever can read that channel. One-time-ness limits the damage and makes it
  detectable; it does not make the channel private.
- **It does not authenticate the reader.** Anyone holding the link can open it.
  The link *is* the capability. Treat it like the secret it carries.

If a secret must reach one specific verified human and nobody else, this is the
wrong tool — use a channel with identity.

## Usage

### In a browser

1. Open <https://hush.threesix.ai>.
2. Paste the secret, press **create a secret**.
3. Copy the link and send it however you like.
4. The recipient opens it, presses **reveal the secret**, and reads it once.

There is no lifetime picker: the page offers one action, and the server applies
its default TTL (24 hours). `ttl_seconds` on the API is where a caller that
cares chooses.

### Why there is a button

Slack, Teams, WhatsApp, iMessage and Outlook Safe Links all fetch a URL to build
a preview *before* any human sees it. A service that destroys on `GET` therefore
destroys most secrets in transit, and the recipient's "already used" is
indistinguishable from a real interception.

So in hush, `GET /s/{id}` is a static page that touches no storage at all. Only
`POST /s/{id}/reveal` reads and destroys. Link previewers are harmless by
construction, not by user-agent guessing.

### API

The API takes **ciphertext**. There is no endpoint that accepts a plaintext
secret, because such an endpoint would make the server able to read secrets and
the claim at the top of this file would become a matter of trust rather than
arithmetic.

```
POST /api/secrets
{ "ciphertext": "<base64url AES-256-GCM, nonce prepended>", "ttl_seconds": 86400 }
→ 201 { "id": "…", "expires_at": "2026-09-04T…Z", "ttl_seconds": 86400 }

POST /api/secrets/{id}/reveal
→ 200 { "ciphertext": "…" }        first caller only, secret destroyed
→ 410 { "error": { "code": "gone" } }   every other case
```

`410 gone` is returned identically whether the id never existed, was already
revealed, or expired. Distinguishing those would confirm to an attacker that a
particular link once existed.

`GET /` serves the create page, `GET /s/{id}` the reveal page. `/healthz`,
`/readyz` and `/metrics` are served on the same port but are **not routed by the
public ingress** — they are reachable in-cluster only.

### From an agent, over MCP

`cmd/hush-mcp` is a stdio MCP server exposing two tools, `hush_create` and
`hush_reveal`. It runs **locally** and does the encryption on your machine, so
using hush from an agent preserves the same zero-knowledge property as using it
from a browser. See [docs/MCP.md](docs/MCP.md).

## Limits

| Thing | Value | Why |
|---|---|---|
| Ciphertext | ≤ 64 KiB | It is a courier for credentials, not a file host |
| TTL | 5m … 7d, default 24h | Long enough to be useful, short enough to bound exposure |
| Rate limit | 30 creates / 10 min / IP | Anonymous create is otherwise a free blob host |
| Reveals per secret | exactly 1 | The product |

## Operating it

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how it works and why each choice
- [docs/DEPLOY.md](docs/DEPLOY.md) — pipeline, DNS, credentials, first deploy
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — alert runbook, log queries, failure modes
- [docs/MCP.md](docs/MCP.md) — the MCP server and how to install it

## Development

```bash
make help          # every target
make release       # build this commit in-cluster and roll it out, then smoke it
make test          # unit tests, no external dependencies
make dev           # a local Redis in Docker + hushd on :18500
make smoke         # full create → reveal → gone against the local instance
make vendor        # refresh vendor/ after a dependency change
```

`go-chassis` is a private module, so dependencies are **vendored** and both CI
and the container build run with `-mod=vendor` and no network. `make vendor` is
the only way dependency versions change.
