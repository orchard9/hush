# The MCP server

`cmd/hush-mcp` gives an MCP host (omp, Claude Code, any client) two tools:

| Tool | Does |
|---|---|
| `hush_create` | Encrypts a secret locally, stores the ciphertext, returns a one-time link |
| `hush_reveal` | Fetches and decrypts a link, **destroying it** |

## Install

```bash
go install github.com/orchard9/hush/cmd/hush-mcp@latest
```

That is the whole install, from anywhere, with no clone: `cmd/hush-mcp` imports
only the standard library, so the module graph never reaches the private
`go-chassis` dependency that `cmd/hushd` needs.

From a clone, `make mcp` does the omp case end to end — it builds to
`~/.local/bin/hush-mcp`, proves the MCP handshake works before wiring anything,
then adds a `hush` entry to `~/.omp/agent/mcp.json`, backing the file up first
and leaving every other server alone. Restart omp to pick it up.

```json
{
  "mcpServers": {
    "hush": {
      "type": "stdio",
      "command": "/Users/you/go/bin/hush-mcp",
      "env": { "HUSH_BASE_URL": "https://hush.threesix.ai" },
      "timeout": 20000
    }
  }
}
```

That shape is what Claude Desktop, Cursor and omp read. VS Code spells the
wrapper key `servers`, Codex uses TOML (`[mcp_servers.hush]`), and Claude Code,
Codex and Gemini each have an `mcp add` subcommand that writes it for you. The
stdio transport is the portable part.

**The user-facing copy of all of that is served by the deployment itself at
<https://hush.threesix.ai/mcp>**, rendered from
`internal/web/templates/mcp.html` and checked on every release by
`scripts/smoke.sh`. A client-specific change belongs in that template; this
file keeps what a reader of the repo needs and the page does not.

## Why it runs locally instead of being an endpoint on hushd

hushd could serve `/mcp` and encrypt on the server. It deliberately does not.

If the server did the encrypting, the server would see every plaintext created
through MCP. hush's guarantee — *we cannot read your secrets* — would then hold
for browser users and quietly not hold for agent users, and no one could tell
which they had by looking at a link. Two guarantees behind one URL is worse
than one honest guarantee.

So `hush-mcp` is a peer of the browser, not of the server: it mints the AES-256
key, encrypts, posts only ciphertext, and assembles the `#fragment` link
itself. hushd sees exactly what it sees from a browser and no more.

The cost is that this is a local binary to install rather than a URL to
configure. That is the right trade for a service whose entire value is where
the key sits.

## Wire compatibility

Three implementations produce and consume one format — the browser
(`internal/web/templates/base.html`), this server, and `scripts/smoke.sh`:

```
AES-256-GCM, 96-bit nonce PREPENDED to the ciphertext,
both ciphertext and key base64url-encoded WITHOUT padding
```

A link minted by any of the three opens in the other two.
`TestWireFormatMatchesAnIndependentImplementation` pins that by round-tripping
Go↔Python in both directions, so a change to one implementation's encoding
fails the build rather than producing links that only work in the client that
made them.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `HUSH_BASE_URL` | `https://hush.threesix.ai` | Which deployment `hush_create` posts to |
| `HUSH_CREATE_TOKEN` | unset | Only needed if that deployment has `HUSH_REQUIRE_AUTH=true` |

`hush_reveal` ignores `HUSH_BASE_URL` and reveals against **the link's own
origin**. A link from another hush deployment must not be posted to this one,
where its id would be meaningless — and silently revealing against the wrong
host would report `gone` for a secret that was never touched.

## Behaviour worth knowing before you call it

- **`hush_reveal` is destructive and irreversible.** After it returns, the link
  is dead and the intended recipient cannot open it. The tool description says
  so, because a model that calls it to "check" a link has burned it.
- **`hush_create` returns the link once.** It cannot be recovered: the key was
  never sent to the server, so nothing can rebuild it.
- **A link with no `#fragment` is reported as an error without touching the
  secret.** Chat and email clients truncate fragments, and this is the commonest
  real failure. The secret is intact and the fix is to ask for the full link —
  which the error says, rather than reporting a generic failure.
- **Errors come back as tool errors** (`isError: true`), not protocol errors, so
  the model reads the message and can act on it instead of seeing an opaque
  transport failure.

## Protocol notes

Implemented directly against the JSON-RPC 2.0 stdio transport rather than via an
SDK: the surface needed is `initialize`, `notifications/initialized`,
`tools/list`, `tools/call` and `ping`, which is less code than an SDK
dependency's API churn would cost.

Two rules the implementation is careful about, both of which produce
hard-to-diagnose host-side failures when broken:

- **stdout carries protocol frames only.** Every diagnostic goes to stderr. A
  stray `Println` corrupts the stream and the host reports an opaque parse error.
- **A notification (no `id`) is never answered.** Replying to one desyncs the
  host, which then attributes the unsolicited response to the next request.
