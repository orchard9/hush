#!/usr/bin/env bash
# Build hush-mcp and register it with omp.
#
# The server runs LOCALLY and does the AES-256-GCM itself. That is the point: if
# hushd served an MCP endpoint and encrypted server-side, the server could read
# every secret created through MCP, and hush's guarantee would hold for browser
# users while quietly not holding for agent users. This binary is a peer of the
# browser, not of the server.
#
# Idempotent: re-running rebuilds the binary and rewrites only hush's entry in
# ~/.omp/agent/mcp.json, leaving every other server alone.
set -euo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
MCP_JSON="${MCP_JSON:-$HOME/.omp/agent/mcp.json}"
BASE_URL="${HUSH_BASE_URL:-https://hush.threesix.ai}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "building hush-mcp"
mkdir -p "$BIN_DIR"
(cd "$ROOT" && go build -trimpath -ldflags="-s -w" -o "$BIN_DIR/hush-mcp" ./cmd/hush-mcp)
echo "  installed $BIN_DIR/hush-mcp"

# Prove the binary speaks MCP before wiring it in. A config pointing at a broken
# server surfaces as an opaque host-side connect failure, so the handshake is
# checked here where the error is legible.
echo "verifying the MCP handshake"
HANDSHAKE=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | HUSH_BASE_URL="$BASE_URL" "$BIN_DIR/hush-mcp" 2>/dev/null)
echo "$HANDSHAKE" | python3 -c '
import json, sys
tools = None
for line in sys.stdin:
    m = json.loads(line)
    if m.get("id") == 1:
        print("  protocol", m["result"]["protocolVersion"], "server", m["result"]["serverInfo"]["name"])
    if m.get("id") == 2:
        tools = [t["name"] for t in m["result"]["tools"]]
if not tools:
    sys.exit("  the server did not answer tools/list")
print("  tools:", ", ".join(tools))
'

echo "registering with omp at $MCP_JSON"
mkdir -p "$(dirname "$MCP_JSON")"
[ -f "$MCP_JSON" ] || printf '{"mcpServers":{}}\n' > "$MCP_JSON"
# Back up before touching a config that may hold other servers.
cp "$MCP_JSON" "$MCP_JSON.bak.$(date +%Y%m%d%H%M%S)"

BIN="$BIN_DIR/hush-mcp" BASE="$BASE_URL" TARGET="$MCP_JSON" python3 - <<'PY'
import json, os

target = os.environ["TARGET"]
with open(target) as f:
    cfg = json.load(f)

cfg.setdefault("$schema",
    "https://raw.githubusercontent.com/can1357/oh-my-pi/main/packages/coding-agent/src/config/mcp-schema.json")
servers = cfg.setdefault("mcpServers", {})

# stdio, not http: the encryption has to happen on this machine.
servers["hush"] = {
    "type": "stdio",
    "command": os.environ["BIN"],
    "env": {"HUSH_BASE_URL": os.environ["BASE"]},
    "timeout": 20000,
}

with open(target, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")

print("  servers now configured:", ", ".join(sorted(servers)))
PY

echo
echo "done. Restart omp to pick up the new server, then: hush_create / hush_reveal"
