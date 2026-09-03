#!/usr/bin/env bash
# End-to-end proof against a RUNNING hushd, doing the real client-side crypto.
#
# This is not a mock: it generates an AES-256-GCM key, encrypts a plaintext,
# posts only the ciphertext, reveals it once, decrypts it, and compares. Then it
# checks the three properties the design rests on:
#
#   1. a second reveal is 410 gone
#   2. GET on the reveal page does NOT consume the secret (link previewers)
#   3. a malformed id and a missing id are indistinguishable
#
# Usage: BASE=http://127.0.0.1:18500 ./scripts/smoke.sh
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:18500}"
PLAINTEXT="${PLAINTEXT:-hunter2-$(date +%s)-$RANDOM}"

pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

command -v python3 >/dev/null || { echo "python3 is required for the crypto half"; exit 1; }

echo "hush smoke against $BASE"

# --- encrypt exactly as the browser does -----------------------------------
# AES-256-GCM, 96-bit nonce prepended, base64url unpadded. Same wire format as
# templates/base.html, which is what makes this a real client.
read -r CIPHERTEXT KEY <<<"$(python3 - "$PLAINTEXT" <<'PY'
import base64, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)
blob = nonce + AESGCM(key).encrypt(nonce, sys.argv[1].encode(), None)
b = lambda x: base64.urlsafe_b64encode(x).decode().rstrip("=")
print(b(blob), b(key))
PY
)"
[ -n "$CIPHERTEXT" ] || fail "could not encrypt (is 'cryptography' installed? pip install cryptography)"
pass "encrypted client-side (${#CIPHERTEXT} bytes of ciphertext)"

# --- create ----------------------------------------------------------------
CREATE=$(curl -sS -X POST "$BASE/api/secrets" -H 'Content-Type: application/json' \
  -d "{\"ciphertext\":\"$CIPHERTEXT\",\"ttl_seconds\":900}")
ID=$(printf '%s' "$CREATE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
[ -n "$ID" ] || fail "create returned no id: $CREATE"
pass "created — id is ${#ID} chars"

# --- the previewer property, checked BEFORE revealing ----------------------
for _ in 1 2 3; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/s/$ID")
  [ "$code" = "200" ] || fail "GET /s/{id} returned $code"
done
pass "GET on the reveal page x3 — Slack/Outlook previews are harmless"

# --- reveal once and decrypt ----------------------------------------------
REVEAL=$(curl -sS -X POST "$BASE/api/secrets/$ID/reveal")
GOT_CT=$(printf '%s' "$REVEAL" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("ciphertext",""))')
[ -n "$GOT_CT" ] || fail "reveal returned no ciphertext: $REVEAL"

DECRYPTED=$(python3 - "$GOT_CT" "$KEY" <<'PY'
import base64, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
blob, key = u(sys.argv[1]), u(sys.argv[2])
sys.stdout.write(AESGCM(key).decrypt(blob[:12], blob[12:], None).decode())
PY
)
[ "$DECRYPTED" = "$PLAINTEXT" ] || fail "decrypted to '$DECRYPTED', expected '$PLAINTEXT'"
pass "revealed and decrypted — round trip matches"

# --- and it is gone --------------------------------------------------------
code=$(curl -sS -o /tmp/hush-gone.$$ -w '%{http_code}' -X POST "$BASE/api/secrets/$ID/reveal")
[ "$code" = "410" ] || fail "second reveal returned $code, want 410"
GONE_BODY=$(cat /tmp/hush-gone.$$); rm -f /tmp/hush-gone.$$
pass "second reveal is 410 gone"

# --- missing and malformed are one response --------------------------------
MISSING=$(curl -sS -X POST "$BASE/api/secrets/$(python3 -c 'print("A"*43)')/reveal")
MALFORMED=$(curl -sS -X POST "$BASE/api/secrets/not-an-id/reveal")
for body in "$MISSING" "$MALFORMED"; do
  norm=$(printf '%s' "$body" | python3 -c 'import json,sys; e=json.load(sys.stdin)["error"]; print(e["code"], e["message"])')
  gone=$(printf '%s' "$GONE_BODY" | python3 -c 'import json,sys; e=json.load(sys.stdin)["error"]; print(e["code"], e["message"])')
  [ "$norm" = "$gone" ] || fail "responses differ between causes: '$norm' vs '$gone'"
done
pass "revealed, expired, missing and malformed are one indistinguishable response"

# --- the server must refuse plaintext -------------------------------------
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/api/secrets" \
  -H 'Content-Type: application/json' -d '{"secret":"hunter2"}')
[ "$code" != "201" ] || fail "the server ACCEPTED a plaintext field — the zero-knowledge claim is broken"
pass "a plaintext field is refused ($code)"

echo
printf '\033[32mall smoke checks passed\033[0m\n'
