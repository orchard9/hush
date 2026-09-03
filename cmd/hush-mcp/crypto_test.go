package main

import (
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	for _, plain := range []string{
		"hunter2",
		"",
		strings.Repeat("x", 40000),
		"unicode: ✓ 漢字 🔐",
		"multi\nline\nwith\ttabs",
	} {
		ct, key, err := seal(plain)
		if err != nil {
			t.Fatalf("seal(%d bytes): %v", len(plain), err)
		}
		got, err := open(ct, key)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if got != plain {
			t.Fatalf("round trip changed the plaintext (%d bytes)", len(plain))
		}
	}
}

func TestSealProducesTheBrowsersWireFormat(t *testing.T) {
	ct, key, err := seal("x")
	if err != nil {
		t.Fatal(err)
	}
	// base64url, unpadded, matching base64.RawURLEncoding on the server and
	// the b64u helper in templates/base.html. Three implementations, one
	// spelling — a mismatch here means a link minted by one client cannot be
	// opened by another.
	for name, v := range map[string]string{"ciphertext": ct, "key": key} {
		if strings.ContainsAny(v, "+/=") {
			t.Fatalf("%s %q uses the standard base64 alphabet or padding; it must be base64url unpadded", name, v)
		}
		if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
			t.Fatalf("%s does not decode as base64url: %v", name, err)
		}
	}
	// 256-bit key.
	raw, _ := base64.RawURLEncoding.DecodeString(key)
	if len(raw) != 32 {
		t.Fatalf("key is %d bytes, want 32 (AES-256)", len(raw))
	}
	// 96-bit nonce prepended, then at least the GCM tag.
	blob, _ := base64.RawURLEncoding.DecodeString(ct)
	if len(blob) < 12+16 {
		t.Fatalf("ciphertext is %d bytes, too short for a 12-byte nonce plus a 16-byte tag", len(blob))
	}
}

func TestOpenRefusesAWrongKeyAndTamperedCiphertext(t *testing.T) {
	ct, _, err := seal("secret")
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, _ := seal("unrelated")

	if _, err := open(ct, otherKey); err == nil {
		t.Fatal("open() accepted a key that does not belong to this ciphertext")
	}

	// GCM is authenticated: a flipped byte must fail, not decrypt to garbage.
	blob, _ := base64.RawURLEncoding.DecodeString(ct)
	blob[len(blob)-1] ^= 0xff
	_, key, _ := seal("x")
	if _, err := open(base64.RawURLEncoding.EncodeToString(blob), key); err == nil {
		t.Fatal("open() accepted tampered ciphertext")
	}

	if _, err := open("!!!not base64!!!", key); err == nil {
		t.Fatal("open() accepted a non-base64url ciphertext")
	}
	if _, err := open(ct, "!!!"); err == nil {
		t.Fatal("open() accepted a non-base64url key")
	}
}

// Cross-implementation check: a blob sealed by this Go client must decrypt with
// Python's AES-GCM, and vice versa. This is what proves the MCP client, the
// browser and the smoke script really share one format rather than three
// self-consistent ones.
func TestWireFormatMatchesAnIndependentImplementation(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	const plain = "cross-implementation-secret"

	ct, key, err := seal(plain)
	if err != nil {
		t.Fatal(err)
	}

	// Go -> Python
	out, err := exec.Command("python3", "-c", `
import base64, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
blob, key = u(sys.argv[1]), u(sys.argv[2])
sys.stdout.write(AESGCM(key).decrypt(blob[:12], blob[12:], None).decode())
`, ct, key).Output()
	if err != nil {
		t.Skipf("python cryptography unavailable: %v", err)
	}
	if string(out) != plain {
		t.Fatalf("python decrypted our ciphertext to %q, want %q", out, plain)
	}

	// Python -> Go
	pyOut, err := exec.Command("python3", "-c", `
import base64, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256); nonce = os.urandom(12)
blob = nonce + AESGCM(key).encrypt(nonce, b"from-python", None)
b = lambda x: base64.urlsafe_b64encode(x).decode().rstrip("=")
print(b(blob), b(key))
`).Output()
	if err != nil {
		t.Fatalf("python encrypt failed: %v", err)
	}
	parts := strings.Fields(string(pyOut))
	if len(parts) != 2 {
		t.Fatalf("unexpected python output %q", pyOut)
	}
	got, err := open(parts[0], parts[1])
	if err != nil {
		t.Fatalf("could not open python's ciphertext: %v", err)
	}
	if got != "from-python" {
		t.Fatalf("opened python's ciphertext to %q", got)
	}
}
