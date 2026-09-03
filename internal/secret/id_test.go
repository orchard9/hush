package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// The id IS the capability, so every path that could print one is checked here.
//
// The first version of this test forbade String() outright, on the theory that
// a type with no Stringer cannot be interpolated. That was wrong and this test
// caught it: Go's fmt prints unexported struct fields regardless, so `%v` was
// emitting live ids. The design now makes the REDACTED form the default on
// every accidental path and requires Value() for the raw one.
//
// Read this test first if you are wondering why ID has a String() that throws
// away information and a MarshalJSON that refuses.
func TestNoAccidentalPathEmitsTheRawID(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	raw := id.Value()

	for _, tc := range []struct {
		name string
		got  string
	}{
		{"fmt %v", fmt.Sprintf("%v", id)},
		{"fmt %s", fmt.Sprintf("%s", id)},
		{"fmt %+v", fmt.Sprintf("%+v", id)},
		{"fmt %#v of a wrapper struct", fmt.Sprintf("%v", struct{ ID ID }{id})},
		{"String()", id.String()},
		{"LogValue()", id.LogValue().String()},
		{"inside a slice", fmt.Sprintf("%v", []ID{id})},
		{"inside a map", fmt.Sprintf("%v", map[string]ID{"k": id})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(tc.got, raw) {
				t.Fatalf("%s emitted the live id (%q) — this value would appear in a log line "+
					"and anyone reading it could reveal the secret", tc.name, tc.got)
			}
			if !strings.Contains(tc.got, id.LogHandle()) {
				t.Fatalf("%s = %q, which carries neither the id nor its handle; a log line "+
					"with no handle cannot be correlated", tc.name, tc.got)
			}
		})
	}
}

// A real slog handler, because that is where ids actually pass through.
func TestSlogEmitsTheHandleNotTheID(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	// Every shape a call site might use, including the careless one.
	log.Info("secret.created", "id", id)
	log.Info("secret.created", "sid", id.LogHandle())
	log.With("id", id).Info("secret.revealed")
	log.Info("secret.gone", "ids", []ID{id})

	out := buf.String()
	if strings.Contains(out, id.Value()) {
		t.Fatalf("slog output contains the live id:\n%s", out)
	}
	if !strings.Contains(out, id.LogHandle()) {
		t.Fatalf("slog output contains no correlation handle:\n%s", out)
	}
}

// Serialising an ID must FAIL rather than quietly emit either form. The raw
// value would leak a capability out of any response struct embedding an ID;
// the redacted value would produce a response that looks like it carries an id
// and does not, turning a server bug into a broken link for the recipient.
func TestMarshallingAnIDIsAnError(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if b, err := json.Marshal(id); err == nil {
		t.Fatalf("json.Marshal(ID) succeeded with %s; it must refuse", b)
	}
	// And from inside a struct, which is how it would actually happen.
	if b, err := json.Marshal(struct {
		ID ID `json:"id"`
	}{id}); err == nil {
		t.Fatalf("marshalling a struct containing an ID succeeded with %s; it must refuse", b)
	}
}

func TestNewIDIsUnguessablyWideAndUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for range 1000 {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id.Value()) != 43 {
			t.Fatalf("id %q is %d chars, want 43 (256 bits base64url unpadded)", id.Value(), len(id.Value()))
		}
		if seen[id.Value()] {
			t.Fatal("NewID repeated a value in 1000 draws — entropy is broken")
		}
		seen[id.Value()] = true
	}
}

func TestParseIDRoundTripsAndRefusesEverythingElse(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseID(id.Value())
	if err != nil {
		t.Fatalf("ParseID rejected a freshly minted id: %v", err)
	}
	if back.Value() != id.Value() {
		t.Fatalf("round trip changed the id: %q -> %q", id.Value(), back.Value())
	}

	for _, bad := range []struct{ name, in string }{
		{"empty", ""},
		{"too short", "abc"},
		{"one char short", id.Value()[:42]},
		{"one char long", id.Value() + "a"},
		{"not base64url", strings.Repeat("!", 43)},
		// A shorter secret encoded in a 43-char field would widen the space a
		// scanner must cover, so the DECODED length is checked too.
		{"padded base64", strings.Repeat("A", 40) + "==="},
		{"path traversal", "../../etc/passwd"},
		{"redis glob", strings.Repeat("*", 43)},
	} {
		t.Run(bad.name, func(t *testing.T) {
			if _, err := ParseID(bad.in); err == nil {
				t.Fatalf("ParseID(%q) accepted a value NewID cannot produce", bad.in)
			}
		})
	}
}

func TestLogHandleIsStableShortAndNotTheID(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	h := id.LogHandle()
	if len(h) != 12 {
		t.Fatalf("LogHandle() = %q, want 12 hex chars", h)
	}
	if id.LogHandle() != h {
		t.Fatal("LogHandle is not stable across calls, so log lines for one secret will not correlate")
	}
	if strings.Contains(h, id.Value()) || strings.Contains(id.Value(), h) {
		t.Fatalf("LogHandle %q overlaps the raw id %q — it must be a hash, not a prefix", h, id.Value())
	}

	// Different ids must not collide into one handle, or correlation is wrong.
	other, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if other.LogHandle() == h {
		t.Fatal("two ids produced the same LogHandle")
	}

	if (ID{}).LogHandle() != "" {
		t.Fatal("the zero ID must produce an empty handle, not a hash of the empty string")
	}
}

func TestStorageKeyStaysInsideTheACLPrefix(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	// The Redis ACL user is scoped to ~hush:*. A key built outside that prefix
	// is refused by the server, so this test is what keeps a rename from
	// turning every write into a NOPERM at runtime.
	if !strings.HasPrefix(id.StorageKey(), "hush:") {
		t.Fatalf("StorageKey() = %q, which is outside the ~hush:* ACL scope", id.StorageKey())
	}
}
