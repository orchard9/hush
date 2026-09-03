package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/orchard9/go-chassis/chassis"

	"github.com/orchard9/hush/internal/secret"
	"github.com/orchard9/hush/internal/store"
	"github.com/orchard9/hush/internal/web"
)

// testApp builds the real route table over an in-memory store, so these tests
// exercise the actual middleware chain, binder and error envelopes rather than
// calling handlers directly.
func testApp(t *testing.T) (http.Handler, *store.Memory) {
	t.Helper()
	pages, err := web.New()
	if err != nil {
		t.Fatal(err)
	}
	mem := store.NewMemory()
	srv := &Server{
		cfg:     Config{Env: "dev"},
		store:   mem,
		pages:   pages,
		metrics: newMetrics(),
	}
	srv.metrics.Prime()

	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	app := chassis.New(chassis.Config{Service: "hush", Env: "dev", MaxBodyBytes: 128 * 1024}, log)
	app.Get("/", srv.handleCreatePage)
	app.Get("/s/{id}", srv.handleRevealPage)
	app.Route("/api", func(r *chassis.Router) {
		r.Post("/secrets", srv.handleCreate)
		r.Post("/secrets/{id}/reveal", srv.handleReveal)
	})
	return app.Handler(), mem
}

func ciphertext(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func do(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any, string) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	raw := w.Body.String()
	var parsed map[string]any
	_ = json.Unmarshal([]byte(raw), &parsed)
	return w.Code, parsed, raw
}

func create(t *testing.T, h http.Handler, ct string) string {
	t.Helper()
	code, body, raw := do(t, h, http.MethodPost, "/api/secrets",
		`{"ciphertext":"`+ct+`","ttl_seconds":3600}`)
	if code != http.StatusCreated {
		t.Fatalf("create = %d, want 201: %s", code, raw)
	}
	id, ok := body["id"].(string)
	if !ok || id == "" {
		t.Fatalf("create response carried no id: %s", raw)
	}
	return id
}

func TestCreateThenRevealThenGone(t *testing.T) {
	h, _ := testApp(t)
	ct := ciphertext("the-secret-bytes")
	id := create(t, h, ct)

	code, body, raw := do(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", "")
	if code != http.StatusOK {
		t.Fatalf("first reveal = %d, want 200: %s", code, raw)
	}
	if body["ciphertext"] != ct {
		t.Fatalf("reveal returned %v, want the stored ciphertext", body["ciphertext"])
	}

	code, _, raw = do(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", "")
	if code != http.StatusGone {
		t.Fatalf("second reveal = %d, want 410: %s", code, raw)
	}
}

// THE regression test for this whole design. Slack, Teams, WhatsApp, iMessage
// and Outlook Safe Links fetch a URL to build a preview before any human sees
// it. If GET consumed the secret, most secrets would be destroyed in transit
// and the recipient's "already used" would be indistinguishable from a real
// interception.
//
// So: fetching the reveal page any number of times must leave the secret intact.
func TestGettingTheRevealPageNeverConsumesTheSecret(t *testing.T) {
	h, _ := testApp(t)
	ct := ciphertext("survives-the-previewers")
	id := create(t, h, ct)

	for i := range 5 {
		code, _, _ := do(t, h, http.MethodGet, "/s/"+id, "")
		if code != http.StatusOK {
			t.Fatalf("GET /s/{id} attempt %d = %d, want 200", i, code)
		}
	}

	code, body, raw := do(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", "")
	if code != http.StatusOK {
		t.Fatalf("reveal after 5 page loads = %d, want 200 — a GET consumed the secret: %s", code, raw)
	}
	if body["ciphertext"] != ct {
		t.Fatal("the ciphertext changed across page loads")
	}
}

// The reveal page must be identical for every id, including ids that were never
// minted. If it 404'd on an unknown id it would become an oracle for whether a
// link was ever real.
func TestTheRevealPageDoesNotDiscloseWhetherASecretExists(t *testing.T) {
	h, _ := testApp(t)
	id := create(t, h, ciphertext("real"))

	_, _, real := do(t, h, http.MethodGet, "/s/"+id, "")
	_, _, fake := do(t, h, http.MethodGet, "/s/"+strings.Repeat("A", 43), "")
	_, _, junk := do(t, h, http.MethodGet, "/s/not-an-id", "")

	if real != fake || real != junk {
		t.Fatal("the reveal page differs between a real id, a well-formed unknown id, and junk — " +
			"it must not disclose existence")
	}
}

// A malformed id must produce the SAME 410 as a missing one. A 400 here would
// separate "not an id this service could mint" from "an id that is gone", which
// hands a probe a free classifier.
func TestMalformedAndMissingIDsAreIndistinguishable(t *testing.T) {
	h, _ := testApp(t)

	unknown, err := secret.NewID()
	if err != nil {
		t.Fatal(err)
	}

	var bodies []string
	for _, id := range []string{
		unknown.Value(),         // well-formed, never stored
		strings.Repeat("A", 43), // well-formed, never minted
		"short",                 // wrong length
		"!!!",                   // not base64url
	} {
		code, body, raw := do(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", "")
		if code != http.StatusGone {
			t.Fatalf("reveal(%q) = %d, want 410: %s", id, code, raw)
		}
		errObj, _ := body["error"].(map[string]any)
		if errObj["code"] != "gone" {
			t.Fatalf("reveal(%q) code = %v, want \"gone\"", id, errObj["code"])
		}
		bodies = append(bodies, errObj["message"].(string))
	}
	for i := range bodies {
		if bodies[i] != bodies[0] {
			t.Fatalf("the gone message differs between causes (%q vs %q) — they must be identical",
				bodies[0], bodies[i])
		}
	}
}

func TestCreateRejectsWhatItCannotStore(t *testing.T) {
	h, _ := testApp(t)

	for _, tc := range []struct {
		name string
		body string
		code string
	}{
		{"empty ciphertext", `{"ciphertext":"","ttl_seconds":3600}`, reasonEmpty},
		{"not base64url", `{"ciphertext":"!!!!","ttl_seconds":3600}`, reasonInvalid},
		{"oversized", `{"ciphertext":"` + strings.Repeat("A", secret.MaxCiphertextBytes+1) + `","ttl_seconds":3600}`, reasonTooLarge},
		{"ttl too short", `{"ciphertext":"` + ciphertext("x") + `","ttl_seconds":60}`, reasonTTL},
		{"ttl too long", `{"ciphertext":"` + ciphertext("x") + `","ttl_seconds":2592000}`, reasonTTL},
		{"negative ttl", `{"ciphertext":"` + ciphertext("x") + `","ttl_seconds":-1}`, reasonTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body, raw := do(t, h, http.MethodPost, "/api/secrets", tc.body)
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("create = %d, want 422: %s", code, raw)
			}
			errObj, _ := body["error"].(map[string]any)
			if errObj["code"] != tc.code {
				t.Fatalf("error code = %v, want %q", errObj["code"], tc.code)
			}
		})
	}
}

func TestOmittedTTLGetsTheDefault(t *testing.T) {
	h, _ := testApp(t)
	code, body, raw := do(t, h, http.MethodPost, "/api/secrets",
		`{"ciphertext":"`+ciphertext("x")+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("create without ttl_seconds = %d, want 201: %s", code, raw)
	}
	if got := body["ttl_seconds"].(float64); int(got) != int(secret.DefaultTTL.Seconds()) {
		t.Fatalf("ttl_seconds = %v, want the default %v", got, secret.DefaultTTL.Seconds())
	}
}

// There must be no way to hand hush a plaintext secret. If a field like
// "secret" or "plaintext" were ever accepted, the server would become able to
// read secrets and the guarantee in the README would quietly become a promise
// about our conduct instead of a property of the design.
func TestThereIsNoPlaintextIntakeField(t *testing.T) {
	h, _ := testApp(t)
	for _, body := range []string{
		`{"secret":"hunter2","ttl_seconds":3600}`,
		`{"plaintext":"hunter2","ttl_seconds":3600}`,
		`{"ciphertext":"` + ciphertext("x") + `","plaintext":"hunter2"}`,
	} {
		code, _, raw := do(t, h, http.MethodPost, "/api/secrets", body)
		if code == http.StatusCreated {
			t.Fatalf("create accepted a plaintext field: %s -> %s", body, raw)
		}
	}
}

// The client-side crypto IS the product. If either page stops shipping it, the
// service silently becomes a plaintext store or a broken reader, and every
// other test here would still pass.
func TestPagesShipTheClientSideCrypto(t *testing.T) {
	h, _ := testApp(t)

	_, _, create := do(t, h, http.MethodGet, "/", "")
	for _, want := range []string{
		"AES-GCM",          // the cipher
		"crypto.subtle",    // in the browser, not on the server
		"generateKey",      // the key is minted client-side
		`"#" + sealed.key`, // and leaves only in the fragment
		"/api/secrets",     // ciphertext is what gets posted
	} {
		if !strings.Contains(create, want) {
			t.Fatalf("the create page no longer contains %q — check it still encrypts client-side", want)
		}
	}
	// The create page must never post a plaintext field.
	for _, forbidden := range []string{`"plaintext"`, `"secret":`} {
		if strings.Contains(create, forbidden) {
			t.Fatalf("the create page mentions %s, which suggests it sends plaintext", forbidden)
		}
	}

	_, _, reveal := do(t, h, http.MethodGet, "/s/"+strings.Repeat("A", 43), "")
	for _, want := range []string{
		"location.hash",        // the key comes from the fragment
		"crypto.subtle",        // decryption is client-side
		"/reveal",              // and only POST consumes
		"history.replaceState", // the key is dropped from the address bar after
	} {
		if !strings.Contains(reveal, want) {
			t.Fatalf("the reveal page no longer contains %q", want)
		}
	}
}

func TestPagesAreNotCacheable(t *testing.T) {
	h, _ := testApp(t)
	for _, path := range []string{"/", "/s/" + strings.Repeat("A", 43)} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		// A cached reveal page in a shared proxy is a copy of a one-time URL.
		if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Fatalf("%s Cache-Control = %q, want no-store", path, cc)
		}
		if ref := w.Header().Get("Referrer-Policy"); ref != "no-referrer" {
			t.Fatalf("%s Referrer-Policy = %q, want no-referrer — a click could otherwise leak the URL", path, ref)
		}
	}
}
