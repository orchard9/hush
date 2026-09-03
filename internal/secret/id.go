// Package secret holds hush's domain types and policy: identifiers, size and
// lifetime limits. It imports nothing outside the standard library, so the
// rules live in one place and are testable without Redis or HTTP.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
)

// IDBytes is the entropy behind a secret id. 256 bits makes enumeration a
// non-threat: an attacker guessing ids is not a scenario this service defends
// against with rate limits, it is a scenario arithmetic forecloses.
const IDBytes = 32

// idEncoding is base64url without padding, so an id is URL-safe, 43 characters,
// and needs no escaping in a path or a fragment.
var idEncoding = base64.RawURLEncoding

// ErrMalformedID is returned for a value that cannot be an id this service
// minted. Callers turn it into the same 410 as a missing secret — telling a
// caller that their id was well-formed but absent confirms the id space.
var ErrMalformedID = errors.New("malformed secret id")

// ID is a secret's identifier, and it IS the capability: anyone holding it can
// reveal the secret exactly once. It is therefore treated like a bearer token.
//
// Every accidental path prints a REDACTED form. An earlier version tried to
// prevent leaks by implementing no String() at all, which was wrong: Go's fmt
// prints unexported struct fields anyway, so `fmt.Sprintf("%v", id)` emitted
// the live id. Forbidding the method did not remove the leak, it only removed
// the chance to control it.
//
// So instead the safe form is the DEFAULT and the raw value needs an explicit
// call:
//
//	String()   -> "ID(a1b2c3d4e5f6)"   fmt %v, %s, string concatenation
//	LogValue() -> "a1b2c3d4e5f6"       every slog call site
//	MarshalJSON -> refuses             a response struct cannot leak one silently
//	Value()    -> the raw id           the two places it must escape
//
// Enforced by id_test.go, which fails if any of those starts emitting the raw
// value.
type ID struct {
	raw string
}

// NewID mints a fresh identifier from crypto/rand. It returns an error rather
// than panicking: a service that cannot get entropy must refuse to mint a
// secret, not mint a guessable one.
func NewID() (ID, error) {
	b := make([]byte, IDBytes)
	if _, err := rand.Read(b); err != nil {
		return ID{}, err
	}
	return ID{raw: idEncoding.EncodeToString(b)}, nil
}

// ParseID validates an id from a URL path. It checks the encoding and the
// decoded LENGTH, so a short-but-valid base64 string cannot become an id and
// widen the space a scanner has to cover.
func ParseID(s string) (ID, error) {
	if len(s) != idEncoding.EncodedLen(IDBytes) {
		return ID{}, ErrMalformedID
	}
	b, err := idEncoding.DecodeString(s)
	if err != nil || len(b) != IDBytes {
		return ID{}, ErrMalformedID
	}
	return ID{raw: s}, nil
}

// Value returns the raw id. Every call site is a place where the capability
// escapes, so there are deliberately few: the storage key and the created
// response body.
func (id ID) Value() string { return id.raw }

// IsZero reports whether this is the zero ID, which no minting path produces.
func (id ID) IsZero() bool { return id.raw == "" }

// LogHandle is the only form of an id that may be logged or reported: the first
// 12 hex characters of its SHA-256. It is stable, so one secret's create,
// reveal and gone lines correlate across the log corpus, and it is one-way, so
// a log reader cannot reveal the secret it refers to.
//
// 48 bits of a hash is not a secret-strength value and is not treated as one —
// it is a correlation handle. The preimage is 256 bits of entropy, so recovering
// an id from a handle is not feasible even though the handle is short.
func (id ID) LogHandle() string {
	if id.raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(id.raw))
	return hex.EncodeToString(sum[:])[:12]
}

// String is the redacted form, so `%v`, `%s` and string concatenation are all
// safe by default. Reaching the raw id requires Value().
func (id ID) String() string {
	if id.raw == "" {
		return "ID(zero)"
	}
	return "ID(" + id.LogHandle() + ")"
}

// LogValue makes every slog call site safe without the caller thinking about
// it: `log.Info("secret.created", "id", id)` emits the handle, not the
// capability. This is why the handlers can pass ids around without a review
// checklist for each log line.
func (id ID) LogValue() slog.Value { return slog.StringValue(id.LogHandle()) }

// MarshalJSON REFUSES rather than emitting either form.
//
// Emitting the raw id would leak a capability into any response struct that
// happened to embed an ID. Emitting the redacted form would be worse: it would
// produce a response that looks like it carries an id and does not, and the bug
// would surface as a broken link rather than a failed request. The two places
// an id legitimately reaches a client both call Value() explicitly.
func (id ID) MarshalJSON() ([]byte, error) {
	return nil, errors.New("secret.ID must not be serialised: call Value() at the one site that needs it")
}

// StorageKey is the Redis key holding this secret's ciphertext. The `hush:`
// prefix is what the Redis ACL user is scoped to (`~hush:*`), so a bug that
// built a key outside this prefix would be refused by the server rather than
// touching another tenant's keyspace.
func (id ID) StorageKey() string { return "hush:s:" + id.raw }
