package secret

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// Size and lifetime policy. Every bound here is a product decision with a
// reason, not a tuning knob:
//
//   - MaxCiphertextBytes keeps hush a courier for credentials rather than a file
//     host. 64 KiB of AES-GCM holds roughly 48 KiB of plaintext, which is a very
//     large credential and a very small file.
//   - MinTTL exists because a link that expires before the recipient reads their
//     messages is a support ticket, not a security win.
//   - MaxTTL bounds exposure. The residual risk in this design is the key sitting
//     in a browser history entry, and a week is as long as that is defensible.
const (
	MaxCiphertextBytes = 64 * 1024
	MinTTL             = 5 * time.Minute
	MaxTTL             = 7 * 24 * time.Hour
	DefaultTTL         = 24 * time.Hour
)

// Validation failures. Each maps to one API error code, so a caller can branch
// on the cause without parsing prose.
var (
	ErrCiphertextEmpty    = errors.New("ciphertext is empty")
	ErrCiphertextTooLarge = errors.New("ciphertext exceeds the size limit")
	ErrCiphertextInvalid  = errors.New("ciphertext is not valid base64url")
	ErrTTLOutOfRange      = errors.New("ttl is outside the permitted range")
)

// ciphertextEncoding matches what the browser produces: base64url, unpadded.
var ciphertextEncoding = base64.RawURLEncoding

// ValidateCiphertext checks what the server is ABLE to check. hush cannot
// verify that the bytes decrypt, because it has no key — by design. So it
// verifies the two things it can: that the encoding is what this service's
// clients produce, and that the size is inside the cap.
//
// The encoding check is not cosmetic. Without it, hush becomes a store for
// arbitrary bytes addressable by URL, which is a different and much less
// defensible service than the one described in the README.
func ValidateCiphertext(ciphertext string) error {
	switch {
	case ciphertext == "":
		return ErrCiphertextEmpty
	case len(ciphertext) > MaxCiphertextBytes:
		// Measured on the encoded form, which is what is stored and what
		// bounds memory. Checked BEFORE decoding so an oversized body is
		// rejected without allocating its decoded copy.
		return fmt.Errorf("%w: %d > %d bytes", ErrCiphertextTooLarge, len(ciphertext), MaxCiphertextBytes)
	}
	if _, err := ciphertextEncoding.DecodeString(ciphertext); err != nil {
		return ErrCiphertextInvalid
	}
	return nil
}

// ResolveTTL turns a caller's requested lifetime into the one that will be
// used. Zero means "unspecified" and gets the default.
//
// An out-of-range value is an ERROR, never a silent clamp. A caller who asked
// for 30 days and got 7 without being told would believe their link outlives
// its actual expiry, and would find out when the recipient could not open it.
func ResolveTTL(requested time.Duration) (time.Duration, error) {
	if requested == 0 {
		return DefaultTTL, nil
	}
	if requested < MinTTL || requested > MaxTTL {
		return 0, fmt.Errorf("%w: %s not in [%s, %s]", ErrTTLOutOfRange, requested, MinTTL, MaxTTL)
	}
	// Truncate to whole seconds: the wire format is seconds and Redis EX takes
	// seconds, so keeping sub-second precision would make the expires_at we
	// report disagree with the expiry Redis enforces.
	return requested.Truncate(time.Second), nil
}
