package secret

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidateCiphertext(t *testing.T) {
	valid := base64.RawURLEncoding.EncodeToString([]byte("nonce+ciphertext bytes"))

	for _, tc := range []struct {
		name string
		in   string
		want error
	}{
		{"a real base64url blob", valid, nil},
		{"empty", "", ErrCiphertextEmpty},
		{"not base64url", "!!!not base64!!!", ErrCiphertextInvalid},
		// Standard base64 uses + and /, which are not URL-safe. Accepting them
		// would mean two spellings of one ciphertext and a client that works in
		// one browser and not another.
		{"standard base64 alphabet", "YWJj+/8=", ErrCiphertextInvalid},
		{"padded", "YWJjZA==", ErrCiphertextInvalid},
		{"at the cap", strings.Repeat("A", MaxCiphertextBytes), nil},
		{"one byte over the cap", strings.Repeat("A", MaxCiphertextBytes+1), ErrCiphertextTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCiphertext(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ValidateCiphertext() = %v, want %v", err, tc.want)
			}
		})
	}
}

// The size check must happen BEFORE the decode, or a 64 KiB+ body costs a
// decoded copy before being refused — which is the cheap half of a memory DoS.
func TestOversizedCiphertextIsRefusedWithoutDecoding(t *testing.T) {
	// Deliberately not valid base64. If the implementation decoded first, this
	// would come back as ErrCiphertextInvalid instead of ErrCiphertextTooLarge.
	huge := strings.Repeat("!", MaxCiphertextBytes+1)
	if err := ValidateCiphertext(huge); !errors.Is(err, ErrCiphertextTooLarge) {
		t.Fatalf("ValidateCiphertext(oversized invalid) = %v, want ErrCiphertextTooLarge — "+
			"the size gate must precede the decode", err)
	}
}

func TestResolveTTL(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
		err  error
	}{
		{"unspecified takes the default", 0, DefaultTTL, nil},
		{"at the minimum", MinTTL, MinTTL, nil},
		{"at the maximum", MaxTTL, MaxTTL, nil},
		{"a normal day", 24 * time.Hour, 24 * time.Hour, nil},
		{"below the minimum", MinTTL - time.Second, 0, ErrTTLOutOfRange},
		{"above the maximum", MaxTTL + time.Second, 0, ErrTTLOutOfRange},
		{"negative", -time.Hour, 0, ErrTTLOutOfRange},
		{"absurd", 3650 * 24 * time.Hour, 0, ErrTTLOutOfRange},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveTTL(tc.in)
			if !errors.Is(err, tc.err) {
				t.Fatalf("ResolveTTL(%s) error = %v, want %v", tc.in, err, tc.err)
			}
			if err == nil && got != tc.want {
				t.Fatalf("ResolveTTL(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// An out-of-range TTL must be an ERROR and never a silent clamp. A caller who
// asked for 30 days and was quietly given 7 would believe their link outlives
// its real expiry, and would discover otherwise when the recipient could not
// open it.
func TestOutOfRangeTTLIsRefusedNotClamped(t *testing.T) {
	got, err := ResolveTTL(30 * 24 * time.Hour)
	if err == nil {
		t.Fatalf("ResolveTTL(30d) silently returned %s instead of refusing", got)
	}
	if got != 0 {
		t.Fatalf("ResolveTTL returned %s alongside an error; callers must not see a usable value", got)
	}
}
