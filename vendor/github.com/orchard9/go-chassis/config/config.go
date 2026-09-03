// Package config is the typed, validated environment loader used at the
// composition root (services/*/main.go, workers/*/main.go) — the ONLY place env
// is read. A Loader accumulates parse/validation errors so boot fails closed
// with one actionable message instead of silently running on bad config.
//
// Secrets (DB passwords, API keys) do NOT belong here — they come from a
// secret source (manager / file). This loads non-secret wiring only.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Loader reads env vars with defaults and validation, collecting every error.
type Loader struct {
	errs []error
}

// New returns an empty Loader.
func New() *Loader { return &Loader{} }

// String returns the env value or def when unset/empty.
func (l *Loader) String(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// Strings splits a comma-separated env value, trimming each entry and dropping
// empties, or returns def when unset. Used for allowlists (CORS origins,
// trusted proxies) where a platform has more than one legitimate value and a
// single-string field would silently serve only the first.
func (l *Loader) Strings(key string, def []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

// Required returns the env value or records an error when unset/empty.
func (l *Loader) Required(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		l.errs = append(l.errs, fmt.Errorf("%s is required", key))
	}
	return v
}

// Int parses an integer env value, recording an error on a malformed value.
func (l *Loader) Int(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		l.errs = append(l.errs, fmt.Errorf("%s: invalid int %q", key, raw))
		return def
	}
	return n
}

// Int64 parses a 64-bit integer env value, recording an error on a malformed
// value. Separate from Int because byte-size limits (body caps, artifact
// ceilings) legitimately exceed a 32-bit int on some platforms.
func (l *Loader) Int64(key string, def int64) int64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		l.errs = append(l.errs, fmt.Errorf("%s: invalid int64 %q", key, raw))
		return def
	}
	return n
}

// Port parses and bounds-checks a TCP port (1..65535).
func (l *Loader) Port(key string, def int) int {
	n := l.Int(key, def)
	if n < 1 || n > 65535 {
		l.errs = append(l.errs, fmt.Errorf("%s: port %d out of range 1..65535", key, n))
		return def
	}
	return n
}

// Duration parses a Go duration (e.g. 5s, 1h), recording an error if malformed.
func (l *Loader) Duration(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		l.errs = append(l.errs, fmt.Errorf("%s: invalid duration %q", key, raw))
		return def
	}
	return d
}

// Bool parses a boolean (1/t/true/0/f/false), recording an error if malformed.
func (l *Loader) Bool(key string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		l.errs = append(l.errs, fmt.Errorf("%s: invalid bool %q", key, raw))
		return def
	}
	return b
}

// OneOf returns the env value when it is in allowed, else records an error.
func (l *Loader) OneOf(key, def string, allowed ...string) string {
	v := l.String(key, def)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	l.errs = append(l.errs, fmt.Errorf("%s: %q not one of %s", key, v, strings.Join(allowed, "|")))
	return def
}

// Err returns the joined validation errors, or nil when the config is clean.
func (l *Loader) Err() error { return errors.Join(l.errs...) }
