// Package logging is the core structured logger: one JSON object per line on
// stdout, ready for any log agent (Fluent Bit, vector, the cloud's native
// collector) to ship. Fields: ts (ISO-8601 UTC, ms, Z), level, service + env
// (the only indexed stream fields — keep them closed enums), msg, plus caller
// attrs. Secrets/PII MUST NOT be logged; forbiddenKeys redacts common offenders
// as defense-in-depth behind code review + lint. See patterns/go-chassis.md.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// LevelCritical sits above slog.LevelError; it maps to the "critical" enum and
// is reserved for fail-closed boot/serve refusal (wire it to a page).
const LevelCritical = slog.Level(12)

// Config selects the closed-enum stream fields the log store indexes.
type Config struct {
	Service string // closed enum, keep small (e.g. api, job-worker)
	Env     string // dev | staging | prod
}

// New returns the core logger writing the JSON wire format to stdout.
func New(cfg Config) *slog.Logger { return newTo(os.Stdout, cfg) }

// NewTo returns the core logger writing the JSON wire format to w. Server mode
// uses New (stdout); a bounded maintenance command uses this to send its
// operational diagnostics to stderr, keeping stdout a clean machine-readable
// result stream a caller can parse without stripping log lines out of it.
func NewTo(w io.Writer, cfg Config) *slog.Logger { return newTo(w, cfg) }

func newTo(w io.Writer, cfg Config) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: replace,
	})
	return slog.New(h).With("service", cfg.Service, "env", cfg.Env)
}

func replace(groups []string, a slog.Attr) slog.Attr {
	if forbiddenKeys[a.Key] { // defense-in-depth secret/PII redaction
		return slog.String(a.Key, "[REDACTED]")
	}
	// The built-in rewrites below apply only to the record's own time/level
	// attrs, which slog always passes at the top level. A caller attr that
	// happens to be named "time" or "level" — log.Info("m", "level", "high") —
	// arrives here too, so both the group depth and the value kind are checked
	// before converting. An unchecked assertion here panics the process inside
	// the logger every binary depends on.
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		if a.Value.Kind() != slog.KindTime {
			return a
		}
		// ts: ISO-8601 UTC, ms precision, Z suffix.
		a.Key = "ts"
		a.Value = slog.StringValue(a.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z07:00"))
	case slog.LevelKey:
		lvl, ok := a.Value.Any().(slog.Level)
		if !ok {
			return a
		}
		a.Key = "level"
		a.Value = slog.StringValue(levelString(lvl))
	}
	return a
}

func levelString(l slog.Level) string {
	switch {
	case l >= LevelCritical:
		return "critical"
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}

// forbiddenKeys are field names that MUST NOT reach the log corpus. Extend it
// with YOUR product's sensitive fields (PII, PII, financial, tokens).
var forbiddenKeys = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true,
	"api_key": true, "apikey": true, "authorization": true, "cookie": true,
	"ssn": true, "email": true, "phone": true,
}

var (
	fallbackMu  sync.RWMutex
	fallbackLog *slog.Logger
)

// SetFallback installs the logger From returns when no request-scoped logger is
// in context. Set once at boot from the composition root.
func SetFallback(l *slog.Logger) {
	fallbackMu.Lock()
	defer fallbackMu.Unlock()
	fallbackLog = l
}

func fallback() *slog.Logger {
	fallbackMu.RLock()
	l := fallbackLog
	fallbackMu.RUnlock()
	if l != nil {
		return l
	}
	return New(Config{Service: "unknown", Env: "dev"})
}

// Critical logs at the fail-closed level (boot/serve refusal). Bind to a page.
func Critical(ctx context.Context, l *slog.Logger, msg string, args ...any) {
	l.Log(ctx, LevelCritical, msg, args...)
}

// Env normalizes an APP_ENV value (local|dev|staging|prod, or a gcp-* / aws-*
// prefix) to the log env enum.
func Env(appEnv string) string {
	switch {
	case strings.HasSuffix(appEnv, "prod"):
		return "prod"
	case strings.HasSuffix(appEnv, "staging"):
		return "staging"
	default:
		return "dev"
	}
}
