package logging

import (
	"context"
	"log/slog"
)

type ctxKey int

const loggerKey ctxKey = iota

// Into returns a child context carrying log, so request-scoped fields
// (request_id, route, ...) added at the edge flow to every downstream call.
func Into(ctx context.Context, log *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, log)
}

// From returns the request-scoped logger stored in ctx, or the package fallback
// (set by SetFallback at boot) so a missing logger never panics or drops logs.
func From(ctx context.Context) *slog.Logger {
	if log, ok := ctx.Value(loggerKey).(*slog.Logger); ok && log != nil {
		return log
	}
	return fallback()
}
