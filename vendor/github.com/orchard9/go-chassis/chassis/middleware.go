package chassis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/orchard9/go-chassis/logging"
)

// chain composes edge middleware so mw[0] is outermost (runs first).
func chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// statusRecorder captures the response status for logging/metrics and survives
// double WriteHeader; it forwards Flush so SSE/streaming handlers still work.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
	// streamed is set by Context.Stream. It keeps a connection an operator
	// held open for twenty minutes out of the request-latency histogram.
	streamed bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.status = code
	r.wrote = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the wrapped writer to http.ResponseController, which is how a
// streaming handler clears the server's WriteTimeout for its own connection.
// Without it ResponseController stops at this wrapper and every deadline call
// returns ErrNotSupported — the response is then cut mid-stream at
// RequestTimeout+socketHeadroom with no error the handler can report.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

type traceIDKey struct{}

// TraceIDFrom returns the request's trace id, or false outside a chassis-handled
// request. shared/httpclient uses it to propagate traceparent downstream.
func TraceIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(traceIDKey{}).(string)
	return id, ok
}

// traceIDFromHeader extracts the 32-hex trace-id from a W3C traceparent header
// ("00-<32hex>-<16hex>-<flags>"); on absence/malformation it generates one.
func traceIDFromHeader(traceparent string) string {
	parts := strings.Split(traceparent, "-")
	if len(parts) == 4 && len(parts[1]) == 32 && parts[1] != strings.Repeat("0", 32) {
		if _, err := hex.DecodeString(parts[1]); err == nil {
			return parts[1]
		}
	}
	return newRequestID()
}

// instrument is the core edge middleware: it assigns/propagates a request_id,
// builds the request-scoped logger, applies the per-request timeout, counts
// in-flight requests, RECOVERS panics (so the access log + metrics observe the
// real 500), and emits one access line + RED metrics. The route label is the
// matched ServeMux pattern (bounded cardinality), never the raw path.
func (a *App) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)

		// Derive the trace id from W3C traceparent (or generate one) so logs +
		// downstream calls correlate. trace_id is a regular log field, NEVER a
		// stream field (high cardinality).
		trace := traceIDFromHeader(r.Header.Get("traceparent"))
		w.Header().Set("X-Trace-Id", trace)

		log := a.log.With("request_id", id, "trace_id", trace)
		ctx := context.WithValue(r.Context(), traceIDKey{}, trace)
		ctx = logging.Into(ctx, log)
		if a.cfg.RequestTimeout > 0 {
			// A deadline cannot be removed from a derived context, so the
			// pre-timeout one is carried alongside for Context.Stream: a
			// server-sent-events response is open for minutes by design and
			// must stay bound to client disconnect and drain, not to the
			// per-request budget every other route wants.
			ctx = context.WithValue(ctx, untimedKey{}, ctx)
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, a.cfg.RequestTimeout)
			defer cancel()
		}
		r2 := r.WithContext(ctx)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		a.metrics.inflight.Inc()
		defer a.metrics.inflight.Dec()
		start := time.Now()

		func() {
			defer func() {
				if rv := recover(); rv != nil {
					log.Error("panic.recovered", "category", "panic",
						"error_type", "panic", "error_msg", fmt.Sprint(rv),
						"stack", string(debug.Stack()))
					if !rec.wrote {
						rec.Header().Set("Content-Type", "application/json; charset=utf-8")
						rec.WriteHeader(http.StatusInternalServerError)
						// Same envelope as writeError, request_id included. A panic
						// is precisely when a user needs an id to quote, so this is
						// the worst response to leave it out of.
						_, _ = fmt.Fprintf(rec,
							`{"error":{"code":"internal","message":"internal error","request_id":%q}}`, id)
					}
				}
			}()
			next.ServeHTTP(rec, r2)
		}()

		route := routeLabel(r2.Pattern)
		dur := time.Since(start)
		log.Debug("http.request",
			"http_method", r.Method, "http_route", route, "http_path", r.URL.Path,
			"http_status", rec.status, "http_duration_ms", dur.Milliseconds(),
			"http_streamed", rec.streamed)
		// A stream's elapsed time is how long an operator left a tab open, not
		// how long the service took to answer. Feeding it to the latency
		// histogram fired HighRequestLatency the first time somebody opened the
		// console and would poison every latency panel for the whole service,
		// so a streamed response is counted but not timed.
		if rec.streamed {
			a.metrics.countOnly(r.Method, route, rec.status)
			return
		}
		a.metrics.observe(r.Method, route, rec.status, dur)
	})
}

// routeLabel reduces a matched ServeMux pattern ("GET /v1/x/{id}") to its path
// shape ("/v1/x/{id}") for a bounded metrics/log label — never the raw path.
func routeLabel(pattern string) string {
	if pattern == "" {
		return "other"
	}
	if i := strings.IndexByte(pattern, ' '); i >= 0 { // drop the "METHOD " prefix
		pattern = pattern[i+1:]
	}
	return pattern
}

// secureHeaders sets conservative response headers for a JSON API (no inline
// content, no framing). HSTS is emitted only in prod, where TLS terminates.
func (a *App) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if a.cfg.Env == "prod" {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// cors echoes the request Origin when it is on the allowlist and answers
// preflight. A platform serves more than one browser surface (admin, tenant,
// operator), so the allowlist is a set and the response echoes the matched
// origin rather than a single fixed value — echoing a fixed origin breaks every
// UI but one, and echoing the request unchecked is an open CORS policy.
func (a *App) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// The response body depends on Origin whenever an allowlist is
		// configured, so Vary is set even on a non-match — otherwise a shared
		// cache can serve an allowed origin's response to a denied one.
		if len(a.cfg.AllowOrigins) > 0 {
			h.Add("Vary", "Origin")
		}
		if origin := r.Header.Get("Origin"); origin != "" && a.originAllowed(origin) {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-Id, Idempotency-Key")
			// Without this the browser can send X-Request-Id but cannot READ the
			// one we echo back, so a cross-origin SPA has no id to show the user
			// next to an error toast. Allow-Headers governs the request; only
			// Expose-Headers governs what JS may read off the response.
			h.Set("Access-Control-Expose-Headers", "X-Request-Id, X-Trace-Id")
			h.Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originAllowed reports whether origin is on the configured allowlist. Matching
// is exact: no suffix or wildcard matching, because "endswith example.com"
// also matches "evil-example.com".
func (a *App) originAllowed(origin string) bool {
	for _, allowed := range a.cfg.AllowOrigins {
		if allowed == origin {
			return true
		}
	}
	return false
}
