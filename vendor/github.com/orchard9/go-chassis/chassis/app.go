// Package chassis is the shared HTTP framework every service surface is built
// on (the API service, any second service, the worker's health endpoint). It
// owns the edge concerns so handlers stay thin: routing (stdlib ServeMux), the
// request Context + JSON envelope, the error model, the edge middleware chain
// (recover, request-id, structured logging, RED metrics, security headers,
// CORS), pluggable health probes, /metrics, an auth seam, and two-phase
// graceful shutdown. See patterns/go-chassis.md.
package chassis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Config is the chassis runtime configuration. Zero values get safe defaults
// (withDefaults); Service + Addr are the only fields a caller must set.
type Config struct {
	Service         string        // closed-enum service name (metrics/logs)
	Env             string        // dev | staging | prod
	Addr            string        // listen address, e.g. ":16150"
	AllowOrigins    []string      // exact-match CORS allowlist for browser UIs (empty = none)
	MaxBodyBytes    int64         // request body cap (Bind) — default 1 MiB
	RequestTimeout  time.Duration // per-request context deadline — default 15s
	ReadyTimeout    time.Duration // readiness check budget — default 2s
	DrainDelay      time.Duration // phase-1 drain wait before Shutdown — default 5s
	ShutdownTimeout time.Duration // phase-2 in-flight drain — default 25s

	// Collectors are service-owned Prometheus collectors registered on the
	// app's private registry alongside the RED/Go/process ones, so /metrics is
	// one scrape and there is no package-level default registry to collide in.
	// Composition roots pass domain metrics here.
	Collectors []prometheus.Collector

	// Validator, if set, runs on every Context.Bind after JSON decode; a non-nil
	// result becomes 422 Unprocessable. Wire shared/validate at the composition root.
	Validator func(any) error
	// EdgeMiddleware are extra http.Handler wrappers applied OUTERMOST (before
	// secureHeaders) — e.g. a tracing span middleware from shared/tracing.
	// Composition roots inject these; the chassis stays dependency-light.
	EdgeMiddleware []func(http.Handler) http.Handler
}

// socketHeadroom is how far the socket deadlines outlive the per-request
// context deadline.
//
// ReadTimeout and WriteTimeout used to be hardcoded at 15s while
// RequestTimeout was configurable, so a surface that raised the request budget
// (reeld runs 120s so a worker can stream a rendered mp4 on the completion
// call) still had its socket cut at 15s. That reads as a proxy 502 rather than
// the board's own 413/504, which is a completely different bug to chase.
//
// The socket MUST outlive the context, never the reverse: when the context
// expires the handler returns and the error envelope is written on a socket
// that is still open. Cutting the socket first truncates the response mid-body.
const socketHeadroom = 30 * time.Second

func (c *Config) withDefaults() {
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 1 << 20
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 15 * time.Second
	}
	if c.ReadyTimeout == 0 {
		c.ReadyTimeout = 2 * time.Second
	}
	if c.DrainDelay == 0 {
		c.DrainDelay = 5 * time.Second
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = 25 * time.Second
	}
}

// App is one HTTP surface: routes + health checks + background workers wired at
// the composition root, served by Run.
type App struct {
	cfg      Config
	log      *slog.Logger
	mux      *http.ServeMux
	metrics  *metrics
	checks   []namedCheck
	bg       []func(context.Context) error
	routes   []Route
	draining atomic.Bool
	// closing is closed when phase-1 drain starts. Request handlers that hold
	// a connection open indefinitely (SSE) select on it so they end at the
	// drain delay instead of stalling Shutdown for the full ShutdownTimeout.
	closing chan struct{}
}

// Route is one registered endpoint. Exposed so a spec-drift test can reconcile
// the OpenAPI document against what the router actually serves — a hand-kept
// list of paths diverges from the code silently, which is the whole failure
// mode API docs have.
type Route struct {
	Method  string
	Pattern string
}

// New builds an App and registers the always-on public routes: /metrics,
// /healthz (liveness), /readyz (readiness).
func New(cfg Config, log *slog.Logger) *App {
	cfg.withDefaults()
	a := &App{
		cfg: cfg, log: log,
		mux:     http.NewServeMux(),
		metrics: newMetrics(cfg.Service, cfg.Collectors...),
		closing: make(chan struct{}),
	}
	a.mux.Handle("GET /metrics", a.metrics.handler())
	a.mux.Handle("GET /healthz", a.toHTTP(a.handleLive))
	a.mux.Handle("GET /readyz", a.toHTTP(a.handleReady))
	return a
}

// toHTTP adapts a HandlerFunc to net/http, mapping a returned error to the
// JSON error envelope.
func (a *App) toHTTP(h HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := &Context{
			w: w, r: r,
			maxBytes: a.cfg.MaxBodyBytes,
			validate: a.cfg.Validator,
			closing:  a.closing,
		}
		if err := h(c); err != nil {
			a.writeError(c, err)
		}
	})
}

// writeError logs the failure (5xx at error, 4xx at debug — both with the
// internal cause) and writes the client envelope, which never carries the cause
// or any secret.
func (a *App) writeError(c *Context, err error) {
	e := asError(err)
	log := c.Log()
	// The cause rides on BOTH branches. Error.cause is documented as
	// "logged server-side", and dropping it on 4xx made that false for every
	// cause the framework attaches — Bind attaches one on 400, 413 and 422 and
	// nothing else ever sees it. The visible symptom: a rejected body logged as
	// bare `bad_request` with no field name, so the same unexplained-rejection
	// hunt WorkerEligible's reason string exists to prevent on the lease path.
	cause := e.Msg
	if e.cause != nil {
		cause = e.cause.Error()
	}
	if e.Status >= http.StatusInternalServerError {
		log.Error("request.error", "category", "request",
			"error_type", e.Code, "http_status", e.Status, "error_msg", cause)
	} else {
		log.Debug("request.rejected", "category", "request",
			"error_type", e.Code, "http_status", e.Status, "error_msg", cause)
	}
	// request_id rides in the body, not just the X-Request-Id header. A browser
	// on a cross-origin deployment cannot read a response header unless it is
	// explicitly exposed, so a body without it leaves the user with an error and
	// nothing to quote to support. The Rust track's error.rs declares this exact
	// triple as the contract for every surface; omitting it here made that claim
	// false for half the projects this skill generates.
	rid := c.w.Header().Get("X-Request-Id")
	if rid == "" {
		// Sentinel, matching the Rust track. A literal "-" is itself the signal
		// that the request-id middleware is not wired, which an absent key is not.
		rid = "-"
	}
	_ = c.JSON(e.Status, map[string]any{
		"error": map[string]any{"code": e.Code, "message": e.Msg, "request_id": rid},
	})
}

func (a *App) register(method, pattern string, h HandlerFunc, mw []Middleware) {
	for i := len(mw) - 1; i >= 0; i-- { // mw[0] outermost
		h = mw[i](h)
	}
	a.routes = append(a.routes, Route{Method: method, Pattern: pattern})
	a.mux.Handle(method+" "+pattern, a.toHTTP(h))
}

// Routes returns every route registered through Get/Post/Handle/Route, in
// registration order. The always-on probes (/healthz, /readyz, /metrics) are
// registered directly on the mux and deliberately excluded — they are chassis
// infrastructure, not part of a service's documented API surface.
func (a *App) Routes() []Route {
	out := make([]Route, len(a.routes))
	copy(out, a.routes)
	return out
}

// Get/Post/Handle register a top-level route with optional route middleware.
func (a *App) Get(pattern string, h HandlerFunc, mw ...Middleware) { a.register("GET", pattern, h, mw) }
func (a *App) Post(pattern string, h HandlerFunc, mw ...Middleware) {
	a.register("POST", pattern, h, mw)
}
func (a *App) Handle(method, pattern string, h HandlerFunc, mw ...Middleware) {
	a.register(method, pattern, h, mw)
}

// Route groups routes under a path prefix with shared middleware (e.g. auth).
func (a *App) Route(prefix string, fn func(r *Router)) { fn(&Router{app: a, prefix: prefix}) }

// Router registers routes under a prefix, applying group middleware to each.
type Router struct {
	app    *App
	prefix string
	mw     []Middleware
}

// Use adds middleware applied to every route registered on this Router.
func (r *Router) Use(mw ...Middleware) { r.mw = append(r.mw, mw...) }

func (r *Router) Get(pattern string, h HandlerFunc, mw ...Middleware) {
	r.handle("GET", pattern, h, mw)
}
func (r *Router) Post(pattern string, h HandlerFunc, mw ...Middleware) {
	r.handle("POST", pattern, h, mw)
}
func (r *Router) Delete(pattern string, h HandlerFunc, mw ...Middleware) {
	r.handle("DELETE", pattern, h, mw)
}

// Handle registers any method under the group prefix.
func (r *Router) Handle(method, pattern string, h HandlerFunc, mw ...Middleware) {
	r.handle(method, pattern, h, mw)
}

func (r *Router) handle(method, pattern string, h HandlerFunc, mw []Middleware) {
	all := make([]Middleware, 0, len(r.mw)+len(mw))
	all = append(all, r.mw...)
	all = append(all, mw...)
	r.app.register(method, r.prefix+pattern, h, all)
}

// Health registers a named readiness dependency check.
func (a *App) Health(name string, fn CheckFunc) {
	a.checks = append(a.checks, namedCheck{name: name, fn: fn})
}

// Background registers a worker run with the server lifecycle; it receives a
// context cancelled on shutdown and Run waits for it to return.
func (a *App) Background(fn func(context.Context) error) { a.bg = append(a.bg, fn) }

// Handler returns the fully composed edge chain over the route mux — used by Run
// and available for in-process tests. Order (outermost first): any injected
// EdgeMiddleware (e.g. tracing), then secureHeaders, instrument, CORS.
func (a *App) Handler() http.Handler {
	mw := make([]func(http.Handler) http.Handler, 0, len(a.cfg.EdgeMiddleware)+3)
	mw = append(mw, a.cfg.EdgeMiddleware...)
	mw = append(mw, a.secureHeaders, a.instrument, a.cors)
	return chain(a.mux, mw...)
}

// Run starts the server and blocks until ctx is cancelled (SIGINT/SIGTERM) or
// the listener fails. Shutdown is two-phase: flip readiness to 503 so the load
// balancer drains the pod, wait DrainDelay, then Shutdown in-flight requests
// under ShutdownTimeout (DrainDelay + ShutdownTimeout MUST be < the k8s grace
// period). Liveness stays 200 throughout so the pod is drained, never killed.
func (a *App) Run(ctx context.Context) error {
	// The socket deadlines track RequestTimeout, they are not independent
	// knobs: see socketHeadroom. ReadTimeout has to clear a full body upload
	// (reeld takes a rendered mp4 on the completion call) and WriteTimeout a
	// full response, both of which are bounded by the request budget.
	srv := &http.Server{
		Addr:              a.cfg.Addr,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 5 * time.Second, // Slowloris guard
		ReadTimeout:       a.cfg.RequestTimeout + socketHeadroom,
		WriteTimeout:      a.cfg.RequestTimeout + socketHeadroom,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, fn := range a.bg {
		wg.Add(1)
		go func(fn func(context.Context) error) {
			defer wg.Done()
			a.superviseBackground(runCtx, fn)
		}(fn)
	}

	errc := make(chan error, 1)
	go func() {
		a.log.Info("server.listening", "http_addr", a.cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		cancel()
		wg.Wait()
		return err
	case <-runCtx.Done():
		a.draining.Store(true) // phase 1: readiness -> 503, LB drains the pod
		// Long-lived streams end here rather than at phase 2: an SSE client
		// that reconnects during the drain delay lands on a pod that is still
		// serving, instead of one that is 25s from closing under it.
		close(a.closing)
		a.log.Info("server.draining", "category", "shutdown", "drain_delay_ms", a.cfg.DrainDelay.Milliseconds())
		time.Sleep(a.cfg.DrainDelay)

		sctx, scancel := context.WithTimeout(context.Background(), a.cfg.ShutdownTimeout) // phase 2: drain in-flight
		defer scancel()
		err := srv.Shutdown(sctx)
		cancel()
		wg.Wait()
		a.log.Info("server.stopped", "category", "shutdown")
		return err
	}
}

// superviseBackground runs one background worker, restarting it with backoff if
// it panics or returns an error.
//
// Without this a panic in an auxiliary worker takes the whole process down,
// including HTTP serving — so a bug in, say, artifact retention would stop the
// board handing out leases. That asymmetry is surprising, because request
// handlers already get panic recovery from the instrument middleware; this
// gives background work the same protection.
//
// Restarting rather than merely recovering matters just as much: a worker that
// dies quietly leaves its job undone forever with a green readiness probe, and
// nobody discovers retention stopped until a disk fills.
func (a *App) superviseBackground(ctx context.Context, fn func(context.Context) error) {
	const (
		minBackoff = time.Second
		maxBackoff = time.Minute
	)
	backoff := minBackoff

	for {
		err, panicked := runBackgroundOnce(ctx, fn)
		switch {
		case ctx.Err() != nil:
			// Shutdown. A worker returning on a cancelled context is the
			// normal path, not a failure.
			return
		case err == nil && !panicked:
			// A clean return before shutdown means the worker considers its
			// job finished. Respect that rather than spinning it forever.
			return
		case panicked:
			a.log.Error("background.panicked", "category", "worker",
				"error_type", "worker_panic", "error_msg", err.Error(),
				"restart_in_ms", backoff.Milliseconds())
		default:
			a.log.Error("background.failed", "category", "worker",
				"error_type", "worker_error", "error_msg", err.Error(),
				"restart_in_ms", backoff.Milliseconds())
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// runBackgroundOnce invokes fn, converting a panic into an error so the
// supervisor can treat both failure modes alike. The stack is attached because
// a recovered panic with no stack is nearly unactionable.
func runBackgroundOnce(ctx context.Context, fn func(context.Context) error) (err error, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			err = fmt.Errorf("panic: %v\n%s", r, debug.Stack())
		}
	}()
	err = fn(ctx)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err, false
}
