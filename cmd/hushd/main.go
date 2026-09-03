// Command hushd serves hush: one-time secret links.
//
// It stores ciphertext it cannot read. The encryption key is generated in the
// browser and travels only in the URL fragment, which browsers never transmit.
// See docs/ARCHITECTURE.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/orchard9/go-chassis/chassis"
	"github.com/orchard9/go-chassis/logging"

	"github.com/orchard9/hush/internal/secret"
	"github.com/orchard9/hush/internal/store"
	"github.com/orchard9/hush/internal/web"
)

// service is the log corpus's `service` value and the metrics prefix. It is a
// member of a closed enum shared with every other orchard9 emitter — the
// cluster's Vector sink indexes `service` as a stream field, so a new value is
// a coordinated decision, not a free string.
const service = "hush"

func main() {
	if err := run(); err != nil {
		// Boot failures go to stderr as well as the log: if logging itself is
		// what failed, the process must still say why before exiting.
		fmt.Fprintf(os.Stderr, "hushd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, cfgErr := loadConfig()

	// The logger is built before the config error is returned, so a
	// misconfiguration is REPORTED through the same corpus as everything else
	// rather than dying silently. cfg.Env is the zero value on failure, which
	// logging.Env normalises.
	log := logging.New(logging.Config{Service: service, Env: logging.Env(cfg.Env)})
	logging.SetFallback(log)

	if cfgErr != nil {
		// critical + category boot is the fail-closed contract: this is a
		// refusal to serve, which is the only thing critical is for.
		logging.Critical(context.Background(), log, "boot.config_invalid",
			"category", "boot", "error_type", "config_invalid", "error_msg", cfgErr.Error())
		return cfgErr
	}

	pages, err := web.New()
	if err != nil {
		logging.Critical(context.Background(), log, "boot.templates_invalid",
			"category", "boot", "error_type", "template_invalid", "error_msg", err.Error())
		return err
	}

	rdb, err := store.NewRedis(cfg.RedisURL)
	if err != nil {
		// The URL is malformed — a config defect, not an outage. Refuse to boot
		// rather than serve a store that can never work.
		logging.Critical(context.Background(), log, "boot.store_invalid",
			"category", "boot", "error_type", "store_invalid", "error_msg", err.Error())
		return err
	}
	defer func() { _ = rdb.Close() }()

	metrics := newMetrics()
	metrics.Prime()

	srv := &Server{cfg: cfg, store: rdb, pages: pages, metrics: metrics}

	app := chassis.New(chassis.Config{
		Service: service,
		Env:     cfg.Env,
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		// 128 KiB caps the body at the edge so an oversized upload is refused
		// before a handler allocates it. The 64 KiB ciphertext cap is enforced
		// separately in the handler; this is the outer bound including JSON
		// framing.
		MaxBodyBytes: 128 * 1024,
		AllowOrigins: cfg.AllowOrigins,
		Collectors:   metrics.Collectors(),
	}, log)

	// Readiness doubles as the store_up gauge, so the alert on Redis
	// reachability reads the same probe Kubernetes uses to route traffic —
	// rather than a second, separately-drifting health notion.
	app.Health("redis", func(ctx context.Context) error {
		err := rdb.Ping(ctx)
		if err != nil {
			metrics.StoreUp.Set(0)
			return err
		}
		metrics.StoreUp.Set(1)
		return nil
	})

	// Pages: no storage access, no rate limit. A link previewer hitting either
	// of these must be free and harmless.
	app.Get("/", srv.handleCreatePage)
	app.Get("/s/{id}", srv.handleRevealPage)

	limiter := &redisLimiter{store: rdb, cfg: cfg, metrics: metrics}
	app.Route("/api", func(r *chassis.Router) {
		// Rate limit applies to create only. A reveal succeeds at most once per
		// secret by construction, so there is nothing to throttle, and
		// throttling would let one busy NAT block a colleague's delivery.
		createMW := []chassis.Middleware{chassis.RateLimit(limiter, chassis.RateKey(cfg.TrustedProxyHops))}
		if cfg.RequireAuthToCreate {
			// The escape hatch for abuse. Reveal stays anonymous either way:
			// the recipient is external and holds no credential.
			createMW = append(createMW, chassis.RequireAuth(chassis.NewStaticToken(cfg.CreateToken)))
		}
		r.Post("/secrets", srv.handleCreate, createMW...)
		r.Post("/secrets/{id}/reveal", srv.handleReveal)
	})

	log.Info("boot.ready", "category", "boot",
		"port", cfg.Port,
		"rate_limit_creates", cfg.RateLimitCreates,
		"rate_limit_window_seconds", int64(cfg.RateLimitWindow.Seconds()),
		"max_ciphertext_bytes", secret.MaxCiphertextBytes,
		"default_ttl_seconds", int64(secret.DefaultTTL.Seconds()),
		"require_auth_to_create", cfg.RequireAuthToCreate)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// redisLimiter adapts the Redis fixed-window counter to chassis.RateLimiter and
// counts refusals, which is the abuse signal the alert rules watch.
type redisLimiter struct {
	store   *store.Redis
	cfg     Config
	metrics *Metrics
}

func (l *redisLimiter) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	ok, retry, err := l.store.AllowN(ctx, key, l.cfg.RateLimitCreates, l.cfg.RateLimitWindow)
	if err != nil {
		// Redis is unreachable. FAIL OPEN on the limiter specifically: the
		// alternative is that a Redis blip turns the rate limiter into a total
		// outage of a service whose whole job is delivering credentials during
		// incidents. The store call immediately after will fail anyway if Redis
		// is really down, so this cannot silently accept a secret it cannot
		// store — it just refuses at the right layer, with the right error.
		return true, 0, nil
	}
	if !ok {
		l.metrics.Limited.Inc()
	}
	return ok, retry, nil
}
