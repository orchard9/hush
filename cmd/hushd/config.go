package main

import (
	"time"

	"github.com/orchard9/go-chassis/config"
)

// Config is every knob hushd has. Loaded once at boot; a missing or malformed
// required value stops the process rather than being defaulted, so a
// misconfigured pod crashloops visibly instead of serving something subtly
// wrong.
type Config struct {
	Env  string
	Port int

	// RedisURL is REQUIRED. There is an in-memory store in the codebase for
	// tests, and requiring this is what makes it impossible to select by
	// accident in production: a pod with no REDIS_URL does not boot, rather
	// than booting with a store that loses every secret on restart.
	RedisURL string

	// RateLimit bounds anonymous creates per client IP. Reveals are not
	// limited by this: a recipient gets exactly one successful reveal by
	// construction, so there is nothing to throttle, and throttling would let
	// one noisy NAT block a colleague's delivery.
	RateLimitCreates int
	RateLimitWindow  time.Duration

	// TrustedProxyHops is how many Traefik hops sit in front of hushd, used to
	// pick the real client IP out of X-Forwarded-For. Wrong-high lets a caller
	// spoof their IP and evade the rate limit; wrong-low rate-limits the
	// ingress itself and throttles everyone together.
	TrustedProxyHops int

	// AllowOrigins is the CORS allowlist. Empty is correct for the deployed
	// service: every page is same-origin, so no cross-origin caller is
	// legitimate.
	AllowOrigins []string

	// RequireAuthToCreate closes anonymous create if the service is abused.
	// Reveal stays anonymous regardless — the recipient is external and holds
	// no credential.
	RequireAuthToCreate bool
	CreateToken         string
}

func loadConfig() (Config, error) {
	l := config.New()
	cfg := Config{
		Env:                 l.OneOf("APP_ENV", "dev", "dev", "staging", "prod"),
		Port:                l.Port("HUSH_PORT", 18500),
		RedisURL:            l.Required("REDIS_URL"),
		RateLimitCreates:    l.Int("HUSH_RATE_LIMIT_CREATES", 30),
		RateLimitWindow:     l.Duration("HUSH_RATE_LIMIT_WINDOW", 10*time.Minute),
		TrustedProxyHops:    l.Int("HUSH_TRUSTED_PROXY_HOPS", 1),
		AllowOrigins:        l.Strings("HUSH_ALLOW_ORIGINS", nil),
		RequireAuthToCreate: l.Bool("HUSH_REQUIRE_AUTH", false),
		CreateToken:         l.String("HUSH_CREATE_TOKEN", ""),
	}
	if err := l.Err(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
