package chassis

import (
	"context"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RateLimiter decides whether a key may proceed now. Back it with a Redis token
// bucket in shared/adapters/redis (tiered by actor). retryAfter hints when to
// retry; it is surfaced as the Retry-After header on a 429.
type RateLimiter interface {
	Allow(ctx context.Context, key string) (allowed bool, retryAfter time.Duration, err error)
}

// RateLimit rejects requests over the limit with 429 + Retry-After. keyFn maps a
// request to a bucket key (default: authenticated subject, else client IP). The
// limiter is best-effort: a backend error fails open (request proceeds) so a
// degraded Redis can't take down the API.
func RateLimit(limiter RateLimiter, keyFn func(*Context) string) Middleware {
	if keyFn == nil {
		keyFn = DefaultRateKey
	}
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) error {
			allowed, retryAfter, err := limiter.Allow(c.r.Context(), keyFn(c))
			if err != nil {
				c.Log().Warn("ratelimit.failed", "category", "ratelimit", "error_msg", err.Error())
				return next(c)
			}
			if !allowed {
				if retryAfter > 0 {
					c.w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
				}
				return TooManyRequests("rate limit exceeded")
			}
			return next(c)
		}
	}
}

// DefaultRateKey buckets by authenticated subject when present, else by client
// IP. It does NOT trust X-Forwarded-For (trustedHops=0), so a spoofed XFF can't
// mint a fresh bucket per request. Behind N trusted proxies/LBs, use RateKey(N).
func DefaultRateKey(c *Context) string { return rateKey(c, 0) }

// RateKey returns a key function for a deployment behind trustedHops proxies/LBs
// (the IP is taken trustedHops entries from the right of X-Forwarded-For).
func RateKey(trustedHops int) func(*Context) string {
	return func(c *Context) string { return rateKey(c, trustedHops) }
}

func rateKey(c *Context, trustedHops int) string {
	if id, ok := c.Identity(); ok && id.Subject != "" && id.Subject != "anonymous" {
		return "sub:" + id.Subject
	}
	return "ip:" + clientIP(c.r, trustedHops)
}

// clientIP derives the client address. With trustedHops<=0 it uses the connection
// RemoteAddr (XFF is attacker-controlled and ignored). Behind trustedHops trusted
// proxies it takes the entry that many hops from the right of X-Forwarded-For —
// the first address the trust boundary did not append.
func clientIP(r *http.Request, trustedHops int) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if trustedHops <= 0 {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	parts := strings.Split(xff, ",")
	idx := len(parts) - trustedHops
	if idx < 0 || idx >= len(parts) {
		return host
	}
	if v := strings.TrimSpace(parts[idx]); v != "" {
		return v
	}
	return host
}
