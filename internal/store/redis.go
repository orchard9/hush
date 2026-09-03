package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/orchard9/hush/internal/secret"
)

// Redis is the production store. It keeps one key per secret and lets Redis own
// expiry, so nothing in hush sweeps, scans, or holds a timer.
type Redis struct {
	client *redis.Client
}

// NewRedis dials Redis from a URL of the form
// redis://user:password@host:6379/5 — the ACL user, the password and the db
// index all ride in the URL, matching every other orchard9 service.
func NewRedis(url string) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	// A secret write must not hang a request behind a slow dependency: the
	// chassis request timeout would fire and the caller would see a 500 with no
	// idea whether the secret was stored. Short, explicit timeouts make the
	// failure fast and unambiguous.
	opt.DialTimeout = 3 * time.Second
	opt.ReadTimeout = 2 * time.Second
	opt.WriteTimeout = 2 * time.Second
	opt.MaxRetries = 2
	return &Redis{client: redis.NewClient(opt)}, nil
}

// Put stores ciphertext with SET ... EX ttl NX.
//
// NX is what makes an id collision an error instead of a silent overwrite of a
// live secret. It cannot fire by chance at 256 bits, which is exactly why a
// false return is worth surfacing: it means something is wrong with id
// generation, and the alternative is destroying a secret somebody is waiting on.
func (r *Redis) Put(ctx context.Context, id secret.ID, ciphertext string, ttl time.Duration) error {
	ok, err := r.client.SetNX(ctx, id.StorageKey(), ciphertext, ttl).Result()
	if err != nil {
		return fmt.Errorf("redis set: %w", err)
	}
	if !ok {
		return ErrIDCollision
	}
	return nil
}

// Take reads and destroys in ONE command.
//
// GETDEL (Redis 6.2+) is atomic, which is the entire one-time guarantee. A
// GET followed by a DEL has a window between the two round trips where two
// simultaneous readers both get the plaintext, and for this service that window
// is the product. Redis 7.4.8 runs in the cluster; the ACL user must carry
// `+getdel` or every reveal returns NOPERM.
//
// redis.Nil covers all four "not available" causes and collapses to ErrGone —
// see the doc comment on ErrGone for why they are not separated.
func (r *Redis) Take(ctx context.Context, id secret.ID) (string, error) {
	v, err := r.client.GetDel(ctx, id.StorageKey()).Result()
	switch {
	case errors.Is(err, redis.Nil):
		return "", ErrGone
	case err != nil:
		return "", fmt.Errorf("redis getdel: %w", err)
	}
	return v, nil
}

// Ping backs /readyz. It is the reason a Redis outage takes the pod out of the
// Service rather than serving 500s from a pod the load balancer still trusts.
func (r *Redis) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Close shuts the pool down.
func (r *Redis) Close() error { return r.client.Close() }

// AllowN implements a fixed-window rate limit in Redis: INCR the window key,
// set its expiry on first use, and refuse once the count passes the limit.
//
// Fixed window rather than a sliding one because it costs two commands, needs
// no Lua, and the failure it permits — up to 2x the limit across a window
// boundary — is irrelevant for an abuse control whose job is to stop bulk
// automation, not to meter precisely.
//
// It lives in Redis rather than in process memory so the limit still holds if
// hush is ever scaled past one replica, and so a restart cannot be used to
// reset it.
func (r *Redis) AllowN(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	full := "hush:rl:" + key
	pipe := r.client.Pipeline()
	incr := pipe.Incr(ctx, full)
	// NX so a long-running window is not extended by later requests inside it;
	// without it a steady stream of calls would push the expiry forward forever
	// and the window would never reset.
	pipe.ExpireNX(ctx, full, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, 0, fmt.Errorf("redis ratelimit: %w", err)
	}
	count := incr.Val()
	if count > int64(limit) {
		retry, err := r.client.PTTL(ctx, full).Result()
		if err != nil || retry < 0 {
			retry = window
		}
		return false, retry, nil
	}
	return true, 0, nil
}
