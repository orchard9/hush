package store

import (
	"context"
	"sync"
	"time"

	"github.com/orchard9/hush/internal/secret"
)

// Memory is an in-process Store for tests and `make dev` without Redis.
//
// It is NOT a deployment option, and the deployment path cannot select it: the
// store is chosen by whether REDIS_URL is set, and REDIS_URL is Required in
// config, so a misconfigured pod fails to boot rather than silently serving
// secrets from a store that dies with the process. This type exists so the
// handler tests do not need a container.
type Memory struct {
	mu    sync.Mutex
	items map[string]memItem
	now   func() time.Time
}

type memItem struct {
	ciphertext string
	expiresAt  time.Time
}

// NewMemory returns an empty store using the real clock.
func NewMemory() *Memory {
	return &Memory{items: map[string]memItem{}, now: time.Now}
}

// NewMemoryAt returns a store driven by a caller-supplied clock, so expiry is
// testable without sleeping.
func NewMemoryAt(now func() time.Time) *Memory {
	return &Memory{items: map[string]memItem{}, now: now}
}

func (m *Memory) Put(_ context.Context, id secret.ID, ciphertext string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := id.StorageKey()
	// Mirror Redis SET NX semantics, including that an EXPIRED key is treated
	// as absent and may be overwritten. A memory store that rejected a write
	// against a stale entry would pass tests Redis fails.
	if it, ok := m.items[k]; ok && m.now().Before(it.expiresAt) {
		return ErrIDCollision
	}
	m.items[k] = memItem{ciphertext: ciphertext, expiresAt: m.now().Add(ttl)}
	return nil
}

// Take mirrors GETDEL: the read and the delete happen under one lock, so the
// atomicity the one-time guarantee depends on holds here too and the
// concurrency test is meaningful against both implementations.
func (m *Memory) Take(_ context.Context, id secret.ID) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := id.StorageKey()
	it, ok := m.items[k]
	if !ok {
		return "", ErrGone
	}
	delete(m.items, k)
	if !m.now().Before(it.expiresAt) {
		return "", ErrGone
	}
	return it.ciphertext, nil
}

func (m *Memory) Ping(context.Context) error { return nil }
func (m *Memory) Close() error               { return nil }

// AllowN is an always-allow limiter: rate limiting is an abuse control on the
// public deployment, and silently enforcing one in tests would make handler
// tests order-dependent and flaky.
func (m *Memory) AllowN(context.Context, string, int, time.Duration) (bool, time.Duration, error) {
	return true, 0, nil
}
