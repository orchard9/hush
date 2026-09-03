// Package store persists ciphertext for at most a TTL and destroys it on the
// first successful read.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/orchard9/hush/internal/secret"
)

// ErrGone is returned by Take for every reason a secret is not available: it
// never existed, it was already revealed, it expired, or Redis evicted it early
// under memory pressure.
//
// The causes are deliberately NOT distinguished. Not because they are hard to
// tell apart, but because telling them apart is the leak: a caller who can
// separate "never existed" from "already revealed" can confirm that a given
// link was real, which is information about someone else's secret. The API maps
// this one error to one 410 for all four cases.
var ErrGone = errors.New("secret is gone")

// ErrIDCollision means Put found the key already occupied. At 256 bits of id
// entropy this cannot happen by chance, so it means a bug or a repeated id, and
// it is surfaced rather than silently overwriting a live secret.
var ErrIDCollision = errors.New("secret id already exists")

// Store is the whole persistence contract. Two methods, both destructive-safe:
// there is no Get, no List, and no Exists — a store that could answer "does
// this id exist" without consuming it would let the reveal page leak existence,
// and a store that could list would make a compromise catastrophic instead of
// merely bad.
type Store interface {
	// Put writes ciphertext under id, expiring after ttl. It must fail rather
	// than overwrite an existing key.
	Put(ctx context.Context, id secret.ID, ciphertext string, ttl time.Duration) error

	// Take returns the ciphertext and destroys it ATOMICALLY. Two concurrent
	// callers must not both receive a value; exactly one gets it and the other
	// gets ErrGone. This atomicity is the one-time property — an implementation
	// that reads then deletes has a window in which both callers succeed.
	Take(ctx context.Context, id secret.ID) (string, error)

	// Ping reports whether the backing store is usable, for readiness.
	Ping(ctx context.Context) error

	// Close releases resources.
	Close() error
}
