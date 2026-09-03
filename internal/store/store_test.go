package store_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/orchard9/hush/internal/secret"
	"github.com/orchard9/hush/internal/store"
)

// One contract, two implementations. The suite runs against Memory always and
// against Redis whenever HUSH_TEST_REDIS_URL is set (`make test-redis`, and CI
// where a Redis service is available).
//
// Running the SAME assertions against both is the point: Memory exists so
// handler tests need no container, and it is only trustworthy if it is held to
// the behaviour Redis actually has — including that an expired key may be
// overwritten and that Take is atomic.
func eachStore(t *testing.T, fn func(t *testing.T, s store.Store)) {
	t.Helper()

	t.Run("memory", func(t *testing.T) {
		fn(t, store.NewMemory())
	})

	url := os.Getenv("HUSH_TEST_REDIS_URL")
	if url == "" {
		t.Log("HUSH_TEST_REDIS_URL unset: skipping the Redis half of the contract suite")
		return
	}
	t.Run("redis", func(t *testing.T) {
		r, err := store.NewRedis(url)
		if err != nil {
			t.Fatalf("dial redis: %v", err)
		}
		t.Cleanup(func() { _ = r.Close() })
		if err := r.Ping(context.Background()); err != nil {
			t.Fatalf("ping redis at %s: %v", url, err)
		}
		fn(t, r)
	})
}

func newID(t *testing.T) secret.ID {
	t.Helper()
	id, err := secret.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPutThenTakeReturnsTheCiphertextExactlyOnce(t *testing.T) {
	eachStore(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		id := newID(t)
		const ct = "bm9uY2UtYW5kLWNpcGhlcnRleHQ"

		if err := s.Put(ctx, id, ct, time.Minute); err != nil {
			t.Fatalf("Put: %v", err)
		}

		got, err := s.Take(ctx, id)
		if err != nil {
			t.Fatalf("first Take: %v", err)
		}
		if got != ct {
			t.Fatalf("first Take = %q, want %q", got, ct)
		}

		// The whole product: the second read must find nothing.
		if _, err := s.Take(ctx, id); !errors.Is(err, store.ErrGone) {
			t.Fatalf("second Take = %v, want ErrGone — the secret was not destroyed", err)
		}
	})
}

func TestTakeOfAnUnknownIDIsGone(t *testing.T) {
	eachStore(t, func(t *testing.T, s store.Store) {
		if _, err := s.Take(context.Background(), newID(t)); !errors.Is(err, store.ErrGone) {
			t.Fatalf("Take(unknown) = %v, want ErrGone", err)
		}
	})
}

func TestPutRefusesToOverwriteALiveSecret(t *testing.T) {
	eachStore(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		id := newID(t)
		if err := s.Put(ctx, id, "first", time.Minute); err != nil {
			t.Fatal(err)
		}
		// At 256 bits this cannot happen by chance, so if it ever does it is an
		// id-generation bug. Destroying the live secret instead of reporting it
		// would lose a secret someone is waiting on.
		if err := s.Put(ctx, id, "second", time.Minute); !errors.Is(err, store.ErrIDCollision) {
			t.Fatalf("second Put = %v, want ErrIDCollision", err)
		}
		got, err := s.Take(ctx, id)
		if err != nil || got != "first" {
			t.Fatalf("Take after refused overwrite = (%q, %v), want (\"first\", nil)", got, err)
		}
	})
}

// Exactly one winner under concurrency. This is why the store contract demands
// an atomic read-and-destroy: a GET followed by a DEL has a window in which two
// readers both receive the plaintext, and for a one-time secret that window is
// the entire guarantee.
func TestConcurrentTakesProduceExactlyOneWinner(t *testing.T) {
	eachStore(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		const racers = 32

		for round := range 20 {
			id := newID(t)
			if err := s.Put(ctx, id, "only-once", time.Minute); err != nil {
				t.Fatalf("round %d Put: %v", round, err)
			}

			var (
				wg       sync.WaitGroup
				mu       sync.Mutex
				wins     int
				gone     int
				othererr error
				start    = make(chan struct{})
			)
			for range racers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start // release them together to maximise the overlap
					v, err := s.Take(ctx, id)
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil && v == "only-once":
						wins++
					case errors.Is(err, store.ErrGone):
						gone++
					default:
						othererr = err
					}
				}()
			}
			close(start)
			wg.Wait()

			if othererr != nil {
				t.Fatalf("round %d: unexpected error from Take: %v", round, othererr)
			}
			if wins != 1 {
				t.Fatalf("round %d: %d goroutines received the secret, want exactly 1 (%d saw gone)", round, wins, gone)
			}
			if gone != racers-1 {
				t.Fatalf("round %d: %d saw gone, want %d", round, gone, racers-1)
			}
		}
	})
}

func TestAnExpiredSecretIsGoneAndItsIDIsReusable(t *testing.T) {
	// Driven by a fake clock so this does not sleep. The Redis half of the
	// contract is covered by TestRedisHonoursTTL below, which uses a short real
	// TTL because Redis owns that clock.
	now := time.Now()
	s := store.NewMemoryAt(func() time.Time { return now })
	ctx := context.Background()
	id := newID(t)

	if err := s.Put(ctx, id, "vanishing", time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute + time.Second)

	if _, err := s.Take(ctx, id); !errors.Is(err, store.ErrGone) {
		t.Fatalf("Take after expiry = %v, want ErrGone", err)
	}
	// Redis treats an expired key as absent, so Put must succeed here. A
	// memory store that refused would pass tests Redis fails.
	if err := s.Put(ctx, id, "reused", time.Minute); err != nil {
		t.Fatalf("Put over an expired key = %v, want nil (Redis SET NX succeeds on an expired key)", err)
	}
}

func TestRedisHonoursTTL(t *testing.T) {
	url := os.Getenv("HUSH_TEST_REDIS_URL")
	if url == "" {
		t.Skip("HUSH_TEST_REDIS_URL unset")
	}
	r, err := store.NewRedis(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	ctx := context.Background()
	id := newID(t)
	// Redis EX takes whole seconds, so 1s is the shortest observable TTL.
	if err := r.Put(ctx, id, "brief", time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := r.Take(ctx, id); !errors.Is(err, store.ErrGone) {
		t.Fatalf("Take after the TTL elapsed = %v, want ErrGone", err)
	}
}

func TestRedisRateLimitCountsWithinAWindowAndThenRefuses(t *testing.T) {
	url := os.Getenv("HUSH_TEST_REDIS_URL")
	if url == "" {
		t.Skip("HUSH_TEST_REDIS_URL unset")
	}
	r, err := store.NewRedis(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	ctx := context.Background()
	// A unique key per run so a re-run is not throttled by the previous one.
	id := newID(t)
	key := "test-" + id.LogHandle()

	for i := 1; i <= 3; i++ {
		ok, _, err := r.AllowN(ctx, key, 3, 5*time.Second)
		if err != nil || !ok {
			t.Fatalf("call %d: AllowN = (%v, %v), want allowed", i, ok, err)
		}
	}
	ok, retry, err := r.AllowN(ctx, key, 3, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("the 4th call in a limit-3 window was allowed")
	}
	if retry <= 0 || retry > 5*time.Second {
		t.Fatalf("retryAfter = %s, want a positive value inside the window", retry)
	}
}
