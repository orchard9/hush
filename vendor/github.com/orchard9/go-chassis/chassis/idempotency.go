package chassis

import (
	"bytes"
	"context"
	"net/http"
	"time"
)

// StoredResponse is a cached successful response, replayed verbatim (status +
// headers + body) on a duplicate Idempotency-Key.
type StoredResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// IdempotencyStore persists and replays responses keyed by Idempotency-Key.
// Back it with Redis (TTL'd) in shared/adapters/redis. Lookup returns found=false
// when the key is new; Save records a successful response.
type IdempotencyStore interface {
	Lookup(ctx context.Context, key string) (StoredResponse, bool, error)
	Save(ctx context.Context, key string, resp StoredResponse, ttl time.Duration) error
}

// Idempotent dedups mutating requests by the Idempotency-Key header: a duplicate
// returns the original response without re-running the handler. Apply it to
// POST/PUT route groups. Requests without the header pass straight through. The
// key is scoped by the caller's org so keys can't collide across tenants. The
// store is best-effort: a backend error fails open (the request proceeds) rather
// than blocking writes.
func Idempotent(store IdempotencyStore, ttl time.Duration) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) error {
			key := c.r.Header.Get("Idempotency-Key")
			if key == "" {
				return next(c)
			}
			// Scope by tenant. With no resolved org we refuse to cache rather than
			// share a global (cross-tenant) key — pair this with RequireOrg.
			org := c.OrgID()
			if org == "" {
				c.Log().Warn("idempotency.skipped_no_org", "category", "idempotency")
				return next(c)
			}
			scoped := org + ":" + key
			ctx := c.r.Context()

			if sr, found, err := store.Lookup(ctx, scoped); err != nil {
				c.Log().Warn("idempotency.lookup_failed", "category", "idempotency", "error_msg", err.Error())
			} else if found {
				h := c.w.Header()
				for k, vs := range sr.Header { // replay the original headers verbatim
					for _, v := range vs {
						h.Add(k, v)
					}
				}
				h.Set("Idempotency-Replayed", "true")
				c.w.WriteHeader(sr.Status)
				_, werr := c.w.Write(sr.Body)
				return werr
			}

			// Capture the handler's response so we can persist + flush it. Restore
			// the writer via defer so a panic in next() can't leave c.w dangling.
			rec := &captureWriter{header: http.Header{}, status: http.StatusOK}
			orig := c.w
			c.w = rec
			defer func() { c.w = orig }()
			if err := next(c); err != nil {
				return err // errors aren't cached; the framework writes the envelope to orig
			}

			for k, vs := range rec.header {
				for _, v := range vs {
					orig.Header().Add(k, v)
				}
			}
			orig.WriteHeader(rec.status)
			if _, werr := orig.Write(rec.buf.Bytes()); werr != nil {
				return werr
			}
			if rec.status >= 200 && rec.status < 300 {
				body := append([]byte(nil), rec.buf.Bytes()...)
				stored := StoredResponse{Status: rec.status, Header: rec.header.Clone(), Body: body}
				if serr := store.Save(ctx, scoped, stored, ttl); serr != nil {
					c.Log().Warn("idempotency.save_failed", "category", "idempotency", "error_msg", serr.Error())
				}
			}
			return nil
		}
	}
}

// captureWriter buffers a handler's response so the idempotency middleware can
// persist and replay it. It implements http.ResponseWriter.
type captureWriter struct {
	header http.Header
	buf    bytes.Buffer
	status int
	wrote  bool
}

func (c *captureWriter) Header() http.Header { return c.header }

func (c *captureWriter) WriteHeader(code int) {
	if c.wrote {
		return
	}
	c.status = code
	c.wrote = true
}

func (c *captureWriter) Write(b []byte) (int, error) {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}
	return c.buf.Write(b)
}
