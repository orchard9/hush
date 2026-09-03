package chassis

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

// Identity is the authenticated principal attached to the request context by an
// auth Middleware. Subject is the stable principal id; OrgID is the tenant the
// principal is acting in (the multi-tenant scoping key — every tenant row
// filters by it); Scopes are the granted permissions; Claims carries any extra
// verified attributes without coupling chassis to a domain type.
type Identity struct {
	Subject string
	OrgID   string
	Scopes  []string
	Claims  map[string]string
}

// HasScope reports whether the identity holds the required scope. A held scope
// ending in ":*" dominates any required scope sharing its prefix, so "admin:*"
// satisfies "admin:read". An exact match always passes.
func (id *Identity) HasScope(required string) bool {
	if id == nil {
		return false
	}
	for _, s := range id.Scopes {
		if s == required {
			return true
		}
		if prefix, ok := strings.CutSuffix(s, ":*"); ok {
			if reqPrefix, _, found := strings.Cut(required, ":"); found && reqPrefix == prefix {
				return true
			}
		}
	}
	return false
}

// Authenticator verifies a request and returns its Identity, or an *Error
// (Unauthorized/Forbidden) when verification fails. Implementations:
//   - NoAuth      — local default, everyone is anonymous (documented seam).
//   - StaticToken — shared bearer token, constant-time compared (local/CI).
//   - (later) OIDC — coreos/go-oidc verifier, JWKS cache, refresh-on-kid-miss.
//   - (later) APIKey — hashed key behind a Secrets port, constant-time compare.
type Authenticator interface {
	Authenticate(r *http.Request) (*Identity, error)
}

type identityKey struct{}

// IdentityFrom returns the authenticated identity, or false when the route was
// not behind RequireAuth.
func IdentityFrom(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(*Identity)
	return id, ok
}

// RequireAuth is route/group middleware that runs the Authenticator, rejecting
// the request (deny-by-default) when it fails and otherwise stashing the
// Identity in the context for handlers.
func RequireAuth(a Authenticator) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) error {
			id, err := a.Authenticate(c.r)
			if err != nil {
				return err // already an *Error (Unauthorized/Forbidden)
			}
			c.r = c.r.WithContext(context.WithValue(c.r.Context(), identityKey{}, id))
			return next(c)
		}
	}
}

// NoAuth treats every caller as anonymous. The explicit local default — never
// select it for a protected environment.
type NoAuth struct{}

func (NoAuth) Authenticate(*http.Request) (*Identity, error) {
	return &Identity{Subject: "anonymous"}, nil
}

// StaticToken authenticates a single shared bearer token in constant time
// (crypto/subtle) to avoid leaking the token via response timing. For local/CI
// and internal service-to-service; real principals use OIDC/API-key later.
type StaticToken struct{ token string }

// NewStaticToken builds a StaticToken; an empty token rejects every request.
func NewStaticToken(token string) StaticToken { return StaticToken{token: token} }

func (s StaticToken) Authenticate(r *http.Request) (*Identity, error) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if s.token == "" || !strings.HasPrefix(h, prefix) {
		return nil, Unauthorized("missing or malformed bearer token")
	}
	got := strings.TrimPrefix(h, prefix)
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
		return nil, Unauthorized("invalid token")
	}
	return &Identity{Subject: "static-token"}, nil
}
