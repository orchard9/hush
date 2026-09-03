package chassis

// Authorization middleware — the layer above authentication. RequireAuth proves
// WHO; these prove WHAT they may do and WHICH tenant they act in. Apply after
// RequireAuth on a route group.

// RequireScope rejects callers lacking the given scope (scope dominance applies:
// a held "x:*" satisfies "x:read"). 401 if unauthenticated, 403 if under-scoped.
func RequireScope(scope string) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) error {
			id, ok := c.Identity()
			if !ok {
				return Unauthorized("authentication required")
			}
			if !id.HasScope(scope) {
				return Forbidden("missing required scope: " + scope)
			}
			return next(c)
		}
	}
}

// RequireOrg enforces the multi-tenant invariant: the caller must have a resolved
// active organization. Handlers behind it can rely on a non-empty Context.OrgID
// and MUST filter every tenant query by it.
func RequireOrg() Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(c *Context) error {
			id, ok := c.Identity()
			if !ok || id.OrgID == "" {
				return Forbidden("no active organization")
			}
			return next(c)
		}
	}
}
