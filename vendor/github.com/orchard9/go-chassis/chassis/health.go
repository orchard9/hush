package chassis

import (
	"context"
	"net/http"
)

// CheckFunc reports whether a dependency is usable right now. It MUST honor the
// passed ctx deadline and return a non-nil error (with no secrets) when unhealthy.
type CheckFunc func(ctx context.Context) error

type namedCheck struct {
	name string
	fn   CheckFunc
}

// handleLive is the k8s liveness probe: 200 while the process runs. It does NOT
// check dependencies and stays 200 during drain — a flapping dep or an
// in-progress shutdown must never trigger a restart, only LB removal.
func (a *App) handleLive(c *Context) error {
	return c.OK(map[string]any{"status": "ok"})
}

// handleReady is the k8s readiness probe. It returns 503 the moment shutdown
// begins (two-phase drain: the LB pulls the pod before connections close), and
// otherwise 200 only when every registered dependency check passes.
func (a *App) handleReady(c *Context) error {
	if a.draining.Load() {
		return c.JSON(http.StatusServiceUnavailable, map[string]any{"status": "draining"})
	}
	ctx, cancel := context.WithTimeout(c.Context(), a.cfg.ReadyTimeout)
	defer cancel()

	checks := make(map[string]string, len(a.checks))
	ok := true
	for _, ch := range a.checks {
		if err := ch.fn(ctx); err != nil {
			checks[ch.name] = "error: " + err.Error()
			ok = false
			continue
		}
		checks[ch.name] = "ok"
	}

	status, code := "ok", http.StatusOK
	if !ok {
		status, code = "unready", http.StatusServiceUnavailable
	}
	return c.JSON(code, map[string]any{"status": status, "checks": checks})
}
