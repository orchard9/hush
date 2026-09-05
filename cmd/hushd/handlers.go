package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/orchard9/go-chassis/chassis"

	"github.com/orchard9/hush/internal/secret"
	"github.com/orchard9/hush/internal/store"
	"github.com/orchard9/hush/internal/web"
)

// Server holds the handler dependencies.
type Server struct {
	cfg     Config
	store   store.Store
	pages   *web.Pages
	metrics *Metrics
}

// pageData is the same for every render: the ciphertext cap, so the browser
// enforces what the server enforces, and the default lifetime, so the page
// states the TTL the server will apply. It carries nothing request-specific,
// which is why every page is safely static.
func (s *Server) pageData() web.Data {
	return web.Data{
		MaxCiphertextBytes: secret.MaxCiphertextBytes,
		DefaultTTLSeconds:  int(secret.DefaultTTL.Seconds()),
	}
}

// handleCreatePage serves GET /.
func (s *Server) handleCreatePage(c *chassis.Context) error {
	return s.pages.Create(c.Writer(), s.pageData())
}

// handleRevealPage serves GET /s/{id}.
//
// It touches NO storage — not even to check whether the id exists. That is the
// design's load-bearing property: Slack, Teams, WhatsApp, iMessage and Outlook
// Safe Links all fetch URLs before a human sees them, so any read here would
// destroy most secrets in transit. It also means this response cannot leak
// whether an id exists.
//
// The id is not even parsed: a malformed one gets the same page, and the POST
// is what answers. Validating here would make this endpoint an id oracle.
func (s *Server) handleRevealPage(c *chassis.Context) error {
	return s.pages.Reveal(c.Writer(), s.pageData())
}

// handleMCPPage serves GET /mcp: how to install the local MCP server and wire
// it into a client. Static prose, no storage, no script.
func (s *Server) handleMCPPage(c *chassis.Context) error {
	return s.pages.MCP(c.Writer(), s.pageData())
}

type createRequest struct {
	Ciphertext string `json:"ciphertext"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

type createResponse struct {
	ID         string `json:"id"`
	ExpiresAt  string `json:"expires_at"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

// handleCreate serves POST /api/secrets.
//
// It accepts ciphertext only. There is deliberately no endpoint taking a
// plaintext secret: one would make the server able to read secrets, and then
// nobody could tell from a link which guarantee they had.
func (s *Server) handleCreate(c *chassis.Context) error {
	var req createRequest
	if err := c.Bind(&req); err != nil {
		s.metrics.Rejected.WithLabelValues(reasonMalformed).Inc()
		return err
	}

	if err := secret.ValidateCiphertext(req.Ciphertext); err != nil {
		reason, code := classifyCiphertextError(err)
		s.metrics.Rejected.WithLabelValues(reason).Inc()
		// err carries sizes, never content: ValidateCiphertext never puts the
		// ciphertext in its message.
		return &chassis.Error{Status: http.StatusUnprocessableEntity, Code: code, Msg: err.Error()}
	}

	ttl, err := secret.ResolveTTL(time.Duration(req.TTLSeconds) * time.Second)
	if err != nil {
		s.metrics.Rejected.WithLabelValues(reasonTTL).Inc()
		return &chassis.Error{Status: http.StatusUnprocessableEntity, Code: reasonTTL, Msg: err.Error()}
	}

	id, err := secret.NewID()
	if err != nil {
		// No entropy means no safe id. Refuse rather than mint a guessable one.
		return chassis.Internal(err)
	}

	if err := s.store.Put(c.Context(), id, req.Ciphertext, ttl); err != nil {
		if errors.Is(err, store.ErrIDCollision) {
			// Impossible at 256 bits, so it means an id-generation bug. Surfaced
			// rather than retried, because a retry loop would hide it.
			c.Log().Error("secret.id_collision", "category", "secret",
				"error_type", "id_collision", "sid", id.LogHandle())
			return chassis.Internal(err)
		}
		return chassis.Internal(err)
	}

	s.metrics.Created.Inc()
	s.metrics.Bytes.Observe(float64(len(req.Ciphertext)))
	// sid, not id: the id is the capability and never reaches a log.
	c.Log().Info("secret.created", "category", "secret",
		"sid", id.LogHandle(), "ttl_seconds", int64(ttl.Seconds()),
		"ciphertext_bytes", len(req.Ciphertext))

	return c.Created(createResponse{
		ID:         id.Value(),
		ExpiresAt:  time.Now().UTC().Add(ttl).Format(time.RFC3339),
		TTLSeconds: int64(ttl.Seconds()),
	})
}

type revealResponse struct {
	Ciphertext string `json:"ciphertext"`
}

// gone is the single response for every unavailable secret: never existed,
// already revealed, expired, or evicted early by Redis.
//
// One response for four causes is deliberate. A caller able to tell "already
// revealed" from "never existed" learns that a particular link was real, which
// is information about someone else's secret.
func gone() *chassis.Error {
	return &chassis.Error{
		Status: http.StatusGone,
		Code:   "gone",
		Msg:    "this secret is not available: it was already revealed, expired, or never existed",
	}
}

// handleReveal serves POST /api/secrets/{id}/reveal — the only destructive
// route, and the reason GET is inert.
func (s *Server) handleReveal(c *chassis.Context) error {
	id, err := secret.ParseID(c.PathValue("id"))
	if err != nil {
		// A malformed id gets the SAME 410 as a missing one. A 400 here would
		// separate "not an id we could have minted" from "an id that is gone",
		// which is a free oracle for anyone probing the id space.
		s.metrics.Revealed.WithLabelValues("gone").Inc()
		return gone()
	}

	ciphertext, err := s.store.Take(c.Context(), id)
	switch {
	case errors.Is(err, store.ErrGone):
		s.metrics.Revealed.WithLabelValues("gone").Inc()
		c.Log().Info("secret.gone", "category", "secret", "sid", id.LogHandle())
		return gone()
	case err != nil:
		// A store error is NOT reported as gone. The secret may still exist,
		// and telling the recipient it is gone would send them to rotate a
		// credential that was never delivered.
		return chassis.Internal(err)
	}

	s.metrics.Revealed.WithLabelValues("ok").Inc()
	c.Log().Info("secret.revealed", "category", "secret", "sid", id.LogHandle())
	return c.OK(revealResponse{Ciphertext: ciphertext})
}

// classifyCiphertextError maps a validation failure to its metric reason and
// API error code, which are the same vocabulary on purpose.
func classifyCiphertextError(err error) (reason, code string) {
	switch {
	case errors.Is(err, secret.ErrCiphertextTooLarge):
		return reasonTooLarge, reasonTooLarge
	case errors.Is(err, secret.ErrCiphertextInvalid):
		return reasonInvalid, reasonInvalid
	case errors.Is(err, secret.ErrCiphertextEmpty):
		return reasonEmpty, reasonEmpty
	default:
		return reasonMalformed, reasonMalformed
	}
}
