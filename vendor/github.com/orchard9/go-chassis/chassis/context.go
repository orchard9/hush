package chassis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/orchard9/go-chassis/logging"
)

// HandlerFunc is the chassis handler signature: return an error and the
// framework maps it to the JSON error envelope. See patterns/go-chassis.md.
type HandlerFunc func(*Context) error

// Middleware decorates a HandlerFunc (route/group scope: auth, rate-limit).
// Cross-cutting infra (recover, request-id, logging, metrics) is applied once
// at the server edge as http.Handler middleware, not here.
type Middleware func(HandlerFunc) HandlerFunc

// Context carries the request/response for one call plus typed helpers.
type Context struct {
	w        http.ResponseWriter
	r        *http.Request
	maxBytes int64
	validate func(any) error // optional; set from Config.Validator
	// closing fires when the app begins draining, so a Stream ends with the
	// pod instead of holding Shutdown open.
	closing <-chan struct{}
}

// Context returns the request context (deadline + request-scoped logger).
func (c *Context) Context() context.Context { return c.r.Context() }

// Request exposes the raw request for the rare case a helper does not cover.
func (c *Context) Request() *http.Request { return c.r }

// Writer exposes the raw ResponseWriter for the three responses the JSON
// envelope cannot carry: the Scalar docs page (HTML), the OpenAPI document
// (pre-rendered bytes), and a streamed artifact (video/mp4).
func (c *Context) Writer() http.ResponseWriter { return c.w }

// Log returns the request-scoped logger (carries request_id).
func (c *Context) Log() *slog.Logger { return logging.From(c.r.Context()) }

// PathValue returns a ServeMux wildcard value, e.g. {id} from "/v1/x/{id}".
func (c *Context) PathValue(key string) string { return c.r.PathValue(key) }

// Identity returns the authenticated principal, or false when the route was not
// behind RequireAuth.
func (c *Context) Identity() (*Identity, bool) { return IdentityFrom(c.r.Context()) }

// OrgID returns the active tenant for the caller ("" when unauthenticated or the
// identity carries no org). Repos MUST filter every tenant query by it.
func (c *Context) OrgID() string {
	if id, ok := c.Identity(); ok {
		return id.OrgID
	}
	return ""
}

// TraceID returns the request's trace id (W3C traceparent or generated).
func (c *Context) TraceID() string {
	id, _ := TraceIDFrom(c.r.Context())
	return id
}

// Bind enforces the body-size limit, then JSON-decodes into v rejecting unknown
// fields. An oversized body becomes 413; a malformed body becomes 400 — neither
// leaks internals to the client.
func (c *Context) Bind(v any) error {
	c.r.Body = http.MaxBytesReader(c.w, c.r.Body, c.maxBytes)
	dec := json.NewDecoder(c.r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return PayloadTooLarge("request body too large").WithCause(err)
		}
		if f, ok := unknownField(err); ok {
			return BadRequest(fmt.Sprintf("unknown field %q", f)).WithCause(err)
		}
		return BadRequest("invalid JSON body").WithCause(err)
	}
	if c.validate != nil {
		if err := c.validate(v); err != nil {
			return Unprocessable("request failed validation").WithCause(err)
		}
	}
	return nil
}

// unknownFieldPrefix is what encoding/json returns under
// DisallowUnknownFields. The stdlib gives no typed error for it, so matching the
// text is the only way to tell "you sent a field we do not accept" from "your
// JSON is broken" — and they are different bugs on the caller's side.
const unknownFieldPrefix = `json: unknown field `

// unknownField extracts the rejected field name, if that is why decoding failed.
//
// The name is echoed to the client because the alternative is what this cost us:
// a worker POSTing a well-formed body with one extra key is told "invalid JSON
// body", which is false, and has nothing to act on. Echoing a key the caller
// just sent leaks nothing. The rest of the decoder's errors stay generic — an
// UnmarshalTypeError names Go struct fields and types, which is internal detail.
func unknownField(err error) (string, bool) {
	msg := err.Error()
	if !strings.HasPrefix(msg, unknownFieldPrefix) {
		return "", false
	}
	name, uerr := strconv.Unquote(strings.TrimPrefix(msg, unknownFieldPrefix))
	if uerr != nil {
		return "", false
	}
	return name, true
}

// OK writes 200 + JSON. Created writes 201. NoContent writes 204.
func (c *Context) OK(v any) error      { return c.JSON(http.StatusOK, v) }
func (c *Context) Created(v any) error { return c.JSON(http.StatusCreated, v) }

func (c *Context) NoContent() error {
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

// JSON writes the status code and JSON-encodes v.
func (c *Context) JSON(code int, v any) error {
	c.w.Header().Set("Content-Type", "application/json; charset=utf-8")
	c.w.WriteHeader(code)
	if v == nil {
		return nil
	}
	return json.NewEncoder(c.w).Encode(v)
}
