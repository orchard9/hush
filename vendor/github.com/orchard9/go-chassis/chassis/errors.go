package chassis

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is the HTTP error model: a stable machine Code + a SAFE public Msg
// (no secrets, no internal detail) shown to the client, plus an internal cause
// that is logged server-side and NEVER serialized to the response. Handlers
// return these; the framework maps them to the JSON error envelope.
//
// This is distinct from any domain result/status enum a handler returns as a
// SUCCESS-response field — those are 200 bodies, not errors.
type Error struct {
	Status int    // HTTP status code
	Code   string // stable machine-readable code (snake_case)
	Msg    string // safe public message
	cause  error  // internal cause: logged, never sent to the client
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Msg, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Msg)
}

func (e *Error) Unwrap() error { return e.cause }

// WithCause attaches the internal cause (logged, never sent). Returns a copy so
// the package-level constructors stay immutable.
func (e *Error) WithCause(err error) *Error {
	c := *e
	c.cause = err
	return &c
}

func newErr(status int, code, msg string) *Error {
	return &Error{Status: status, Code: code, Msg: msg}
}

// Constructors — public Msg defaults are safe and generic; override per call.
func BadRequest(msg string) *Error   { return newErr(http.StatusBadRequest, "bad_request", msg) }
func Unauthorized(msg string) *Error { return newErr(http.StatusUnauthorized, "unauthorized", msg) }
func Forbidden(msg string) *Error    { return newErr(http.StatusForbidden, "forbidden", msg) }
func NotFound(msg string) *Error     { return newErr(http.StatusNotFound, "not_found", msg) }
func Conflict(msg string) *Error     { return newErr(http.StatusConflict, "conflict", msg) }
func Unprocessable(msg string) *Error {
	return newErr(http.StatusUnprocessableEntity, "unprocessable", msg)
}
func TooManyRequests(msg string) *Error {
	return newErr(http.StatusTooManyRequests, "rate_limited", msg)
}
func PayloadTooLarge(msg string) *Error {
	return newErr(http.StatusRequestEntityTooLarge, "payload_too_large", msg)
}

// Internal wraps any non-Error as a 500 with a generic public message; the real
// cause is preserved for logging but hidden from the client.
func Internal(cause error) *Error {
	return (&Error{Status: http.StatusInternalServerError, Code: "internal", Msg: "internal error"}).WithCause(cause)
}

// asError maps any error to an *Error, defaulting unknown errors to a 500 whose
// detail is hidden from the client.
func asError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Internal(err)
}
