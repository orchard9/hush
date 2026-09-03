package chassis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// untimedKey carries the pre-deadline request context so Stream can shed the
// per-request budget. See instrument.
type untimedKey struct{}

// heartbeatEvery bounds how long a stream stays silent. Any proxy between the
// board and a browser will drop an idle connection eventually — Traefik's
// default is 0 (never) but Cloudflare's is 100s and a corporate egress proxy's
// is anyone's guess — so a comment frame goes out on every tick even when the
// board state has not moved. It is two bytes and it is the difference between
// a live dashboard and one that silently stopped updating an hour ago.
const heartbeatEvery = 20 * time.Second

// Stream is an open server-sent-events response.
//
// SSE rather than a websocket because the traffic is strictly one-way (the
// board pushes state, the browser never talks back), it survives every proxy
// that speaks HTTP/1.1, and EventSource reconnects on its own — so a board
// restart costs the dashboard a few seconds rather than a page reload.
type Stream struct {
	w       http.ResponseWriter
	rc      *http.ResponseController
	ctx     context.Context
	closing <-chan struct{}
}

// Stream converts the response into an event stream and returns a handle.
//
// It clears this connection's write deadline (the server sets one from
// RequestTimeout for every other route) and detaches from the per-request
// context deadline, leaving the stream bound to exactly two things: the client
// hanging up, and the server beginning to drain.
//
// The handler MUST NOT write to the Context afterwards — the response is
// committed the moment this returns.
func (c *Context) Stream() (*Stream, error) {
	w := c.w
	rc := http.NewResponseController(w)
	// A stream lives past any per-request deadline by definition. This is the
	// call that needs statusRecorder.Unwrap; without it the connection is cut
	// mid-stream at RequestTimeout+socketHeadroom.
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("chassis: stream needs a deadline-capable writer: %w", err)
	}
	// Tell the edge not to time this response. How long a stream stays open is
	// how long an operator left a tab open; in the latency histogram it fires
	// HighRequestLatency and drags every percentile for the whole service.
	if rec, ok := w.(*statusRecorder); ok {
		rec.streamed = true
	}

	ctx := c.r.Context()
	if untimed, ok := ctx.Value(untimedKey{}).(context.Context); ok {
		ctx = untimed
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache, no-transform")
	h.Set("Connection", "keep-alive")
	// Traefik does not buffer, but this response passes through whatever the
	// operator puts in front of it and an accumulating proxy turns a live
	// stream into a batch delivered at close.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// Past this point the response is committed, so a flush failure must not
	// become a returned error — the chassis would write a JSON envelope on top
	// of a 200 event stream. The first Send surfaces a dead connection.
	_ = rc.Flush()

	return &Stream{w: w, rc: rc, ctx: ctx, closing: c.closing}, nil
}

// Context is the stream's lifetime: cancelled when the client disconnects.
func (s *Stream) Context() context.Context { return s.ctx }

// Send JSON-encodes v as one named event and flushes it. A write error means
// the client is gone; the caller returns and the handler ends.
func (s *Stream) Send(event string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("chassis: stream encode %s: %w", event, err)
	}
	// The payload is compact JSON from encoding/json, so it contains no raw
	// newline and needs no multi-line data: continuation.
	if _, err := fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", event, body); err != nil {
		return err
	}
	return s.rc.Flush()
}

// Run pushes an initial frame, then one per tick, until the client disconnects
// or the server drains. It returns nil on every ordinary end — a browser
// closing a tab is not a server error and must not be logged as one.
func (s *Stream) Run(every time.Duration, frame func(context.Context) (any, error)) error {
	send := func() error {
		v, err := frame(s.ctx)
		if err != nil {
			return err
		}
		return s.Send("state", v)
	}

	if err := send(); err != nil {
		return s.classify(err)
	}

	tick := time.NewTicker(every)
	defer tick.Stop()
	beat := time.NewTicker(heartbeatEvery)
	defer beat.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return nil
		case <-s.closing:
			// Tell the browser to come back rather than letting it infer a
			// dead board from a closed socket.
			_ = s.Send("bye", map[string]string{"reason": "draining"})
			return nil
		case <-beat.C:
			if _, err := fmt.Fprint(s.w, ": ping\n\n"); err != nil {
				return nil
			}
			if err := s.rc.Flush(); err != nil {
				return nil
			}
		case <-tick.C:
			if err := send(); err != nil {
				return s.classify(err)
			}
		}
	}
}

// classify swallows the errors that mean "the client left". A disconnect races
// every write, so treating it as a failure would fill the log with 500s every
// time somebody closes a dashboard tab.
func (s *Stream) classify(err error) error {
	if s.ctx.Err() != nil {
		return nil
	}
	return err
}
