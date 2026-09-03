package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// A minimal, dependency-free MCP server over stdio.
//
// MCP on stdio is newline-delimited JSON-RPC 2.0. The surface this server needs
// is four methods — initialize, notifications/initialized, tools/list,
// tools/call — so it is implemented directly rather than pulling in an SDK
// whose API churn would be a bigger maintenance surface than the protocol.
//
// The one rule that matters for a stdio server: stdout carries protocol frames
// ONLY. Anything diagnostic goes to stderr, because a stray Println on stdout
// corrupts the stream and the host reports an opaque parse failure.

// protocolVersion is the MCP revision this server implements. The host sends
// its own in initialize; the spec has the server answer with the version it
// will actually speak rather than echoing the client's.
const protocolVersion = "2025-06-18"

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC 2.0 reserved codes. -32602 is the one that matters here: a bad tool
// argument is an invalid-params error, not a transport failure.
const (
	codeInvalidParams = -32602
	codeMethodMissing = -32601
	codeInternal      = -32603
)

// Tool is one callable tool. Schema is the raw JSON Schema advertised to the
// host, which is what makes the arguments self-documenting in the client.
type Tool struct {
	Name        string
	Title       string
	Description string
	Schema      map[string]any
	// Handler returns the text to show the caller. An error is reported as a
	// TOOL error (isError on the result) rather than a protocol error, so the
	// model sees the message and can act on it instead of the call appearing
	// to have failed at the transport level.
	Handler func(args json.RawMessage) (string, error)
}

// Server dispatches MCP over a reader/writer pair.
type Server struct {
	name    string
	version string
	tools   []Tool

	mu  sync.Mutex // serialises writes: one frame per line, never interleaved
	out *json.Encoder
	w   io.Writer
}

func NewServer(name, version string, out io.Writer, tools []Tool) *Server {
	return &Server{name: name, version: version, tools: tools, out: json.NewEncoder(out), w: out}
}

// Serve reads frames until stdin closes, which is how a stdio host signals
// shutdown.
func (s *Server) Serve(in io.Reader) error {
	sc := bufio.NewScanner(in)
	// A tool result can carry a secret link, which is small, but the buffer is
	// raised so a large argument cannot truncate a frame into a parse error.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			// Malformed frame with no id: nothing to reply to. Report on stderr
			// and keep the stream alive.
			fmt.Fprintf(stderr, "hush-mcp: unparseable frame: %v\n", err)
			continue
		}
		s.dispatch(req)
	}
	return sc.Err()
}

func (s *Server) dispatch(req request) {
	// A notification has no id and MUST NOT be answered. Replying to one is the
	// classic stdio bug: the host sees an unsolicited response and desyncs.
	isNotification := len(req.ID) == 0

	switch req.Method {
	case "initialize":
		s.reply(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": s.name, "version": s.version},
		})
	case "notifications/initialized":
		// Handshake complete. Nothing to send.
	case "ping":
		s.reply(req.ID, map[string]any{})
	case "tools/list":
		list := make([]map[string]any, 0, len(s.tools))
		for _, t := range s.tools {
			list = append(list, map[string]any{
				"name":        t.Name,
				"title":       t.Title,
				"description": t.Description,
				"inputSchema": t.Schema,
			})
		}
		s.reply(req.ID, map[string]any{"tools": list})
	case "tools/call":
		s.call(req)
	default:
		if !isNotification {
			s.fail(req.ID, codeMethodMissing, "unsupported method: "+req.Method)
		}
	}
}

func (s *Server) call(req request) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.fail(req.ID, codeInvalidParams, "malformed tools/call params")
		return
	}
	for _, t := range s.tools {
		if t.Name != p.Name {
			continue
		}
		text, err := t.Handler(p.Arguments)
		if err != nil {
			// isError:true keeps this a TOOL failure the model can read and
			// react to, rather than a protocol error that looks like the server
			// broke.
			s.reply(req.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": err.Error()}},
				"isError": true,
			})
			return
		}
		s.reply(req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
		})
		return
	}
	s.fail(req.ID, codeInvalidParams, "unknown tool: "+p.Name)
}

func (s *Server) reply(id json.RawMessage, result any) {
	if len(id) == 0 {
		return
	}
	s.write(response{JSONRPC: "2.0", ID: id, Result: result})
}

func (s *Server) fail(id json.RawMessage, code int, msg string) {
	if len(id) == 0 {
		return
	}
	s.write(response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}

func (s *Server) write(r response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.out.Encode(r); err != nil {
		fmt.Fprintf(stderr, "hush-mcp: write failed: %v\n", err)
	}
}
