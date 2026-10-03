// Package mcpserver is the protocol core of the MCP servers this project
// ships (mcp-server-fs, the gateway's own gateway-admin): newline-delimited
// JSON-RPC messages on a stream, requests handled concurrently, each with
// a context that a notifications/cancelled from the client ends. What a
// request does is the Handler's.
package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// ProtocolVersions are the protocol versions the servers speak, newest
// first.
var ProtocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// Negotiate returns the version to answer an initialize request asking
// for requested: that one if spoken, else the newest (the client then
// decides whether to go on).
func Negotiate(requested string) string {
	for _, v := range ProtocolVersions {
		if v == requested {
			return v
		}
	}
	return ProtocolVersions[0]
}

// MaxConcurrent bounds the requests handled at once; more wait.
const MaxConcurrent = 8

// Error is a JSON-RPC error. A Handler returning one has it sent as is;
// any other error is sent as an internal error.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

// JSON-RPC and MCP error codes.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
	CodeNoResource     = -32002
)

// Handler answers one request. ctx ends when the client cancels it or the
// connection ends.
type Handler func(ctx context.Context, method string, params json.RawMessage) (any, error)

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Server answers MCP requests read from a stream; the answer to a
// cancelled request is not sent.
type Server struct {
	handle Handler

	mu       sync.Mutex // guards out, inflight
	out      *json.Encoder
	inflight map[string]context.CancelFunc

	slots chan struct{}
	wg    sync.WaitGroup
}

// New returns a server that writes its answers to w.
func New(h Handler, w io.Writer) *Server {
	return &Server{handle: h, out: json.NewEncoder(w), inflight: map[string]context.CancelFunc{},
		slots: make(chan struct{}, MaxConcurrent)}
}

// Serve reads messages from r until it ends, then cancels what is still
// running and waits for it. maxMessage bounds a message's size; a longer
// line is answered with an error and skipped.
func (s *Server) Serve(r io.Reader, maxMessage int) error {
	in := bufio.NewReaderSize(r, 64<<10)
	for {
		line, tooLong, err := readLine(in, maxMessage)
		if len(bytes.TrimSpace(line)) > 0 || tooLong {
			if tooLong {
				s.send(message{ID: json.RawMessage("null"), Error: &Error{CodeInvalidRequest, "message too large"}})
			} else {
				s.dispatch(line)
			}
		}
		if err != nil {
			s.mu.Lock()
			for _, cancel := range s.inflight {
				cancel()
			}
			s.mu.Unlock()
			s.wg.Wait()
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// readLine returns the next line without its newline; a line longer than
// max is consumed and reported as too long.
func readLine(r *bufio.Reader, max int) ([]byte, bool, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > max+1 {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			return nil, true, err
		}
		line = append(line, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return bytes.TrimSuffix(line, []byte("\n")), false, err
	}
}

func (s *Server) dispatch(line []byte) {
	var m message
	if err := json.Unmarshal(line, &m); err != nil {
		s.send(message{ID: json.RawMessage("null"), Error: &Error{CodeParse, "parse error"}})
		return
	}
	switch {
	case m.Method == "" && len(m.ID) > 0:
		return // a response; these servers send no requests
	case m.Method == "":
		s.send(message{ID: json.RawMessage("null"), Error: &Error{CodeInvalidRequest, "invalid request"}})
		return
	case len(m.ID) == 0:
		s.notification(m)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	key := string(m.ID)
	s.mu.Lock()
	s.inflight[key] = cancel
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.slots <- struct{}{}
		defer func() { <-s.slots }()
		res, err := s.handle(ctx, m.Method, m.Params)
		s.mu.Lock()
		delete(s.inflight, key)
		s.mu.Unlock()
		cancelled := ctx.Err() != nil
		cancel()
		if cancelled {
			return
		}
		resp := message{ID: m.ID}
		var rerr *Error
		switch {
		case errors.As(err, &rerr):
			resp.Error = rerr
		case err != nil:
			resp.Error = &Error{CodeInternal, err.Error()}
		default:
			resp.Result = res
		}
		s.send(resp)
	}()
}

func (s *Server) notification(m message) {
	if m.Method != "notifications/cancelled" {
		return // initialized, roots/list_changed, ...: nothing to do
	}
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(m.Params, &p) != nil {
		return
	}
	s.mu.Lock()
	cancel := s.inflight[string(p.RequestID)]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Server) send(m message) {
	m.JSONRPC = "2.0"
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.out.Encode(m)
}
