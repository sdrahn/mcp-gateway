package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// The protocol versions this server speaks, newest first. A client asking
// for another gets the newest (the client then decides whether to go on).
var protocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// maxConcurrent bounds the requests handled at once; more wait.
const maxConcurrent = 8

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return e.Message }

// JSON-RPC and MCP error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	codeNoResource     = -32002
)

// server answers MCP requests on a stream of newline-delimited JSON-RPC
// messages. Requests run concurrently, each with a context that a
// notifications/cancelled from the client ends; the answer to a cancelled
// request is not sent.
type server struct {
	fs *fileServer

	mu       sync.Mutex // guards out, inflight
	out      *json.Encoder
	inflight map[string]context.CancelFunc

	slots chan struct{}
	wg    sync.WaitGroup
}

func newServer(fs *fileServer, w io.Writer) *server {
	return &server{fs: fs, out: json.NewEncoder(w), inflight: map[string]context.CancelFunc{},
		slots: make(chan struct{}, maxConcurrent)}
}

// serve reads messages from r until it ends, then cancels what is still
// running and waits for it. maxMessage bounds a message's size; a longer
// line is answered with an error and skipped.
func (s *server) serve(r io.Reader, maxMessage int) error {
	in := bufio.NewReaderSize(r, 64<<10)
	for {
		line, tooLong, err := readLine(in, maxMessage)
		if len(bytes.TrimSpace(line)) > 0 || tooLong {
			if tooLong {
				s.send(message{ID: json.RawMessage("null"), Error: &rpcError{codeInvalidRequest, "message too large"}})
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

func (s *server) dispatch(line []byte) {
	var m message
	if err := json.Unmarshal(line, &m); err != nil {
		s.send(message{ID: json.RawMessage("null"), Error: &rpcError{codeParse, "parse error"}})
		return
	}
	switch {
	case m.Method == "" && len(m.ID) > 0:
		return // a response; this server sends no requests
	case m.Method == "":
		s.send(message{ID: json.RawMessage("null"), Error: &rpcError{codeInvalidRequest, "invalid request"}})
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
		var rerr *rpcError
		switch {
		case errors.As(err, &rerr):
			resp.Error = rerr
		case err != nil:
			resp.Error = &rpcError{codeInternal, err.Error()}
		default:
			resp.Result = res
		}
		s.send(resp)
	}()
}

func (s *server) notification(m message) {
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

func (s *server) send(m message) {
	m.JSONRPC = "2.0"
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.out.Encode(m)
}

func (s *server) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(params, &p)
		version := protocolVersions[0]
		for _, v := range protocolVersions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "title": "Files", "version": serverVersion},
			"instructions":    s.fs.instructions(),
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": s.fs.toolList()}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcError{codeInvalidParams, "invalid params"}
		}
		return s.fs.call(ctx, p.Name, p.Arguments)
	case "resources/list":
		var p struct {
			Cursor string `json:"cursor"`
		}
		_ = json.Unmarshal(params, &p)
		return s.fs.resourceList(p.Cursor)
	case "resources/templates/list":
		return map[string]any{"resourceTemplates": s.fs.resourceTemplates()}, nil
	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.URI == "" {
			return nil, &rpcError{codeInvalidParams, "invalid params"}
		}
		return s.fs.readResource(p.URI)
	case "prompts/list":
		return map[string]any{"prompts": []map[string]any{{
			"name": "summarize_file", "title": "Summarize a file", "description": "Summarize a file",
			"arguments": []map[string]any{{"name": "path", "description": "the file", "required": true}},
		}}}, nil
	case "prompts/get":
		var p struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.Name != "summarize_file" {
			return nil, &rpcError{codeInvalidParams, "unknown prompt"}
		}
		if p.Arguments["path"] == "" {
			return nil, &rpcError{codeInvalidParams, "argument path is required"}
		}
		return map[string]any{"messages": []map[string]any{{
			"role":    "user",
			"content": map[string]any{"type": "text", "text": "Summarize the file at " + p.Arguments["path"] + "."},
		}}}, nil
	}
	return nil, &rpcError{codeMethodNotFound, "method not found"}
}
