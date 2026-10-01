// Package jsonrpc implements the JSON-RPC 2.0 message framing used by the
// MCP stdio transport: one JSON object per line.
//
// Messages keep params, results and ids as raw JSON so the gateway can
// forward them without re-encoding what it does not need to inspect.
package jsonrpc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Version is the only supported JSON-RPC version.
const Version = "2.0"

// MaxMessageSize bounds a single message to protect the gateway from
// unbounded memory use.
const MaxMessageSize = 32 << 20

// Standard and gateway-specific error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	// CodeForbidden is returned when the gateway's policy denies a request.
	CodeForbidden = -32001
)

// ErrMessageTooLarge is returned by Read for messages over MaxMessageSize.
var ErrMessageTooLarge = errors.New("jsonrpc: message too large")

// Error is a JSON-RPC error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message) }

// LineError is returned by Read for a line that is not valid JSON-RPC: Err
// (also reachable with errors.As) says what is wrong, Line is the line, for
// logging.
type LineError struct {
	Err  *Error
	Line []byte
}

func (e *LineError) Error() string { return e.Err.Error() }

// Unwrap returns the JSON-RPC error.
func (e *LineError) Unwrap() error { return e.Err }

// Message is a request, notification or response.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// IsRequest reports whether m is a request (method and id).
func (m *Message) IsRequest() bool { return m.Method != "" && len(m.ID) > 0 }

// IsNotification reports whether m is a notification (method, no id).
func (m *Message) IsNotification() bool { return m.Method != "" && len(m.ID) == 0 }

// IsResponse reports whether m is a response (id, no method).
func (m *Message) IsResponse() bool { return m.Method == "" && len(m.ID) > 0 }

// Key returns a map key for the message id. Ids 1 and "1" differ.
func (m *Message) Key() string { return string(m.ID) }

// NewRequest builds a request with the given id and params.
func NewRequest(id json.RawMessage, method string, params any) (*Message, error) {
	p, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return &Message{JSONRPC: Version, ID: id, Method: method, Params: p}, nil
}

// NewNotification builds a notification.
func NewNotification(method string, params any) (*Message, error) {
	p, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return &Message{JSONRPC: Version, Method: method, Params: p}, nil
}

// NewResult builds a successful response.
func NewResult(id json.RawMessage, result any) (*Message, error) {
	r, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &Message{JSONRPC: Version, ID: id, Result: r}, nil
}

// NewError builds an error response.
func NewError(id json.RawMessage, code int, msg string) *Message {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &Message{JSONRPC: Version, ID: id, Error: &Error{Code: code, Message: msg}}
}

// MessageConn is a bidirectional message stream: a Conn over a byte
// stream, or a transport that frames messages itself (HTTP).
type MessageConn interface {
	// Read returns the next message. A *Error means the peer sent an
	// invalid message and the connection remains usable.
	Read() (*Message, error)
	Write(m *Message) error
	Close() error
}

var _ MessageConn = (*Conn)(nil)

// Conn reads and writes newline-delimited messages. Write is safe for
// concurrent use; Read must be called from a single goroutine.
type Conn struct {
	r  *bufio.Reader
	w  io.Writer
	c  io.Closer
	mu sync.Mutex
}

// NewConn wraps rwc.
func NewConn(rwc io.ReadWriteCloser) *Conn {
	return &Conn{r: bufio.NewReaderSize(rwc, 64<<10), w: rwc, c: rwc}
}

// Read returns the next message. Blank lines are skipped. A line that is
// not valid JSON-RPC yields a *LineError wrapping a *Error with
// CodeParseError or CodeInvalidRequest; the connection remains usable.
func (c *Conn) Read() (*Message, error) {
	for {
		line, err := c.readLine()
		if err != nil {
			return nil, err
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		m := &Message{}
		if err := json.Unmarshal(line, m); err != nil {
			return nil, &LineError{Err: &Error{Code: CodeParseError, Message: "parse error"}, Line: line}
		}
		if m.JSONRPC != Version || (m.Method == "" && len(m.ID) == 0) {
			return nil, &LineError{Err: &Error{Code: CodeInvalidRequest, Message: "invalid request"}, Line: line}
		}
		return m, nil
	}
}

func (c *Conn) readLine() ([]byte, error) {
	var buf []byte
	for {
		chunk, err := c.r.ReadSlice('\n')
		if len(buf)+len(chunk) > MaxMessageSize {
			return nil, ErrMessageTooLarge
		}
		buf = append(buf, chunk...)
		switch {
		case err == nil:
			return buf, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(bytes.TrimSpace(buf)) > 0:
			return buf, nil
		default:
			return nil, err
		}
	}
}

// Write sends m followed by a newline.
func (c *Conn) Write(m *Message) error {
	if m.JSONRPC == "" {
		m.JSONRPC = Version
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.w.Write(b)
	return err
}

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.c.Close() }
