package transport

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
)

// HelloMethod is the notification a client sends first to select a backend
// (mcp-connect does this). It is a valid JSON-RPC notification, so it
// travels over the same framing as MCP itself.
const HelloMethod = "mcp-gateway/hello"

// HelloVersion is the current hello protocol version.
const HelloVersion = 1

// Hello selects the endpoint for a connection.
type Hello struct {
	Version int `json:"version"`
	// Server is a backend name, or "all" for the aggregated endpoint.
	Server string `json:"server"`
}

// NewHello builds the hello notification.
func NewHello(server string) (*jsonrpc.Message, error) {
	return jsonrpc.NewNotification(HelloMethod, Hello{Version: HelloVersion, Server: server})
}

// ErrNoHello means the client started with an MCP message instead of a
// hello, i.e. it wants the aggregated endpoint.
var ErrNoHello = errors.New("transport: no hello")

// ParseHello interprets the first message of a connection.
func ParseHello(m *jsonrpc.Message) (Hello, error) {
	if m.Method != HelloMethod {
		return Hello{}, ErrNoHello
	}
	if !m.IsNotification() {
		return Hello{}, errors.New("transport: hello must be a notification")
	}
	var h Hello
	if err := json.Unmarshal(m.Params, &h); err != nil {
		return Hello{}, fmt.Errorf("transport: invalid hello: %w", err)
	}
	if h.Version != HelloVersion {
		return Hello{}, fmt.Errorf("transport: unsupported hello version %d", h.Version)
	}
	if h.Server == "" {
		return Hello{}, errors.New("transport: hello without server")
	}
	return h, nil
}
