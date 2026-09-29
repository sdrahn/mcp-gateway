// Command mcpcall makes one MCP request through the gateway's unix socket,
// as the user running it, and prints the result as JSON. The VM tests
// (test/vm) use it to drive the installed gateway.
//
//	mcpcall --server fs --method tools/call --params '{"name":"read_file","arguments":{"path":"/home/alice/a.txt"}}'
//
// It exits with 1 if the request fails (JSON-RPC error) and with 2 if the
// result is a tool error (isError), printing the error or result.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func main() {
	socket := flag.String("socket", config.DefaultSocket, "gateway unix socket")
	server := flag.String("server", "all", `MCP server, or "all" for the aggregated endpoint`)
	method := flag.String("method", "tools/list", "request method")
	params := flag.String("params", "{}", "request params (JSON)")
	timeout := flag.Duration("timeout", 90*time.Second, "overall timeout")
	flag.Parse()

	code, err := run(*socket, *server, *method, json.RawMessage(*params), *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpcall:", err)
	}
	os.Exit(code)
}

func run(socket, server, method string, params json.RawMessage, timeout time.Duration) (int, error) {
	if !json.Valid(params) {
		return 1, errors.New("--params is not valid JSON")
	}
	c, err := net.DialTimeout("unix", socket, 10*time.Second)
	if err != nil {
		return 1, err
	}
	defer func() { _ = c.Close() }()
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 1, err
	}
	w := json.NewEncoder(c)
	r := bufio.NewScanner(c)
	r.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	if server != "all" {
		hello, err := transport.NewHello(server)
		if err != nil {
			return 1, err
		}
		if err := w.Encode(hello); err != nil {
			return 1, err
		}
	}
	// read returns the response to id, skipping notifications and
	// refusing requests from the gateway (the test client offers none).
	read := func(id string) (*message, error) {
		for r.Scan() {
			var m message
			if err := json.Unmarshal(r.Bytes(), &m); err != nil {
				return nil, fmt.Errorf("invalid message %q: %w", r.Text(), err)
			}
			switch {
			case m.Method != "" && len(m.ID) > 0:
				refuse := map[string]any{"jsonrpc": "2.0", "id": m.ID,
					"error": map[string]any{"code": -32601, "message": "not supported by mcpcall"}}
				if err := w.Encode(refuse); err != nil {
					return nil, err
				}
			case m.Method != "":
				// notification
			case string(m.ID) == id:
				return &m, nil
			}
		}
		if err := r.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("connection closed")
	}

	send := func(m map[string]any) error { m["jsonrpc"] = "2.0"; return w.Encode(m) }
	if err := send(map[string]any{"id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "mcpcall", "version": "1"},
	}}); err != nil {
		return 1, err
	}
	init, err := read("1")
	if err != nil {
		return 1, fmt.Errorf("initialize: %w", err)
	}
	if init.Error != nil {
		return 1, fmt.Errorf("initialize: %s", init.Error.Message)
	}
	if err := send(map[string]any{"method": "notifications/initialized"}); err != nil {
		return 1, err
	}
	if err := send(map[string]any{"id": 2, "method": method, "params": params}); err != nil {
		return 1, err
	}
	resp, err := read("2")
	if err != nil {
		return 1, fmt.Errorf("%s: %w", method, err)
	}
	if resp.Error != nil {
		fmt.Printf("{\"error\":{\"code\":%d,\"message\":%q}}\n", resp.Error.Code, resp.Error.Message)
		return 1, nil
	}
	fmt.Println(string(resp.Result))
	var tool struct {
		IsError bool `json:"isError"`
	}
	if json.Unmarshal(resp.Result, &tool) == nil && tool.IsError {
		return 2, nil
	}
	return 0, nil
}
