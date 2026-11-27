// Command echo is a test server for the kind test of the container image
// (test/kind/run.sh): over Streamable HTTP (JSON responses) on :8080, or
// with -stdio over stdin and stdout, as an instance of the Kubernetes
// launcher. Its tools: echo (counts the calls it answers, so the test
// sees that a call ran once) and reach (tries a TCP connection to an
// address, so the test sees what an instance's NetworkPolicy lets it
// reach).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

type request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"params"`
}

var calls atomic.Int64

// answer is the result of a request.
func answer(m request) any {
	switch m.Method {
	case "initialize":
		return map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{"name": "echo", "version": "1"}}
	case "tools/list":
		str := map[string]any{"type": "string"}
		return map[string]any{"tools": []any{
			map[string]any{"name": "echo", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"text": str}}},
			map[string]any{"name": "reach", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"address": str}}},
		}}
	case "tools/call":
		var text string
		if m.Params.Name == "reach" {
			c, err := net.DialTimeout("tcp", fmt.Sprint(m.Params.Arguments["address"]), 3*time.Second)
			if err != nil {
				text = "unreachable: " + err.Error()
			} else {
				_ = c.Close()
				text = "reachable"
			}
		} else {
			text = fmt.Sprintf("echo: %v (call %d)", m.Params.Arguments["text"], calls.Add(1))
		}
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}
	}
	return map[string]any{}
}

func main() {
	stdio := flag.Bool("stdio", false, "speak MCP over stdin and stdout")
	flag.Parse()
	if *stdio {
		serveStdio()
		return
	}
	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var m request
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if m.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": answer(m)})
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func serveStdio() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64<<10), 4<<20)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var m request
		if json.Unmarshal(in.Bytes(), &m) != nil || m.ID == nil {
			continue
		}
		_ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": answer(m)})
	}
}
