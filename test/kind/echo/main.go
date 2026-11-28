// Command echo is a test server for the kind test of the container image
// (test/kind/run.sh): over Streamable HTTP (JSON responses) on :8080, or
// with -stdio over stdin and stdout, as an instance of the Kubernetes
// launcher. Its tools: echo (counts the calls it answers, so the test
// sees that a call ran once) and reach (tries a TCP connection to an
// address, so the test sees what an instance's NetworkPolicy lets it
// reach). With -call URL it is a client instead: it calls the echo tool
// of the server at URL through the gateway over and over, with the
// ServiceAccount token of -token and the CA of -ca, and prints a line per
// call (ok or failed), so that the test sees a rolling update of the
// gateway's replicas cut no call off.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
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
	call := flag.String("call", "", "call the echo tool at this URL over and over")
	token := flag.String("token", "/var/run/secrets/tokens/token", "with -call: the file of the bearer token")
	ca := flag.String("ca", "/etc/mcp-gateway-ca/ca.crt", "with -call: the CA of the gateway's certificate")
	every := flag.Duration("every", 200*time.Millisecond, "with -call: the pause between calls")
	flag.Parse()
	if *call != "" {
		callLoop(*call, *token, *ca, *every)
		return
	}
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

// callLoop calls the echo tool at url, each call in a session of its own,
// until it is stopped.
func callLoop(url, tokenFile, caFile string, every time.Duration) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatalf("no certificate in %s", caFile)
	}
	// A connection of its own for each request, as a new client would
	// open: the Service picks a replica for each.
	c := &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}}
	for n := 1; ; n++ {
		start := time.Now()
		text, err := callOnce(c, url, tokenFile, n)
		if err != nil {
			fmt.Printf("failed %d after %s: %v\n", n, time.Since(start).Round(time.Millisecond), err)
		} else {
			fmt.Printf("ok %d after %s: %s\n", n, time.Since(start).Round(time.Millisecond), text)
		}
		time.Sleep(every)
	}
}

func callOnce(c *http.Client, url, tokenFile string, n int) (string, error) {
	tok, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", err
	}
	bearer := "Bearer " + strings.TrimSpace(string(tok))
	post := func(session string, body any) (*http.Response, []byte, error) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
		req.Header.Set("Authorization", bearer)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
			req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		out, err := io.ReadAll(resp.Body)
		return resp, out, err
	}
	resp, _, err := post("", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "kind-caller", "version": "1"}}})
	if err != nil {
		return "", fmt.Errorf("initialize: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("initialize: HTTP %d", resp.StatusCode)
	}
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		return "", errors.New("initialize: no session")
	}
	defer func() {
		req, _ := http.NewRequest(http.MethodDelete, url, nil)
		req.Header.Set("Authorization", bearer)
		req.Header.Set("Mcp-Session-Id", session)
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		if resp, err := c.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	if resp, _, err := post(session, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return "", fmt.Errorf("initialized: %w", err)
	} else if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("initialized: HTTP %d", resp.StatusCode)
	}
	resp, body, err := post(session, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": "echo", "arguments": map[string]any{"text": fmt.Sprint("call ", n)}}})
	if err != nil {
		return "", fmt.Errorf("tools/call: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tools/call: HTTP %d: %.200s", resp.StatusCode, body)
	}
	var m struct {
		Result *struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return "", fmt.Errorf("tools/call: %w: %.200s", err, body)
	}
	switch {
	case m.Error != nil:
		return "", fmt.Errorf("tools/call: %s", m.Error.Message)
	case m.Result == nil || len(m.Result.Content) == 0:
		return "", fmt.Errorf("tools/call: %.200s", body)
	case m.Result.IsError:
		return "", fmt.Errorf("tools/call: the tool's error: %s", m.Result.Content[0].Text)
	}
	return m.Result.Content[0].Text, nil
}
