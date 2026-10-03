package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

func handler(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(params, &p)
		return map[string]any{"protocolVersion": Negotiate(p.ProtocolVersion)}, nil
	case "ping":
		return map[string]any{}, nil
	case "fail":
		return nil, errors.New("broken")
	case "wait":
		<-ctx.Done()
		return map[string]any{}, nil
	}
	return nil, &Error{CodeMethodNotFound, "method not found"}
}

// The protocol: version negotiation, errors, concurrent requests,
// cancellation, oversized messages, notifications without answers.
func TestProtocol(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	srv := New(handler, outW)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(inR, 4096); _ = outW.Close() }()
	responses := make(chan map[string]any, 16)
	go func() {
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				responses <- m
			}
		}
		close(responses)
	}()
	send := func(s string) {
		if _, err := io.WriteString(inW, s+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	next := func() map[string]any {
		select {
		case m := <-responses:
			return m
		case <-time.After(5 * time.Second):
			t.Fatal("no answer")
		}
		return nil
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	if m := next(); m["result"].(map[string]any)["protocolVersion"] != "2024-11-05" {
		t.Errorf("negotiated: %v", m)
	}
	send(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	if m := next(); m["result"].(map[string]any)["protocolVersion"] != ProtocolVersions[0] {
		t.Errorf("unknown version: %v", m)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":3,"method":"nope"}`)
	if m := next(); m["error"].(map[string]any)["code"] != float64(CodeMethodNotFound) {
		t.Errorf("unknown method: %v", m)
	}
	send(`{"jsonrpc":"2.0","id":3,"method":"fail"}`)
	if m := next(); m["error"].(map[string]any)["code"] != float64(CodeInternal) || m["error"].(map[string]any)["message"] != "broken" {
		t.Errorf("internal error: %v", m)
	}
	send(`not json`)
	if m := next(); m["error"].(map[string]any)["code"] != float64(CodeParse) {
		t.Errorf("parse error: %v", m)
	}
	send(`{"jsonrpc":"2.0","id":4,"method":"ping","params":{"x":"` + strings.Repeat("x", 5000) + `"}}`)
	if m := next(); m["error"].(map[string]any)["message"] != "message too large" {
		t.Errorf("oversized: %v", m)
	}
	send(`{"jsonrpc":"2.0","id":"s","method":"ping"}`)
	if m := next(); m["id"] != "s" || m["result"] == nil {
		t.Errorf("ping: %v", m)
	}

	// A cancelled request gets no answer; the next one does.
	send(`{"jsonrpc":"2.0","id":5,"method":"wait"}`)
	time.Sleep(50 * time.Millisecond)
	send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":5}}`)
	send(`{"jsonrpc":"2.0","id":6,"method":"ping"}`)
	if m := next(); m["id"] != float64(6) {
		t.Errorf("after the cancelled request: %v (the cancelled one was answered?)", m)
	}

	// The end of the input ends requests still running.
	send(`{"jsonrpc":"2.0","id":7,"method":"wait"}`)
	time.Sleep(50 * time.Millisecond)
	_ = inW.Close()
	if err := <-done; err != nil {
		t.Errorf("serve: %v", err)
	}
}

// Requests beyond MaxConcurrent wait for a slot: with every slot taken
// by a waiting request, a ping is answered only after one is cancelled.
func TestConcurrencyBound(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	srv := New(handler, outW)
	go func() { _ = srv.Serve(inR, 4096); _ = outW.Close() }()
	answered := make(chan struct{}, 1)
	go func() {
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			if strings.Contains(sc.Text(), `"id":"p"`) {
				answered <- struct{}{}
			}
		}
	}()
	defer func() { _ = inW.Close() }()
	send := func(s string) {
		if _, err := io.WriteString(inW, s+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < MaxConcurrent; i++ {
		send(`{"jsonrpc":"2.0","id":` + strconv.Itoa(i) + `,"method":"wait"}`)
	}
	for deadline := time.Now().Add(5 * time.Second); len(srv.slots) < MaxConcurrent; {
		if time.Now().After(deadline) {
			t.Fatal("the waiting requests did not take every slot")
		}
		time.Sleep(time.Millisecond)
	}
	send(`{"jsonrpc":"2.0","id":"p","method":"ping"}`)
	select {
	case <-answered:
		t.Fatal("answered with every slot taken")
	case <-time.After(100 * time.Millisecond):
	}
	send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":0}}`)
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("not answered after a slot was freed")
	}
}
