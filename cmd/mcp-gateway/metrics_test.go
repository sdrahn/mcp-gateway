package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestServeMetrics(t *testing.T) {
	// A free port, then serve on it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	stop, err := serveMetrics(slog.New(slog.DiscardHandler), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "# TYPE mcp_gateway_decisions_total counter") {
		t.Fatalf("GET /metrics: %d\n%s", resp.StatusCode, body)
	}
	resp, err = http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /: %d", resp.StatusCode)
	}
	if _, err := serveMetrics(slog.New(slog.DiscardHandler), addr); err == nil {
		t.Error("a second listener on the same address: no error")
	}
}
