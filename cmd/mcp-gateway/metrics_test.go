package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	stop, err := serveMetrics(slog.New(slog.DiscardHandler), addr, nil)
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
	if _, err := serveMetrics(slog.New(slog.DiscardHandler), addr, nil); err == nil {
		t.Error("a second listener on the same address: no error")
	}
}

// The probes: /healthz while the process serves, /readyz while the
// policy engine answers.
func TestProbes(t *testing.T) {
	var opaErr error
	var draining atomic.Bool
	h := metricsHandler(readiness(&draining, func(context.Context) error { return opaErr }))
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.String()
	}
	if code, body := get("/healthz"); code != 200 || body != "ok\n" {
		t.Errorf("healthz %d %q", code, body)
	}
	if code, body := get("/readyz"); code != 200 || body != "ready\n" {
		t.Errorf("readyz %d %q", code, body)
	}
	opaErr = errors.New("opa: dial unix /run/mcp-gateway/opa.sock: no such file")
	if code, body := get("/readyz"); code != http.StatusServiceUnavailable || !strings.Contains(body, "the policy engine: opa: dial") {
		t.Errorf("readyz without OPA %d %q", code, body)
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Errorf("healthz without OPA %d", code)
	}
	// A replica that stops: not ready, still healthy.
	opaErr = nil
	draining.Store(true)
	if code, body := get("/readyz"); code != http.StatusServiceUnavailable || !strings.Contains(body, "draining") {
		t.Errorf("readyz while draining %d %q", code, body)
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Errorf("healthz while draining %d", code)
	}
}
