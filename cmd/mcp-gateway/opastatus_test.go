package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A status report (POST /status) has the policy checked; other paths and
// methods do not, nor does a report over the size limit; a bundle OPA
// could not activate is logged; reports while a check is due add none.
func TestOPAStatusHandler(t *testing.T) {
	var logs bytes.Buffer
	notify := make(chan struct{}, 1)
	h := opaStatusHandler(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), notify)
	do := func(method, path, body string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec.Code
	}
	notified := func() bool {
		select {
		case <-notify:
			return true
		default:
			return false
		}
	}
	if code := do(http.MethodPost, "/status", `{"bundles":{"mcp":{"active_revision":"r2"}}}`); code != http.StatusOK || !notified() {
		t.Fatalf("report: %d, notified %v", code, !notified())
	}
	if !strings.Contains(logs.String(), `bundles="mcp=r2"`) {
		t.Errorf("not logged: %s", logs.String())
	}
	if code := do(http.MethodGet, "/status", ""); code != http.StatusMethodNotAllowed || notified() {
		t.Errorf("GET: %d", code)
	}
	if code := do(http.MethodPost, "/other", "{}"); code != http.StatusNotFound || notified() {
		t.Errorf("other path: %d", code)
	}
	if code := do(http.MethodPost, "/status", strings.Repeat("x", maxStatusReport+1)); code != http.StatusRequestEntityTooLarge || notified() {
		t.Errorf("too large: %d", code)
	}
	logs.Reset()
	if code := do(http.MethodPost, "/status", `{"bundles":{"mcp":{"active_revision":"r2","code":"bundle_error","message":"signature verification failed"}}}`); code != http.StatusOK {
		t.Fatalf("failed bundle: %d", code)
	}
	if !strings.Contains(logs.String(), "could not activate") || !strings.Contains(logs.String(), "signature verification failed") {
		t.Errorf("failure not logged: %s", logs.String())
	}
	// Not JSON: still a reason to look.
	do(http.MethodPost, "/status", "not json")
	if !notified() || notified() {
		t.Error("one check due, not two")
	}
}

// The listener serves the handler on the address; stopping it closes it.
func TestServeOPAStatus(t *testing.T) {
	notify := make(chan struct{}, 1)
	stop, err := serveOPAStatus(slog.New(slog.DiscardHandler), "127.0.0.1:0", notify)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if _, err := serveOPAStatus(slog.New(slog.DiscardHandler), "256.0.0.1:x", notify); err == nil || !strings.Contains(err.Error(), "policy.status_listen") {
		t.Errorf("bad address: %v", err)
	}
}

// Any of the channels signals the merged one; nil ones are left out.
func TestMergeSignals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := make(chan struct{}, 1), make(chan struct{}, 1)
	out := mergeSignals(ctx, a, nil, b)
	for _, c := range []chan struct{}{a, b} {
		c <- struct{}{}
		select {
		case <-out:
		case <-time.After(5 * time.Second):
			t.Fatal("no signal")
		}
	}
}
