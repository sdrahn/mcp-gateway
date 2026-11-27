package router

import (
	"context"
	"testing"
	"time"
)

// Without a Unix socket (container mode), Serve waits for the end and
// returns then: clients come over HTTP.
func TestServeWithoutSocket(t *testing.T) {
	r, _ := testRouter(t, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, nil) }()
	select {
	case err := <-done:
		t.Fatalf("Serve returned before the end: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}
