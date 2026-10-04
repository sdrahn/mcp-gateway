package router

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// A policy file written: the fingerprint is checked shortly after, and
// again while OPA has not reloaded it yet, long before the interval.
func TestWatchPolicyChanged(t *testing.T) {
	r := &Router{Log: slog.New(slog.DiscardHandler)}
	var mu sync.Mutex
	calls, reloadAt := 0, 3 // OPA has the new policy from the third check on
	fp := func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls >= reloadAt {
			return "new", nil
		}
		return "old", nil
	}
	changes := make(chan struct{}, 4)
	changed := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.WatchPolicy(ctx, func() time.Duration { return time.Hour }, fp, func() { changes <- struct{}{} }, changed)
	time.Sleep(50 * time.Millisecond) // the first check
	start := time.Now()
	changed <- struct{}{}
	select {
	case <-changes:
	case <-time.After(5 * time.Second):
		t.Fatal("the change was not noticed")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("noticed after %v", d)
	}
	time.Sleep(3500 * time.Millisecond) // the remaining rechecks find nothing new
	if len(changes) != 0 {
		t.Error("the change was reported twice")
	}
}
