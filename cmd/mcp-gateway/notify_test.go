package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type notifications struct {
	mu   sync.Mutex
	sent []string
}

func (n *notifications) notify(s string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, s)
	return nil
}

func (n *notifications) all() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.sent...)
}

func (n *notifications) count(sub string) int {
	c := 0
	for _, s := range n.all() {
		if strings.Contains(s, sub) {
			c++
		}
	}
	return c
}

func TestNotifySystemd(t *testing.T) {
	var n notifications
	var mu sync.Mutex // held: the gateway is stuck
	probe := func() string {
		mu.Lock()
		defer mu.Unlock()
		return statusLine(2, 1, 0)
	}
	var logs lockedBuffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		notifySystemd(ctx, log, n.notify, 60*time.Millisecond, probe)
		close(done)
	}()

	waitFor(t, func() bool { return n.count("WATCHDOG=1") >= 2 })
	if got := n.all(); got[0] != "READY=1" || !strings.Contains(got[1], "STATUS=2 sessions, 1 server instances, 0 pending approvals") {
		t.Fatalf("notifications %q", got)
	}

	mu.Lock() // stuck: no more pings
	waitFor(t, func() bool { return strings.Contains(logs.String(), "locked for too long") })
	before := n.count("WATCHDOG=1")
	time.Sleep(150 * time.Millisecond)
	if after := n.count("WATCHDOG=1"); after != before {
		t.Errorf("pings while stuck: %d, then %d", before, after)
	}
	mu.Unlock() // responds again
	waitFor(t, func() bool { return n.count("WATCHDOG=1") > before })

	cancel()
	<-done
	if got := n.all(); !strings.HasPrefix(got[len(got)-1], "STOPPING=1") {
		t.Errorf("last notification %q", got[len(got)-1])
	}
}

// Without a watchdog, only readiness and the status line are sent.
func TestNotifySystemdNoWatchdog(t *testing.T) {
	var n notifications
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		notifySystemd(ctx, slog.New(slog.DiscardHandler), n.notify, 0, func() string { return "ok" })
		close(done)
	}()
	waitFor(t, func() bool { return n.count("STATUS=ok") >= 1 })
	cancel()
	<-done
	if n.count("WATCHDOG") != 0 {
		t.Errorf("watchdog pings without a watchdog: %q", n.all())
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
