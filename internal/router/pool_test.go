package router

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// fakeClock is a settable time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testPool(t *testing.T, idle time.Duration) (*pool, *fakeLauncher, *fakeClock) {
	t.Helper()
	l := newFakeLauncher(t)
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	p := newPool(l, idle, slog.New(slog.DiscardHandler))
	p.now = clock.now
	t.Cleanup(p.closeAll)
	return p, l, clock
}

// crash makes the most recent instance of b exit and waits until the
// pool noticed.
func crash(t *testing.T, p *pool, l *fakeLauncher, b *config.Backend) {
	t.Helper()
	insts := l.started(b.Name)
	_ = insts[len(insts)-1].Close()
	key := instanceKey(b, alice())
	for i := 0; i < 400; i++ {
		p.mu.Lock()
		_, alive := p.entries[key]
		p.mu.Unlock()
		if !alive {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pool did not notice the crash")
}

func retryIn(t *testing.T, err error) time.Duration {
	t.Helper()
	var b *BackoffError
	if !errors.As(err, &b) {
		t.Fatalf("got %v, want a backoff error", err)
	}
	return b.RetryIn
}

func TestRestartBackoff(t *testing.T) {
	p, l, clock := testPool(t, time.Hour)
	b := &config.Backend{Name: "fs", Isolation: config.IsolationPrincipal}
	ctx := context.Background()

	if _, _, err := p.acquire(ctx, b, alice()); err != nil {
		t.Fatal(err)
	}
	clock.add(time.Second)
	crash(t, p, l, b)
	_, _, err := p.acquire(ctx, b, alice())
	if d := retryIn(t, err); d != backoffBase {
		t.Fatalf("first retry in %s", d)
	}
	if n := len(l.started("fs")); n != 1 {
		t.Fatalf("%d starts during backoff", n)
	}

	// After the wait, the instance starts again; crashing right away
	// doubles the wait.
	clock.add(backoffBase)
	if _, _, err := p.acquire(ctx, b, alice()); err != nil {
		t.Fatal(err)
	}
	crash(t, p, l, b)
	_, _, err = p.acquire(ctx, b, alice())
	if d := retryIn(t, err); d != 2*backoffBase {
		t.Fatalf("second retry in %s", d)
	}

	// Other principals and backends are not affected.
	bob := alice()
	bob.Sub = "bob"
	if _, _, err := p.acquire(ctx, b, bob); err != nil {
		t.Fatal(err)
	}

	// An instance that ran stably starts the count afresh.
	clock.add(2 * backoffBase)
	if _, _, err := p.acquire(ctx, b, alice()); err != nil {
		t.Fatal(err)
	}
	clock.add(stableAfter)
	crash(t, p, l, b)
	_, _, err = p.acquire(ctx, b, alice())
	if d := retryIn(t, err); d != backoffBase {
		t.Fatalf("retry after a stable run in %s", d)
	}
}

func TestRestartBackoffCapped(t *testing.T) {
	p, l, clock := testPool(t, time.Hour)
	b := &config.Backend{Name: "fs", Isolation: config.IsolationPrincipal}
	l.fail = errors.New("no such unit")
	var last time.Duration
	for i := 0; i < 40; i++ {
		_, _, err := p.acquire(context.Background(), b, alice())
		if err == nil || errors.As(err, new(*BackoffError)) {
			t.Fatalf("attempt %d: %v", i, err)
		}
		_, _, err = p.acquire(context.Background(), b, alice())
		last = retryIn(t, err)
		clock.add(last)
	}
	if last != backoffMax {
		t.Fatalf("wait not capped: %s", last)
	}
}

func TestIdleStopIsNoFailure(t *testing.T) {
	p, l, _ := testPool(t, 0)
	b := &config.Backend{Name: "fs", Isolation: config.IsolationPrincipal}
	_, release, err := p.acquire(context.Background(), b, alice())
	if err != nil {
		t.Fatal(err)
	}
	up := p.entries[instanceKey(b, alice())].up
	release()
	<-up.closed
	time.Sleep(20 * time.Millisecond) // let the watcher run
	if _, _, err := p.acquire(context.Background(), b, alice()); err != nil {
		t.Fatalf("restart after an idle stop: %v", err)
	}
	if n := len(l.started("fs")); n != 2 {
		t.Fatalf("%d starts", n)
	}
}

func TestCancelledStartIsNoFailure(t *testing.T) {
	p, l, _ := testPool(t, time.Hour)
	b := &config.Backend{Name: "fs", Isolation: config.IsolationPrincipal}
	l.fail = context.Canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := p.acquire(ctx, b, alice()); err == nil {
		t.Fatal("start succeeded")
	}
	l.fail = nil
	if _, _, err := p.acquire(context.Background(), b, alice()); err != nil {
		t.Fatalf("cancelled start delayed the next one: %v", err)
	}
}
