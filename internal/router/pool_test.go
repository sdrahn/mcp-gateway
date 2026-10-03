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

func TestListAndStopInstances(t *testing.T) {
	p, l, _ := testPool(t, time.Hour)
	b := &config.Backend{Name: "fs", Isolation: config.IsolationPrincipal}
	up, _, err := p.acquire(context.Background(), b, alice())
	if err != nil {
		t.Fatal(err)
	}
	list := p.list()
	if len(list) != 1 || list[0].ID != up.id || list[0].Server != "fs" || list[0].Sub != "alice" ||
		list[0].Sessions != 1 || list[0].Unit == "" || list[0].SessionID != "" {
		t.Fatalf("list %+v", list)
	}
	if p.stop("nope") {
		t.Fatal("stopped an unknown instance")
	}
	if !p.stop(up.id) {
		t.Fatal("stop failed")
	}
	<-up.closed
	if len(p.list()) != 0 {
		t.Fatal("stopped instance still listed")
	}
	time.Sleep(20 * time.Millisecond) // let the watcher run
	// A stop on request is no failure: the next call starts a new one.
	if _, _, err := p.acquire(context.Background(), b, alice()); err != nil {
		t.Fatal(err)
	}
	if n := len(l.started("fs")); n != 2 {
		t.Fatalf("%d starts", n)
	}
}

// startCommit sends a "commit" call to u whose caller gives up at once,
// as a client does that cancels or disconnects; the backend goes on.
func startCommit(t *testing.T, u *upstream) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = u.request(ctx, nil, "tools/call", map[string]any{"name": "commit"})
	}()
	for !u.busy() {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}

func isClosed(ch chan struct{}, wait time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(wait):
		return false
	}
}

func TestPrivilegedInstanceKeptWhileCallRuns(t *testing.T) {
	for _, privileged := range []bool{false, true} {
		p, l, _ := testPool(t, 0) // stop as soon as unused
		b := &config.Backend{Name: "zypp", Isolation: config.IsolationPrincipal, Privileged: privileged}
		u, release, err := p.acquire(context.Background(), b, alice())
		if err != nil {
			t.Fatal(err)
		}
		fi := l.started("zypp")[0]
		startCommit(t, u)
		release()
		if !privileged {
			if !isClosed(fi.closed, time.Second) {
				t.Fatal("unprivileged instance not stopped")
			}
			continue
		}
		if isClosed(fi.closed, 50*time.Millisecond) {
			t.Fatal("privileged instance stopped while a call runs")
		}
		if infos := p.list(); len(infos) != 1 || !infos[0].Privileged || !infos[0].Busy {
			t.Fatalf("instances %+v", infos)
		}
		if p.stop(u.id) {
			t.Fatal("stop on request stopped a busy privileged instance")
		}
		close(fi.commit)
		if !isClosed(fi.closed, time.Second) {
			t.Fatal("privileged instance not stopped after the call ended")
		}
	}
}

func TestCloseAllWaitsForPrivilegedCalls(t *testing.T) {
	p, l, _ := testPool(t, time.Hour)
	b := &config.Backend{Name: "zypp", Isolation: config.IsolationPrincipal, Privileged: true}
	u, _, err := p.acquire(context.Background(), b, alice())
	if err != nil {
		t.Fatal(err)
	}
	fs := &config.Backend{Name: "fs", Isolation: config.IsolationPrincipal}
	if _, _, err := p.acquire(context.Background(), fs, alice()); err != nil {
		t.Fatal(err)
	}
	startCommit(t, u)
	closed := make(chan struct{})
	go func() {
		p.closeAll()
		close(closed)
	}()
	if !isClosed(l.started("fs")[0].closed, time.Second) {
		t.Fatal("unprivileged instance not stopped at once")
	}
	if isClosed(closed, 50*time.Millisecond) {
		t.Fatal("closeAll did not wait for the privileged call")
	}
	if _, err := u.request(context.Background(), nil, "tools/list", nil); !errors.Is(err, errShuttingDown) {
		t.Fatalf("new request while draining: %v", err)
	}
	close(l.started("zypp")[0].commit)
	if !isClosed(closed, time.Second) {
		t.Fatal("closeAll did not return after the call ended")
	}
}

func TestCloseAllDrainTimeout(t *testing.T) {
	p, l, clock := testPool(t, time.Hour)
	p.drainTimeout = time.Minute
	b := &config.Backend{Name: "zypp", Isolation: config.IsolationPrincipal, Privileged: true}
	u, _, err := p.acquire(context.Background(), b, alice())
	if err != nil {
		t.Fatal(err)
	}
	startCommit(t, u)
	closed := make(chan struct{})
	go func() {
		p.closeAll()
		close(closed)
	}()
	if isClosed(closed, 50*time.Millisecond) {
		t.Fatal("closeAll did not wait")
	}
	clock.add(time.Minute)
	if !isClosed(closed, time.Second) || !isClosed(l.started("zypp")[0].closed, time.Second) {
		t.Fatal("closeAll did not stop the instance after the drain timeout")
	}
}

func TestRetire(t *testing.T) {
	p, l, _ := testPool(t, time.Hour)
	fs := &config.Backend{Name: "fs", Isolation: config.IsolationPrincipal}
	zypp := &config.Backend{Name: "zypp", Isolation: config.IsolationPrincipal, Privileged: true}
	if _, _, err := p.acquire(context.Background(), fs, alice()); err != nil { // held by a session
		t.Fatal(err)
	}
	u, _, err := p.acquire(context.Background(), zypp, alice())
	if err != nil {
		t.Fatal(err)
	}
	startCommit(t, u)

	if n := p.retire("fs"); n != 1 {
		t.Fatalf("retired %d", n)
	}
	if !isClosed(l.started("fs")[0].closed, time.Second) {
		t.Fatal("instance in use not stopped")
	}
	if _, _, err := p.acquire(context.Background(), fs, alice()); err != nil || len(l.started("fs")) != 2 {
		t.Fatalf("no new instance: %v", err)
	}

	if n := p.retire("zypp"); n != 1 {
		t.Fatalf("retired %d", n)
	}
	fi := l.started("zypp")[0]
	if isClosed(fi.closed, 50*time.Millisecond) {
		t.Fatal("privileged instance stopped while a call runs")
	}
	close(fi.commit)
	if !isClosed(fi.closed, time.Second) {
		t.Fatal("privileged instance not stopped after the call ended")
	}
}
