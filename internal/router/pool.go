package router

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/authn"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// Restart backoff: after an instance failed to start or exited on its
// own, the next start of the same instance waits backoffBase, doubling
// with each further failure up to backoffMax. An instance that ran for
// stableAfter before exiting starts the count afresh.
const (
	backoffBase = time.Second
	backoffMax  = 2 * time.Minute
	stableAfter = time.Minute
)

// pool owns backend instances: one per (principal, backend) by default,
// one per (session, backend) for backends with isolation: session. An
// instance stays up for idle after its last session detached.
type pool struct {
	launcher supervisor.Launcher
	idle     time.Duration
	log      *slog.Logger
	now      func() time.Time

	backoffBase, backoffMax, stableAfter time.Duration

	mu      sync.Mutex
	entries map[string]*poolEntry
	failing map[string]*failures
}

type poolEntry struct {
	key       string
	principal principal.Principal
	isolation config.Isolation
	ready     chan struct{}
	up        *upstream
	err       error
	refs      int
	timer     *time.Timer
	started   time.Time
	// stopping is set when the pool stops the instance, to tell that
	// apart from the instance exiting on its own.
	stopping bool
	// ended is set once the end of the instance has been accounted for.
	ended bool
}

// failures tracks consecutive failures of one instance key.
type failures struct {
	n     int
	until time.Time
}

// BackoffError is returned while an instance that failed waits before
// it is started again.
type BackoffError struct {
	Server  string
	RetryIn time.Duration
}

func (e *BackoffError) Error() string {
	return fmt.Sprintf("%s failed recently; next start in %s", e.Server, e.RetryIn.Round(time.Second))
}

func newPool(l supervisor.Launcher, idle time.Duration, log *slog.Logger) *pool {
	return &pool{launcher: l, idle: idle, log: log, now: time.Now,
		backoffBase: backoffBase, backoffMax: backoffMax, stableAfter: stableAfter,
		entries: map[string]*poolEntry{}, failing: map[string]*failures{}}
}

func instanceKey(b *config.Backend, p principal.Principal) string {
	if b.Isolation == config.IsolationSession {
		return "session:" + p.SessionID + ":" + b.Name
	}
	return "principal:" + string(p.Transport) + ":" + p.Sub + ":" + b.Name
}

// acquire returns a running instance of b for p and a function that must
// be called when the caller no longer needs it.
func (p *pool) acquire(ctx context.Context, b *config.Backend, pr principal.Principal) (*upstream, func(), error) {
	key := instanceKey(b, pr)
	for {
		p.mu.Lock()
		e := p.entries[key]
		if e == nil {
			if f := p.failing[key]; f != nil {
				if wait := f.until.Sub(p.now()); wait > 0 {
					p.mu.Unlock()
					return nil, nil, &BackoffError{Server: b.Name, RetryIn: wait}
				}
			}
			e = &poolEntry{key: key, principal: pr, isolation: b.Isolation, ready: make(chan struct{}), refs: 1}
			p.entries[key] = e
			p.mu.Unlock()
			e.up, e.err = p.start(ctx, b, pr)
			e.started = p.now()
			close(e.ready)
			if e.err != nil {
				p.mu.Lock()
				if p.entries[key] == e {
					delete(p.entries, key)
				}
				// A start cancelled by the client is not the backend's fault.
				if ctx.Err() == nil {
					p.failed(key, b.Name, 0)
				}
				p.mu.Unlock()
				return nil, nil, e.err
			}
			go func() {
				<-e.up.closed
				p.exited(e)
			}()
			return e.up, p.releaser(e), nil
		}
		// Existing entry: drop it if its instance is gone, else join it.
		select {
		case <-e.ready:
			if e.err != nil || e.up.isClosed() {
				if e.err == nil {
					p.ended(e) // before the watcher gets to it
				}
				if p.entries[key] == e {
					delete(p.entries, key)
				}
				p.mu.Unlock()
				continue
			}
		default:
		}
		e.refs++
		if e.timer != nil {
			e.timer.Stop()
			e.timer = nil
		}
		p.mu.Unlock()
		select {
		case <-e.ready:
		case <-ctx.Done():
			p.releaser(e)()
			return nil, nil, ctx.Err()
		}
		if e.err != nil {
			return nil, nil, e.err
		}
		return e.up, p.releaser(e), nil
	}
}

func (p *pool) start(ctx context.Context, b *config.Backend, pr principal.Principal) (*upstream, error) {
	id := authn.NewSessionID()
	inst, err := p.launcher.Start(ctx, b, pr, id)
	if err != nil {
		return nil, err
	}
	up, err := newUpstream(ctx, b, id, inst, p.log)
	if err != nil {
		return nil, err
	}
	p.log.Info("instance started", "server", b.Name, "instance", inst.Name(), "sub", pr.Sub)
	return up, nil
}

// exited handles the end of e's instance: expected if the pool stopped
// it, else a failure that delays the next start.
func (p *pool) exited(e *poolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entries[e.key] == e {
		delete(p.entries, e.key)
	}
	p.ended(e)
}

// ended accounts for the end of e's instance once; p.mu must be held.
func (p *pool) ended(e *poolEntry) {
	if e.ended {
		return
	}
	e.ended = true
	if e.stopping {
		delete(p.failing, e.key)
		return
	}
	uptime := p.now().Sub(e.started)
	p.log.Warn("instance exited unexpectedly", "server", e.up.backend.Name, "instance", e.up.id, "uptime", uptime.Round(time.Millisecond))
	p.failed(e.key, e.up.backend.Name, uptime)
}

// failed records a failure of key; p.mu must be held.
func (p *pool) failed(key, server string, uptime time.Duration) {
	now := p.now()
	for k, f := range p.failing {
		if now.Sub(f.until) > p.stableAfter {
			delete(p.failing, k) // long forgotten
		}
	}
	f := p.failing[key]
	if f == nil || uptime >= p.stableAfter {
		f = &failures{}
		p.failing[key] = f
	}
	f.n++
	wait := p.backoffMax
	if f.n <= 30 {
		wait = min(p.backoffBase<<(f.n-1), p.backoffMax)
	}
	f.until = now.Add(wait)
	p.log.Info("instance restart delayed", "server", server, "failures", f.n, "wait", wait)
}

func (p *pool) releaser(e *poolEntry) func() {
	var once sync.Once
	return func() { once.Do(func() { p.release(e) }) }
}

func (p *pool) release(e *poolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e.refs--
	if e.refs > 0 || p.entries[e.key] != e {
		return
	}
	stop := func() {
		p.mu.Lock()
		if e.refs > 0 || p.entries[e.key] != e {
			p.mu.Unlock()
			return
		}
		delete(p.entries, e.key)
		e.stopping = true
		p.mu.Unlock()
		p.log.Info("instance stopped", "server", e.up.backend.Name, "instance", e.up.id)
		e.up.close()
	}
	if e.isolation == config.IsolationSession || p.idle == 0 {
		go stop()
		return
	}
	e.timer = time.AfterFunc(p.idle, stop)
}

// InstanceInfo describes a running backend instance.
type InstanceInfo struct {
	ID        string              `json:"id"`
	Server    string              `json:"server"`
	Unit      string              `json:"unit"`
	Sub       string              `json:"sub"`
	Issuer    string              `json:"iss,omitempty"`
	UID       *uint32             `json:"uid,omitempty"`
	Transport principal.Transport `json:"transport"`
	// SessionID is set for instances of backends with isolation: session.
	SessionID string           `json:"session_id,omitempty"`
	Isolation config.Isolation `json:"isolation"`
	Started   time.Time        `json:"started"`
	// Sessions is the number of sessions using the instance; 0 while it
	// waits for the idle timeout.
	Sessions int `json:"sessions"`
}

// list describes the running instances, ordered by start.
func (p *pool) list() []InstanceInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []InstanceInfo
	for _, e := range p.entries {
		select {
		case <-e.ready:
		default:
			continue // starting
		}
		if e.err != nil || e.up.isClosed() {
			continue
		}
		info := InstanceInfo{ID: e.up.id, Server: e.up.backend.Name, Unit: e.up.unit,
			Sub: e.principal.Sub, Issuer: e.principal.Issuer, UID: e.principal.UID,
			Transport: e.principal.Transport, Isolation: e.isolation, Started: e.started, Sessions: e.refs}
		if e.isolation == config.IsolationSession {
			info.SessionID = e.principal.SessionID
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out
}

// stop stops the instance with the given id; sessions using it get a new
// instance on their next call.
func (p *pool) stop(id string) bool {
	p.mu.Lock()
	var found *poolEntry
	for _, e := range p.entries {
		select {
		case <-e.ready:
			if e.err == nil && e.up.id == id {
				found = e
			}
		default:
		}
	}
	if found == nil {
		p.mu.Unlock()
		return false
	}
	delete(p.entries, found.key)
	found.stopping = true
	if found.timer != nil {
		found.timer.Stop()
	}
	p.mu.Unlock()
	p.log.Info("instance stopped on request", "server", found.up.backend.Name, "instance", found.up.id)
	found.up.close()
	return true
}

// closeAll stops every instance.
func (p *pool) closeAll() {
	p.mu.Lock()
	entries := make([]*poolEntry, 0, len(p.entries))
	for _, e := range p.entries {
		e.stopping = true
		entries = append(entries, e)
	}
	p.entries = map[string]*poolEntry{}
	p.mu.Unlock()
	for _, e := range entries {
		<-e.ready
		if e.up != nil {
			e.up.close()
		}
	}
}
