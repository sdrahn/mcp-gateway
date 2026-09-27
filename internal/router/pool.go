package router

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/authn"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// pool owns backend instances: one per (principal, backend) by default,
// one per (session, backend) for backends with isolation: session. An
// instance stays up for idle after its last session detached.
type pool struct {
	launcher supervisor.Launcher
	idle     time.Duration
	log      *slog.Logger

	mu      sync.Mutex
	entries map[string]*poolEntry
}

type poolEntry struct {
	key       string
	isolation config.Isolation
	ready     chan struct{}
	up        *upstream
	err       error
	refs      int
	timer     *time.Timer
}

func newPool(l supervisor.Launcher, idle time.Duration, log *slog.Logger) *pool {
	return &pool{launcher: l, idle: idle, log: log, entries: map[string]*poolEntry{}}
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
			e = &poolEntry{key: key, isolation: b.Isolation, ready: make(chan struct{}), refs: 1}
			p.entries[key] = e
			p.mu.Unlock()
			e.up, e.err = p.start(ctx, b, pr)
			close(e.ready)
			if e.err != nil {
				p.remove(e)
				return nil, nil, e.err
			}
			go func() {
				<-e.up.closed
				p.remove(e)
			}()
			return e.up, p.releaser(e), nil
		}
		// Existing entry: drop it if its instance is gone, else join it.
		select {
		case <-e.ready:
			if e.err != nil || e.up.isClosed() {
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

func (p *pool) remove(e *poolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entries[e.key] == e {
		delete(p.entries, e.key)
	}
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

// closeAll stops every instance.
func (p *pool) closeAll() {
	p.mu.Lock()
	entries := make([]*poolEntry, 0, len(p.entries))
	for _, e := range p.entries {
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
