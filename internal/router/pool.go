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
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/metrics"
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

// On shutdown the gateway waits up to drainTimeout for calls to
// privileged backends (mcp-gateway.service has TimeoutStopSec=30min),
// checking every drainPoll.
const (
	drainTimeout = 28 * time.Minute
	drainPoll    = 100 * time.Millisecond
)

// pool owns backend instances: one per (principal, backend) by default,
// one per (session, backend) for backends with isolation: session. An
// instance stays up for idle after its last session detached.
type pool struct {
	launcher supervisor.Launcher
	idle     time.Duration
	log      *slog.Logger
	now      func() time.Time
	// onListChanged is handed to every upstream (see upstreamHooks).
	onListChanged func(*upstream, *jsonrpc.Message)

	backoffBase, backoffMax, stableAfter time.Duration
	// drainTimeout bounds how long closeAll waits for privileged calls.
	drainTimeout time.Duration

	// maxPerPrincipal and maxTotal limit running instances (decision
	// D14); 0 means no limit. Discovery instances do not count.
	maxPerPrincipal, maxTotal int

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
	// released is when the last reference went (the instance waits out
	// the idle timeout since).
	released time.Time
	// stopping is set when the pool stops the instance, to tell that
	// apart from the instance exiting on its own.
	stopping bool
	// ended is set once the end of the instance has been accounted for.
	ended bool
	// idleWait is set when a privileged instance was due to stop but a
	// request was still in flight; it stops once that is answered.
	idleWait bool
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
		backoffBase: backoffBase, backoffMax: backoffMax, stableAfter: stableAfter, drainTimeout: drainTimeout,
		entries: map[string]*poolEntry{}, failing: map[string]*failures{}}
}

// makeRoom checks the instance limits for a new instance of pr. At a
// limit it takes the longest-idle instance that nobody uses (one waiting
// out its idle timeout) out of the pool and returns it, for the caller to
// close after unlocking; if there is none, it returns a *LimitError.
// p.mu must be held.
func (p *pool) makeRoom(pr principal.Principal) ([]*poolEntry, error) {
	if isDiscovery(pr) {
		return nil, nil
	}
	var victims []*poolEntry
	check := func(limit string, max int, counts func(*poolEntry) bool) error {
		if max <= 0 {
			return nil
		}
		n := 0
		var victim *poolEntry
		for _, e := range p.entries {
			if !counts(e) {
				continue
			}
			n++
			if p.idleEntry(e) && (victim == nil || e.released.Before(victim.released)) {
				victim = e
			}
		}
		if n < max {
			return nil
		}
		if victim == nil {
			return &LimitError{Limit: limit, Max: max}
		}
		victim.timer.Stop()
		victim.timer = nil
		victim.stopping = true
		delete(p.entries, victim.key)
		victims = append(victims, victim)
		return nil
	}
	key := principalKey(pr)
	if err := check("instances_per_principal", p.maxPerPrincipal, func(e *poolEntry) bool {
		return principalKey(e.principal) == key
	}); err != nil {
		return victims, err
	}
	err := check("instances", p.maxTotal, func(e *poolEntry) bool {
		return !isDiscovery(e.principal)
	})
	return victims, err
}

// isDiscovery reports whether p is the gateway's own discovery principal.
func isDiscovery(p principal.Principal) bool {
	return p.Transport == discoveryPrincipal.Transport && p.Sub == discoveryPrincipal.Sub
}

// idleEntry reports whether e is a running instance nobody uses, waiting
// out its idle timeout; p.mu must be held.
func (p *pool) idleEntry(e *poolEntry) bool {
	select {
	case <-e.ready:
	default:
		return false // starting
	}
	return e.err == nil && e.refs == 0 && e.timer != nil && !e.stopping && !mustKeep(e)
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
			victims, err := p.makeRoom(pr)
			if err == nil {
				e = &poolEntry{key: key, principal: pr, isolation: b.Isolation, ready: make(chan struct{}), refs: 1}
				p.entries[key] = e
			}
			p.mu.Unlock()
			for _, v := range victims {
				p.log.Info("instance stopped for a new one at the instance limit", "server", v.up.backend.Name, "instance", v.up.id)
				v.up.close()
			}
			if err != nil {
				return nil, nil, err
			}
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
			e.up.setOnIdle(func() { p.idled(e) })
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
		metrics.InstanceFailures.Inc(b.Name, "start")
		return nil, err
	}
	up, err := newUpstream(ctx, b, id, inst, p.log, upstreamHooks{
		internal:      pr.Transport == principal.TransportInternal,
		onListChanged: p.onListChanged,
	})
	if err != nil {
		metrics.InstanceFailures.Inc(b.Name, "start")
		return nil, err
	}
	metrics.InstanceStarts.Inc(b.Name)
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
	metrics.InstanceFailures.Inc(e.up.backend.Name, "exit")
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
	e.released = p.now()
	p.scheduleStop(e)
}

// idled is called when e's last request in flight was answered: a
// privileged instance that was due to stop meanwhile stops now (after
// the idle timeout).
func (p *pool) idled(e *poolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !e.idleWait || e.refs > 0 || p.entries[e.key] != e {
		return
	}
	e.idleWait = false
	p.scheduleStop(e)
}

// mustKeep reports whether e is a privileged instance with a request in
// flight, which the pool does not stop.
func mustKeep(e *poolEntry) bool {
	return e.up != nil && e.up.backend.Privileged && e.up.busy()
}

// scheduleStop stops e, which no session uses, after the idle timeout
// (at once for isolation: session); p.mu must be held.
func (p *pool) scheduleStop(e *poolEntry) {
	stop := func() {
		p.mu.Lock()
		if e.refs > 0 || p.entries[e.key] != e {
			p.mu.Unlock()
			return
		}
		if mustKeep(e) {
			e.idleWait = true
			p.mu.Unlock()
			p.log.Info("privileged instance kept while a call runs", "server", e.up.backend.Name, "instance", e.up.id)
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
	// Privileged instances (section 5.7.1) are not stopped while Busy
	// (requests in flight).
	Privileged bool `json:"privileged,omitempty"`
	Busy       bool `json:"busy,omitempty"`
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
			Transport: e.principal.Transport, Isolation: e.isolation, Started: e.started, Sessions: e.refs,
			Privileged: e.up.backend.Privileged, Busy: e.up.busy()}
		if e.isolation == config.IsolationSession {
			info.SessionID = e.principal.SessionID
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out
}

// stop stops the instance with the given id; sessions using it get a new
// instance on their next call. A privileged instance with a request in
// flight is not stopped (reported as not found; InstanceInfo.Busy tells).
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
	if found == nil || mustKeep(found) {
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

// closeAll stops every instance. Privileged instances first refuse new
// requests and get until drainTimeout to answer those in flight.
func (p *pool) closeAll() {
	p.mu.Lock()
	entries := make([]*poolEntry, 0, len(p.entries))
	for _, e := range p.entries {
		e.stopping = true
		entries = append(entries, e)
	}
	p.entries = map[string]*poolEntry{}
	p.mu.Unlock()
	var privileged []*poolEntry
	for _, e := range entries {
		<-e.ready
		switch {
		case e.up == nil:
		case e.up.backend.Privileged:
			e.up.draining.Store(true)
			privileged = append(privileged, e)
		default:
			e.up.close()
		}
	}
	deadline := p.now().Add(p.drainTimeout)
	for _, e := range privileged {
		if e.up.busy() {
			p.log.Info("waiting for privileged calls", "server", e.up.backend.Name, "instance", e.up.id)
		}
		for e.up.busy() && !e.up.isClosed() && p.now().Before(deadline) {
			time.Sleep(drainPoll)
		}
		if e.up.busy() && !e.up.isClosed() {
			p.log.Warn("stopping privileged instance with a call still running", "server", e.up.backend.Name, "instance", e.up.id)
		}
		e.up.close()
	}
}
