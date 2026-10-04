package router

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/authn"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/signin"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// helloTimeout bounds how long a new connection may take to send its
// first message.
const helloTimeout = 10 * time.Second

// Router accepts client connections and runs a Session per connection.
type Router struct {
	// Backends are the server definitions at start; SetBackends replaces
	// them (CurrentBackends returns those in force).
	Backends map[string]*config.Backend
	Launcher supervisor.Launcher
	PDP      pep.PDP
	Broker   *broker.Broker
	Audit    *audit.Logger
	Log      *slog.Logger
	// IdleTimeout keeps an instance running this long after its last
	// session ended.
	IdleTimeout time.Duration
	// MaxSessionsPerPrincipal, MaxInstancesPerPrincipal and MaxInstances are the
	// limits of decision D14 (0: the default; for MaxInstances: none).
	MaxSessionsPerPrincipal, MaxInstancesPerPrincipal, MaxInstances int
	// ProgressInterval is how often a call waiting for approval reports
	// progress to a client that asked for it (default 15 s).
	ProgressInterval time.Duration
	// Seen, if set, is told the name of each local user who connects.
	Seen func(name string)
	// SignIns, if set, signs principals in to servers with sign_in.
	SignIns SignIns

	once      sync.Once
	registry  atomic.Pointer[map[string]*config.Backend] // the definitions in force (SetBackends)
	reloadMu  sync.Mutex
	live      atomic.Pointer[Settings] // the settings in force (SetSettings)
	pool      *pool
	limiter   *pep.Limiter
	discovery discoveryCache

	mu       sync.Mutex
	sessions map[*Session]struct{}
}

// SignIns signs principals in to servers with sign_in and gives their
// instances the tokens (signin.Manager).
type SignIns interface {
	Signed(p principal.Principal, server string) bool
	Run(ctx context.Context, el broker.Elicitor, b *config.Backend, p principal.Principal) error
	Prepare(ctx context.Context, b *config.Backend, p principal.Principal) (*config.Backend, func(), error)
	// Rejected records that the server refused p's access token.
	Rejected(server string, p principal.Principal)
	// Token gives a running instance a new access token after its
	// server refused the token refused (mcp-gateway/token).
	Token(ctx context.Context, b *config.Backend, p principal.Principal, refused string) (string, time.Time, error)
	// DefinitionChanged is told that a server's definition old was
	// replaced by next (nil: removed); tokens that no longer fit go.
	DefinitionChanged(old, next *config.Backend)
}

// SignInChanged tells the principal k's sessions that what server offers
// them changed (they signed in or out); on sign-out it also stops k's
// instances of server, which hold the token.
func (r *Router) SignInChanged(k signin.Key, server string, signedIn bool) {
	r.init()
	if !signedIn {
		if n := r.pool.stopFor(server, func(p principal.Principal) bool { return k.Same(signin.KeyOf(p)) }); n > 0 {
			r.Log.Info("instances stopped on sign-out", "server", server, "sub", k.Sub, "instances", n)
		}
	}
	r.mu.Lock()
	var sessions []*Session
	for s := range r.sessions {
		if k.Same(signin.KeyOf(s.snapshotPrincipal())) {
			sessions = append(sessions, s)
		}
	}
	r.mu.Unlock()
	for _, s := range sessions {
		s.listChanged()
	}
}

func (r *Router) unregister(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, s)
}

// PolicyChanged notifies every session that the tools, prompts and
// resources it may see may have changed, so clients list them again.
// (Grants do not change visibility: discovery shows items that need
// approval.)
func (r *Router) PolicyChanged() {
	r.mu.Lock()
	sessions := make([]*Session, 0, len(r.sessions))
	for s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	r.Log.Info("policy changed; notifying sessions", "sessions", len(sessions))
	for _, s := range sessions {
		s.listChanged()
	}
}

// policyRechecks are the delays after a policy file changed (changed in
// WatchPolicy) at which the fingerprint is checked: OPA reloads changed
// files itself, a moment after they were written.
var policyRechecks = []time.Duration{300 * time.Millisecond, time.Second, 3 * time.Second}

// WatchPolicy calls fingerprint every interval(), and shortly after each
// value from changed (a policy file was written; nil: none), and
// PolicyChanged when the result changes. Errors are logged and skipped
// (decisions fail closed meanwhile anyway). It returns when ctx ends.
func (r *Router) WatchPolicy(ctx context.Context, interval func() time.Duration, fingerprint func(context.Context) (string, error), onChange func(), changed <-chan struct{}) {
	r.init()
	var last string
	check := func() bool {
		fp, err := fingerprint(ctx)
		switch {
		case err != nil:
			r.Log.Warn("policy fingerprint failed", "err", err)
		case last != "" && fp != last:
			r.PolicyChanged()
			if onChange != nil {
				onChange()
			}
			last = fp
			return true
		default:
			last = fp
		}
		return false
	}
	t := time.NewTimer(interval())
	defer t.Stop()
	soon := time.NewTimer(time.Hour)
	soon.Stop()
	defer soon.Stop()
	var pending []time.Duration // rechecks still due after a change
	check()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
			t.Reset(interval())
		case <-changed:
			pending = slices.Clone(policyRechecks)
			soon.Reset(pending[0])
		case <-soon.C:
			waited := pending[0]
			pending = pending[1:]
			if check() || len(pending) == 0 {
				pending = nil
				continue
			}
			soon.Reset(pending[0] - waited)
		}
	}
}

// privileged reports whether server is a privileged backend.
func (r *Router) privileged(server string) bool {
	b := r.backends()[server]
	return b != nil && b.Privileged
}

// Instances describes the running backend instances.
func (r *Router) Instances() []InstanceInfo {
	r.init()
	return r.pool.list()
}

// StopInstance stops a running backend instance; sessions using it get a
// new one on their next call. It reports whether the instance existed.
func (r *Router) StopInstance(id string) bool {
	r.init()
	return r.pool.stop(id)
}

// Stats returns the number of client sessions and of running backend
// instances. It takes only the router's and the pool's locks, so the
// watchdog can use it to see that they are not stuck.
func (r *Router) Stats() (sessions, instances int) {
	r.init()
	r.mu.Lock()
	sessions = len(r.sessions)
	r.mu.Unlock()
	return sessions, len(r.pool.list())
}

func (r *Router) init() {
	r.once.Do(func() {
		if r.Log == nil {
			r.Log = slog.New(slog.DiscardHandler)
		}
		initial := r.Backends
		if initial == nil {
			initial = map[string]*config.Backend{}
		}
		r.registry.Store(&initial)
		r.pool = newPool(r.Launcher, r.IdleTimeout, r.Log)
		r.applySettings(Settings{IdleTimeout: r.IdleTimeout, ProgressInterval: r.ProgressInterval,
			MaxSessionsPerPrincipal: r.MaxSessionsPerPrincipal, MaxInstancesPerPrincipal: r.MaxInstancesPerPrincipal,
			MaxInstances: r.MaxInstances})
		r.pool.onListChanged = r.listChanged
		r.pool.current = func(server string) *config.Backend { return (*r.registry.Load())[server] }
		if r.SignIns != nil {
			r.pool.prepare = r.SignIns.Prepare
			r.pool.rejected = r.SignIns.Rejected
			r.pool.token = r.SignIns.Token
		}
		r.limiter = pep.NewLimiter()
	})
}

// Settings are the router's options a configuration reload changes; at
// start they are the fields of Router of the same names.
type Settings struct {
	IdleTimeout, ProgressInterval                                   time.Duration
	MaxSessionsPerPrincipal, MaxInstancesPerPrincipal, MaxInstances int
}

// SetSettings changes the settings (a reload of the configuration):
// limits apply to the next session or instance, the idle timeout to
// instances that become idle from now on, the progress interval to calls
// that start waiting for an approval.
func (r *Router) SetSettings(s Settings) {
	r.init()
	r.applySettings(s)
}

func (r *Router) applySettings(s Settings) {
	r.live.Store(&s)
	perPrincipal := s.MaxInstancesPerPrincipal
	if perPrincipal <= 0 {
		perPrincipal = defaultInstancesPerPrincipal
	}
	r.pool.configure(s.IdleTimeout, perPrincipal, s.MaxInstances)
}

func (r *Router) settings() Settings {
	r.init()
	return *r.live.Load()
}

// Serve accepts connections from l until ctx ends, then stops all backend
// instances.
func (r *Router) Serve(ctx context.Context, l *transport.UnixListener) error {
	r.init()
	defer r.pool.closeAll()
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			r.Log.Warn("accept failed", "err", err)
			continue
		}
		go r.handle(ctx, c)
	}
}

func (r *Router) handle(ctx context.Context, c *transport.UnixConn) {
	log := r.Log.With("peer_uid", c.Peer.UID, "peer_pid", c.Peer.PID)
	p, err := authn.Local(c.Peer)
	if err != nil {
		log.Warn("authentication failed", "err", err)
		_ = c.Close()
		return
	}
	if r.Seen != nil {
		r.Seen(p.Sub)
	}
	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	client := jsonrpc.NewConn(c)
	first, err := client.Read()
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		log.Info("no first message", "err", err)
		_ = client.Close()
		return
	}
	r.ServeClient(ctx, client, p, first)
}

// ServeClient runs the session of an authenticated client whose first
// message (a hello, or an MCP message for the aggregated endpoint) has
// been read.
func (r *Router) ServeClient(ctx context.Context, client jsonrpc.MessageConn, p principal.Principal, first *jsonrpc.Message) {
	r.init()
	log := r.Log.With("session", p.SessionID, "sub", p.Sub)

	// Under reloadMu, so that SetBackends either sees the session
	// registered or ran before its endpoint was taken.
	r.reloadMu.Lock()
	var ep endpoint
	hello, err := transport.ParseHello(first)
	switch {
	case err == nil:
		if hello.Server == "all" {
			ep = aggregatedEndpoint(r.backends())
		} else if b, ok := r.backends()[hello.Server]; ok {
			ep = singleEndpoint(b)
		} else {
			r.reloadMu.Unlock()
			reject(client, first, fmt.Sprintf("unknown server %q", hello.Server))
			return
		}
		first = nil // consumed
	case errors.Is(err, transport.ErrNoHello):
		ep = aggregatedEndpoint(r.backends())
	default:
		r.reloadMu.Unlock()
		reject(client, first, err.Error())
		return
	}

	s := newSession(r, ep, client, p)
	err = r.admit(s)
	r.reloadMu.Unlock()
	if err != nil {
		refuse(client, first, err.Error())
		return
	}
	log.Info("session started", "aggregated", ep.aggregated, "servers", ep.order, "selinux", p.SELinux)
	err = s.Run(ctx, first)
	log.Info("session ended", "err", err)
}

// refuse is reject for a session whose first MCP message may not have
// been read yet (after a hello): it waits briefly for it, so that the
// client's initialize gets the error instead of a closed connection.
func refuse(c jsonrpc.MessageConn, first *jsonrpc.Message, msg string) {
	if first == nil {
		got := make(chan *jsonrpc.Message, 1)
		go func() {
			m, _ := c.Read()
			got <- m
		}()
		select {
		case first = <-got:
		case <-time.After(refuseWait):
		}
	}
	reject(c, first, msg)
}

// refuseWait bounds how long refuse waits for the client's first message.
var refuseWait = 5 * time.Second

// reject answers the first message with an error if it was a request, and
// closes the connection.
func reject(c jsonrpc.MessageConn, first *jsonrpc.Message, msg string) {
	defer func() { _ = c.Close() }()
	if first != nil && first.IsRequest() {
		_ = c.Write(jsonrpc.NewError(first.ID, jsonrpc.CodeInvalidRequest, "mcp-gateway: "+msg))
		return
	}
	n, err := jsonrpc.NewNotification("notifications/message", map[string]any{
		"level": "error", "logger": "mcp-gateway", "data": msg,
	})
	if err == nil {
		_ = c.Write(n)
	}
}
