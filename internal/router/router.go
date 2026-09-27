package router

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/authn"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// helloTimeout bounds how long a new connection may take to send its
// first message.
const helloTimeout = 10 * time.Second

// Router accepts client connections and runs a Session per connection.
type Router struct {
	Backends map[string]*config.Backend
	Launcher supervisor.Launcher
	PDP      pep.PDP
	Broker   *broker.Broker
	Audit    *audit.Logger
	Log      *slog.Logger
	// IdleTimeout keeps an instance running this long after its last
	// session ended.
	IdleTimeout time.Duration

	once    sync.Once
	pool    *pool
	limiter *pep.Limiter
}

func (r *Router) init() {
	r.once.Do(func() {
		if r.Log == nil {
			r.Log = slog.New(slog.DiscardHandler)
		}
		r.pool = newPool(r.Launcher, r.IdleTimeout, r.Log)
		r.limiter = pep.NewLimiter()
	})
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

	var ep endpoint
	hello, err := transport.ParseHello(first)
	switch {
	case err == nil:
		if hello.Server == "all" {
			ep = aggregatedEndpoint(r.Backends)
		} else if b, ok := r.Backends[hello.Server]; ok {
			ep = singleEndpoint(b)
		} else {
			reject(client, first, fmt.Sprintf("unknown server %q", hello.Server))
			return
		}
		first = nil // consumed
	case errors.Is(err, transport.ErrNoHello):
		ep = aggregatedEndpoint(r.Backends)
	default:
		reject(client, first, err.Error())
		return
	}

	log.Info("session started", "aggregated", ep.aggregated, "servers", ep.order, "selinux", p.SELinux)
	err = newSession(r, ep, client, p).Run(ctx, first)
	log.Info("session ended", "err", err)
}

// reject answers the first message with an error if it was a request, and
// closes the connection.
func reject(c jsonrpc.MessageConn, first *jsonrpc.Message, msg string) {
	defer func() { _ = c.Close() }()
	if first.IsRequest() {
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
