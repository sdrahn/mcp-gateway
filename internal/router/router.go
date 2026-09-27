package router

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/authn"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// helloTimeout bounds how long a new connection may take to select an
// endpoint.
const helloTimeout = 10 * time.Second

// Router accepts client connections and runs a Session per connection.
type Router struct {
	Backends map[string]*config.Backend
	Launcher supervisor.Launcher
	PDP      pep.PDP
	Broker   *broker.Broker
	Audit    *audit.Logger
	Log      *slog.Logger
}

// Serve accepts connections from l until ctx ends.
func (r *Router) Serve(ctx context.Context, l *transport.UnixListener) error {
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
	client := jsonrpc.NewConn(c)
	defer func() { _ = client.Close() }()

	p, err := authn.Local(c.Peer)
	if err != nil {
		log.Warn("authentication failed", "err", err)
		return
	}
	log = log.With("session", p.SessionID, "sub", p.Sub)

	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	first, err := client.Read()
	if err != nil {
		log.Info("no hello", "err", err)
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	hello, err := transport.ParseHello(first)
	if err != nil {
		msg := err.Error()
		if errors.Is(err, transport.ErrNoHello) {
			msg = "aggregated endpoint not implemented yet; connect with mcp-connect --server <name>"
		}
		r.reject(client, first, msg)
		return
	}
	b, ok := r.Backends[hello.Server]
	if !ok {
		r.reject(client, first, fmt.Sprintf("unknown server %q", hello.Server))
		return
	}

	inst, err := r.Launcher.Start(ctx, b, p)
	if err != nil {
		log.Error("starting backend failed", "server", b.Name, "err", err)
		r.reject(client, first, "backend unavailable")
		return
	}
	log.Info("session started", "server", b.Name, "instance", inst.Name(), "selinux", p.SELinux)
	sess := NewSession(SessionConfig{
		Principal: p,
		Server:    b.Name,
		Instance:  inst.Name(),
		Client:    client,
		Backend:   jsonrpc.NewConn(inst),
		PDP:       r.PDP,
		Broker:    r.Broker,
		Audit:     r.Audit,
		Log:       r.Log,
	})
	err = sess.Run(ctx)
	r.Broker.EndSession(p.SessionID)
	log.Info("session ended", "err", err)
}

// reject answers the first message with an error if it was a request.
// Otherwise the client learns about the problem when the connection
// closes.
func (r *Router) reject(c *jsonrpc.Conn, first *jsonrpc.Message, msg string) {
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
