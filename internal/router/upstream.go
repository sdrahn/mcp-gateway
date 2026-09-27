package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

// protocolVersion is the MCP version the gateway speaks to backends.
const protocolVersion = "2025-06-18"

// supportedVersions are the versions accepted from clients.
var supportedVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
	"2025-11-25": true,
}

const initTimeout = 30 * time.Second

var errBackendGone = errors.New("backend instance exited")

// initResult is a backend's initialize result.
type initResult struct {
	ProtocolVersion string                     `json:"protocolVersion"`
	Capabilities    map[string]json.RawMessage `json:"capabilities"`
	ServerInfo      json.RawMessage            `json:"serverInfo"`
	Instructions    string                     `json:"instructions,omitempty"`
}

func (r initResult) has(capability string) bool {
	_, ok := r.Capabilities[capability]
	return ok
}

type progressRoute struct {
	s     *Session
	token json.RawMessage
}

// upstream is the gateway's own MCP session with one backend instance. It
// can be shared by several client sessions of the same principal: request
// ids are the gateway's, notifications are fanned out, and requests the
// backend sends to "its client" go to a session with a request in flight.
type upstream struct {
	backend *config.Backend
	id      string
	// internal: the instance runs for the gateway's own principal (shared
	// discovery), not for a user.
	internal bool
	// onListChanged, if set, is told about the backend's */list_changed
	// notifications (the router invalidates cached lists).
	onListChanged func(*upstream, *jsonrpc.Message)
	unit          string // the instance's name, e.g. its systemd unit
	conn          *jsonrpc.Conn
	log           *slog.Logger
	init          initResult

	nextID    atomic.Int64
	closed    chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	pending  map[string]chan *jsonrpc.Message
	sessions map[*Session]int // attached sessions → requests in flight
	progress map[string]progressRoute
}

// newUpstream performs the MCP handshake with a freshly started instance.
func newUpstream(ctx context.Context, b *config.Backend, id string, inst supervisor.Instance, log *slog.Logger, hooks upstreamHooks) (*upstream, error) {
	u := &upstream{
		backend:       b,
		id:            id,
		internal:      hooks.internal,
		onListChanged: hooks.onListChanged,
		unit:          inst.Name(),
		conn:          jsonrpc.NewConn(inst),
		log:           log.With("server", b.Name, "instance", inst.Name()),
		closed:        make(chan struct{}),
		pending:       map[string]chan *jsonrpc.Message{},
		sessions:      map[*Session]int{},
		progress:      map[string]progressRoute{},
	}
	go u.readLoop()

	ctx, cancel := context.WithTimeout(ctx, initTimeout)
	defer cancel()
	resp, err := u.request(ctx, nil, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		// The gateway relays these to its clients, subject to policy.
		"capabilities": map[string]any{
			"elicitation": map[string]any{},
			"sampling":    map[string]any{},
			"roots":       map[string]any{"listChanged": true},
		},
		"clientInfo": map[string]any{"name": "mcp-gateway", "version": version.Version},
	})
	if err == nil && resp.Error != nil {
		err = resp.Error
	}
	if err == nil {
		err = json.Unmarshal(resp.Result, &u.init)
	}
	if err != nil {
		u.close()
		return nil, fmt.Errorf("initializing %s: %w", b.Name, err)
	}
	if err := u.notify("notifications/initialized", nil); err != nil {
		u.close()
		return nil, err
	}
	return u, nil
}

func (u *upstream) close() {
	u.closeOnce.Do(func() {
		close(u.closed)
		_ = u.conn.Close()
	})
}

func (u *upstream) isClosed() bool {
	select {
	case <-u.closed:
		return true
	default:
		return false
	}
}

func (u *upstream) attach(s *Session) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.sessions[s]; !ok {
		u.sessions[s] = 0
	}
}

func (u *upstream) detach(s *Session) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.sessions, s)
	for k, r := range u.progress {
		if r.s == s {
			delete(u.progress, k)
		}
	}
}

func (u *upstream) notify(method string, params any) error {
	m := &jsonrpc.Message{JSONRPC: jsonrpc.Version, Method: method}
	if params != nil {
		p, err := json.Marshal(params)
		if err != nil {
			return err
		}
		m.Params = p
	}
	return u.conn.Write(m)
}

// request sends a request on behalf of session s (nil for the gateway
// itself) and waits for the response. On ctx cancellation the backend is
// told with notifications/cancelled.
func (u *upstream) request(ctx context.Context, s *Session, method string, params any) (*jsonrpc.Message, error) {
	id := json.RawMessage(strconv.FormatInt(u.nextID.Add(1), 10))
	req, err := jsonrpc.NewRequest(id, method, params)
	if err != nil {
		return nil, err
	}
	ch := make(chan *jsonrpc.Message, 1)
	u.mu.Lock()
	u.pending[string(id)] = ch
	if _, ok := u.sessions[s]; ok {
		u.sessions[s]++
	}
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		delete(u.pending, string(id))
		if n, ok := u.sessions[s]; ok && n > 0 {
			u.sessions[s] = n - 1
		}
		u.mu.Unlock()
	}()

	if err := u.conn.Write(req); err != nil {
		return nil, errBackendGone
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		_ = u.notify("notifications/cancelled", map[string]any{"requestId": id, "reason": ctx.Err().Error()})
		return nil, ctx.Err()
	case <-u.closed:
		return nil, errBackendGone
	}
}

// registerProgress maps a client's progress token to a gateway token that
// is unique on this upstream.
func (u *upstream) registerProgress(s *Session, token json.RawMessage) json.RawMessage {
	gw := json.RawMessage(strconv.Quote("gw-" + strconv.FormatInt(u.nextID.Add(1), 10)))
	u.mu.Lock()
	u.progress[string(gw)] = progressRoute{s: s, token: token}
	u.mu.Unlock()
	return gw
}

func (u *upstream) unregisterProgress(gw json.RawMessage) {
	u.mu.Lock()
	delete(u.progress, string(gw))
	u.mu.Unlock()
}

// upstreamHooks configure a new upstream.
type upstreamHooks struct {
	internal      bool
	onListChanged func(*upstream, *jsonrpc.Message)
}

// isAttached reports whether s uses u.
func (u *upstream) isAttached(s *Session) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	_, ok := u.sessions[s]
	return ok
}

func (u *upstream) attached() []*Session {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]*Session, 0, len(u.sessions))
	for s := range u.sessions {
		out = append(out, s)
	}
	return out
}

// activeSession returns the attached session with the most requests in
// flight, or nil if none has any: a backend may only ask a client
// something while serving it.
func (u *upstream) activeSession() *Session {
	u.mu.Lock()
	defer u.mu.Unlock()
	var best *Session
	max := 0
	for s, n := range u.sessions {
		if n > max {
			best, max = s, n
		}
	}
	return best
}

func (u *upstream) readLoop() {
	defer u.close()
	for {
		m, err := u.conn.Read()
		if err != nil {
			var rpcErr *jsonrpc.Error
			if errors.As(err, &rpcErr) {
				u.log.Warn("invalid message from backend", "err", err)
				continue
			}
			u.log.Info("backend connection closed", "err", err)
			return
		}
		switch {
		case m.IsResponse():
			u.mu.Lock()
			ch := u.pending[m.Key()]
			u.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		case m.IsNotification():
			u.notification(m)
		case m.IsRequest():
			go u.backendRequest(m)
		}
	}
}

func (u *upstream) notification(m *jsonrpc.Message) {
	switch m.Method {
	case "notifications/progress":
		var p map[string]json.RawMessage
		if json.Unmarshal(m.Params, &p) != nil {
			return
		}
		u.mu.Lock()
		r, ok := u.progress[string(p["progressToken"])]
		u.mu.Unlock()
		if !ok {
			return
		}
		p["progressToken"] = r.token
		params, err := json.Marshal(p)
		if err != nil {
			return
		}
		_ = r.s.client.Write(&jsonrpc.Message{JSONRPC: jsonrpc.Version, Method: m.Method, Params: params})
	case "notifications/tools/list_changed",
		"notifications/resources/list_changed",
		"notifications/prompts/list_changed":
		if u.onListChanged != nil {
			u.onListChanged(u, m)
		}
		for _, s := range u.attached() {
			s.upstreamNotification(u, m)
		}
	case "notifications/message", "notifications/resources/updated":
		for _, s := range u.attached() {
			s.upstreamNotification(u, m)
		}
	default:
		u.log.Debug("dropped backend notification", "method", m.Method)
	}
}

func (u *upstream) backendRequest(m *jsonrpc.Message) {
	if m.Method == "ping" {
		if r, err := jsonrpc.NewResult(m.ID, map[string]any{}); err == nil {
			_ = u.conn.Write(r)
		}
		return
	}
	s := u.activeSession()
	if s == nil {
		_ = u.conn.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeForbidden, "no client request in progress"))
		return
	}
	_ = u.conn.Write(s.relayBackendRequest(u, m))
}
