package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/signin"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

// protocolVersion is the legacy MCP version the gateway initializes
// backends with (modernVersion for those without the handshake).
const protocolVersion = "2025-11-25"

// supportedVersions are the versions accepted from clients.
var supportedVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
	"2025-11-25": true,
}

const initTimeout = 30 * time.Second

var errBackendGone = errors.New("backend instance exited")

// errShuttingDown refuses new requests to a privileged backend while the
// gateway waits for running ones before it stops.
var errShuttingDown = errors.New("the gateway is shutting down")

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
	req   json.RawMessage // the client request the progress is for
	// offset is added to the backend's progress and total: the gateway
	// reported that much progress itself before (while the call waited
	// for approval), and progress must keep increasing.
	offset float64
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
	// token answers mcp-gateway/token (upstreamHooks.token); nil for
	// instances without a principal's sign-in.
	token func(ctx context.Context, refused string) (string, time.Time, error)
	unit  string // the instance's name, e.g. its systemd unit
	conn  *jsonrpc.Conn
	log   *slog.Logger
	init  initResult
	// modern: the server speaks MCP 2026-07-28 (modern.go): no
	// handshake, per-request _meta, a subscriptions/listen stream.
	modern bool

	nextID    atomic.Int64
	closed    chan struct{}
	closeOnce sync.Once

	// draining refuses new requests (see errShuttingDown).
	draining atomic.Bool

	mu       sync.Mutex
	pending  map[string]chan *jsonrpc.Message
	sessions map[*Session]int // attached sessions → requests in flight
	// calls holds, per session, the client requests its requests in
	// flight serve (by upstream request id), to tell which one a
	// backend's request or log message belongs to.
	calls    map[*Session]map[string]json.RawMessage
	progress map[string]progressRoute
	// inflight holds the requests sent and not yet answered, including
	// those whose caller gave up (cancelled, session gone): a backend may
	// finish what it started, and a privileged one must not be stopped
	// before (docs/architecture.md, section 5.7.1).
	inflight map[string]struct{}
	// onIdle, if set, is called when the last request in flight was
	// answered.
	onIdle func()
	// listenID is the id of the open subscriptions/listen request of a
	// modern server, subscribed the resources clients subscribed to
	// (with how many subscriptions each).
	listenID   json.RawMessage
	subscribed map[string]int
}

// newUpstream performs the MCP handshake with a freshly started instance.
func newUpstream(ctx context.Context, b *config.Backend, id string, inst supervisor.Instance, log *slog.Logger, hooks upstreamHooks) (*upstream, error) {
	u := &upstream{
		backend:       b,
		id:            id,
		internal:      hooks.internal,
		onListChanged: hooks.onListChanged,
		token:         hooks.token,
		unit:          inst.Name(),
		conn:          jsonrpc.NewConn(inst),
		log:           log.With("server", b.Name, "instance", inst.Name()),
		closed:        make(chan struct{}),
		pending:       map[string]chan *jsonrpc.Message{},
		sessions:      map[*Session]int{},
		calls:         map[*Session]map[string]json.RawMessage{},
		progress:      map[string]progressRoute{},
		inflight:      map[string]struct{}{},
		subscribed:    map[string]int{},
	}
	go u.readLoop()

	ctx, cancel := context.WithTimeout(ctx, initTimeout)
	defer cancel()
	// Servers that speak HTTP are reached through the connector, which
	// speaks the legacy transport (roadmap step 24 brings the modern one).
	if hooks.era != eraLegacy && b.URL == "" {
		init, modern, err := u.discover(ctx)
		if err != nil {
			u.close()
			if errors.Is(err, errProbeEnded) {
				return nil, err
			}
			return nil, fmt.Errorf("probing %s: %w", b.Name, err)
		}
		if hooks.learnEra != nil {
			hooks.learnEra(map[bool]era{true: eraModern, false: eraLegacy}[modern])
		}
		if modern {
			u.modern, u.init = true, init
			u.listen()
			return u, nil
		}
	}
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

// busy reports whether requests are in flight.
func (u *upstream) busy() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.inflight) > 0
}

// setOnIdle sets the function called when u stops being busy.
func (u *upstream) setOnIdle(f func()) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.onIdle = f
}

// answered removes a request from those in flight.
func (u *upstream) answered(key string) {
	u.mu.Lock()
	_, was := u.inflight[key]
	delete(u.inflight, key)
	idle := was && len(u.inflight) == 0
	f := u.onIdle
	u.mu.Unlock()
	if idle && f != nil {
		f()
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

// leave stops routing u's notifications to s, which moved to another
// instance; progress of s's calls still running on u keeps reaching it.
func (u *upstream) leave(s *Session) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.sessions, s)
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
	if u.draining.Load() {
		return nil, errShuttingDown
	}
	if u.modern {
		switch method {
		case "resources/subscribe", "resources/unsubscribe":
			raw, _ := json.Marshal(params)
			return u.subscribe(raw, method == "resources/subscribe"), nil
		case "logging/setLevel":
			// The level travels with each request (meta).
			return &jsonrpc.Message{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{}`)}, nil
		}
		p, err := withMeta(params, u.meta(s))
		if err != nil {
			return nil, err
		}
		params = p
	}
	id := json.RawMessage(strconv.FormatInt(u.nextID.Add(1), 10))
	req, err := jsonrpc.NewRequest(id, method, params)
	if err != nil {
		return nil, err
	}
	ch := make(chan *jsonrpc.Message, 1)
	u.mu.Lock()
	u.pending[string(id)] = ch
	u.inflight[string(id)] = struct{}{}
	if _, ok := u.sessions[s]; ok {
		u.sessions[s]++
	}
	if req := requestOf(ctx); s != nil && req != nil {
		if u.calls[s] == nil {
			u.calls[s] = map[string]json.RawMessage{}
		}
		u.calls[s][string(id)] = req
	}
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		delete(u.pending, string(id))
		if n, ok := u.sessions[s]; ok && n > 0 {
			u.sessions[s] = n - 1
		}
		if c := u.calls[s]; c != nil {
			delete(c, string(id))
			if len(c) == 0 {
				delete(u.calls, s)
			}
		}
		u.mu.Unlock()
	}()

	if err := u.conn.Write(req); err != nil {
		u.answered(string(id))
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
func (u *upstream) registerProgress(s *Session, token json.RawMessage, offset float64, req json.RawMessage) json.RawMessage {
	gw := json.RawMessage(strconv.Quote("gw-" + strconv.FormatInt(u.nextID.Add(1), 10)))
	u.mu.Lock()
	u.progress[string(gw)] = progressRoute{s: s, token: token, offset: offset, req: req}
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
	// era is what the pool knows of the definition's era: eraLegacy
	// skips the server/discover probe. learnEra is told the result of a
	// probe.
	era           era
	learnEra      func(era)
	internal      bool
	onListChanged func(*upstream, *jsonrpc.Message)
	// token, for an instance of a server with sign_in, answers its
	// connector's mcp-gateway/token requests.
	token func(ctx context.Context, refused string) (string, time.Time, error)
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
// relatedRequest returns the client request of s that what the backend
// sends now belongs to: the one s has in flight on u, nil if it has none
// or several (JSON-RPC does not say which of them a backend means).
func (u *upstream) relatedRequest(s *Session) json.RawMessage {
	u.mu.Lock()
	defer u.mu.Unlock()
	reqs := map[string]json.RawMessage{}
	for _, req := range u.calls[s] {
		reqs[string(req)] = req
	}
	if len(reqs) != 1 {
		return nil
	}
	for _, req := range reqs {
		return req
	}
	return nil
}

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
				// The start of the line usually says why: a usage message,
				// a log line the server writes to stdout instead of stderr.
				args := []any{"err", err}
				var lineErr *jsonrpc.LineError
				if errors.As(err, &lineErr) {
					args = append(args, "line", excerpt(lineErr.Line, maxLoggedLine))
				}
				u.log.Warn("invalid message from backend", args...)
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
			u.answered(m.Key())
		case m.IsNotification():
			u.notification(m)
		case m.IsRequest():
			go u.backendRequest(m)
		}
	}
}

func (u *upstream) notification(m *jsonrpc.Message) {
	if u.modern {
		m = stripSubscriptionMeta(m)
	}
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
		if r.offset > 0 {
			shiftProgress(p, "progress", r.offset)
			shiftProgress(p, "total", r.offset)
		}
		params, err := json.Marshal(p)
		if err != nil {
			return
		}
		_ = jsonrpc.WriteRelated(r.s.client, &jsonrpc.Message{JSONRPC: jsonrpc.Version, Method: m.Method, Params: params}, r.req)
	case "notifications/tools/list_changed",
		"notifications/resources/list_changed",
		"notifications/prompts/list_changed":
		if u.onListChanged != nil {
			u.onListChanged(u, m)
		}
		for _, s := range u.attached() {
			s.upstreamNotification(u, m, nil)
		}
	case "notifications/message":
		// A log message during a call belongs to it, as far as one can
		// tell (relatedRequest).
		for _, s := range u.attached() {
			s.upstreamNotification(u, m, u.relatedRequest(s))
		}
	case "notifications/resources/updated":
		for _, s := range u.attached() {
			s.upstreamNotification(u, m, nil)
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
	if m.Method == TokenMethod {
		_ = u.conn.Write(u.answerToken(m))
		return
	}
	s := u.activeSession()
	if s == nil {
		_ = u.conn.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeForbidden, "no client request in progress"))
		return
	}
	_ = u.conn.Write(s.relayBackendRequest(u, m, u.relatedRequest(s)))
}

// TokenMethod is the request an instance of a server with sign_in (its
// mcp-http-connector) sends the gateway when the server refused its access
// token, with the refused token as params.refused; the answer is
// {"access_token", "expires_at"}. It is never relayed to a client, and
// the gateway never relays such a request from a client (unknown methods
// are refused).
const TokenMethod = "mcp-gateway/token"

// tokenTimeout bounds answering TokenMethod (a refresh through the
// helper).
const tokenTimeout = 2 * time.Minute

// answerToken answers m, a TokenMethod request. An instance without a
// principal's sign-in gets "method not found"; one whose principal must
// sign in again an error naming signin.RejectedMarker, so that its
// connector exits as before.
func (u *upstream) answerToken(m *jsonrpc.Message) *jsonrpc.Message {
	if u.token == nil {
		return jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "method not found")
	}
	var p struct {
		Refused string `json:"refused"`
	}
	_ = json.Unmarshal(m.Params, &p)
	ctx, cancel := context.WithTimeout(context.Background(), tokenTimeout)
	defer cancel()
	tok, exp, err := u.token(ctx, p.Refused)
	if err != nil {
		u.log.Info("no new access token for the instance", "err", err)
		return jsonrpc.NewError(m.ID, jsonrpc.CodeInternalError, signin.RejectedMarker+": "+err.Error())
	}
	res := map[string]any{"access_token": tok}
	if !exp.IsZero() {
		res["expires_at"] = exp.UTC().Format(time.RFC3339)
	}
	r, err := jsonrpc.NewResult(m.ID, res)
	if err != nil {
		return jsonrpc.NewError(m.ID, jsonrpc.CodeInternalError, err.Error())
	}
	u.log.Info("new access token handed to the instance")
	return r
}

// maxLoggedLine bounds what is logged of a backend line that is not
// JSON-RPC.
const maxLoggedLine = 200

// excerpt returns at most n bytes of line as valid UTF-8, marked when cut.
func excerpt(line []byte, n int) string {
	if len(line) <= n {
		return strings.ToValidUTF8(string(line), "\ufffd")
	}
	return strings.ToValidUTF8(string(line[:n]), "\ufffd") + "…"
}
