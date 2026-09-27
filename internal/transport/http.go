package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Errors an Authenticator returns: ErrInvalidToken answers 401,
// ErrInsufficientScope 403 (RFC 6750).
var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrInsufficientScope = errors.New("insufficient scope")
)

// Authenticator validates bearer tokens. cert is the client's verified
// TLS certificate, if it presented one, for certificate-bound tokens.
type Authenticator interface {
	Authenticate(ctx context.Context, token string, cert *x509.Certificate) (principal.Principal, error)
}

// SessionFunc runs an MCP session over conn; first is the hello selecting
// the endpoint. It returns when the session ends.
type SessionFunc func(ctx context.Context, conn jsonrpc.MessageConn, p principal.Principal, first *jsonrpc.Message)

// HTTPConfig configures the Streamable HTTP transport.
type HTTPConfig struct {
	// Resource is the gateway's public MCP URL (the token audience). Its
	// path is the aggregated endpoint; <path>/<server> are the per-server
	// endpoints.
	Resource string
	// AuthorizationServers are listed in the protected resource metadata.
	AuthorizationServers []string
	Scopes               []string
	AllowedOrigins       []string
	// CertificateBoundTokens announces support for certificate-bound
	// access tokens (RFC 8705) in the metadata; set with mTLS.
	CertificateBoundTokens bool
	// KnownServer reports whether a per-server endpoint exists.
	KnownServer func(name string) bool
	SessionIdle time.Duration
	Log         *slog.Logger
}

const (
	sessionHeader  = "Mcp-Session-Id"
	versionHeader  = "MCP-Protocol-Version"
	metadataPath   = "/.well-known/oauth-protected-resource"
	maxBody        = jsonrpc.MaxMessageSize
	streamBuffer   = 64
	maxQueued      = 128
	keepAlive      = 25 * time.Second
	reapInterval   = time.Minute
	pushTimeout    = 10 * time.Second
	sessionIDBytes = 16
)

var supportedVersions = map[string]bool{"2025-03-26": true, "2025-06-18": true, "2025-11-25": true}

// HTTPHandler serves MCP Streamable HTTP (single endpoint; POST for client
// messages, GET for a server stream, DELETE to end a session) and the
// OAuth protected resource metadata (RFC 9728).
type HTTPHandler struct {
	cfg      HTTPConfig
	auth     Authenticator
	serve    SessionFunc
	log      *slog.Logger
	basePath string
	metaURL  string
	ctx      context.Context
	cancel   context.CancelFunc

	mu       sync.Mutex
	sessions map[string]*httpSession
}

// NewHTTPHandler returns the transport handler. Close it to end all
// sessions.
func NewHTTPHandler(cfg HTTPConfig, auth Authenticator, serve SessionFunc) (*HTTPHandler, error) {
	u, err := url.Parse(cfg.Resource)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("transport: invalid resource URL %q", cfg.Resource)
	}
	base := strings.TrimSuffix(u.Path, "/")
	if base == "" {
		base = "/"
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &HTTPHandler{
		cfg:      cfg,
		auth:     auth,
		serve:    serve,
		log:      log,
		basePath: base,
		// RFC 9728: the metadata path is the well-known prefix followed by
		// the resource's path.
		metaURL:  u.Scheme + "://" + u.Host + metadataPath + strings.TrimSuffix(base, "/"),
		ctx:      ctx,
		cancel:   cancel,
		sessions: map[string]*httpSession{},
	}
	go h.reap()
	return h, nil
}

// Close ends all sessions.
func (h *HTTPHandler) Close() {
	h.cancel()
	h.mu.Lock()
	sessions := make([]*httpSession, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, s)
	}
	h.mu.Unlock()
	for _, s := range sessions {
		_ = s.Close()
	}
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == metadataPath || r.URL.Path == metadataPath+strings.TrimSuffix(h.basePath, "/") {
		h.serveMetadata(w, r)
		return
	}
	server, ok := h.endpoint(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if o := r.Header.Get("Origin"); o != "" && !slices.Contains(h.cfg.AllowedOrigins, o) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	p, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if v := r.Header.Get(versionHeader); v != "" && !supportedVersions[v] {
		http.Error(w, "unsupported MCP protocol version", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.post(w, r, p, server)
	case http.MethodGet:
		h.get(w, r, p)
	case http.MethodDelete:
		if s := h.session(r, p); s != nil {
			_ = s.Close()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "unknown session", http.StatusNotFound)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// endpoint maps a request path to "all" (aggregated) or a server name.
func (h *HTTPHandler) endpoint(path string) (string, bool) {
	if path == h.basePath || path == h.basePath+"/" {
		return "all", true
	}
	prefix := strings.TrimSuffix(h.basePath, "/") + "/"
	name, ok := strings.CutPrefix(path, prefix)
	if !ok || name == "" || strings.Contains(name, "/") {
		return "", false
	}
	if h.cfg.KnownServer != nil && !h.cfg.KnownServer(name) {
		return "", false
	}
	return name, true
}

func (h *HTTPHandler) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	meta := map[string]any{
		"resource":                 h.cfg.Resource,
		"authorization_servers":    h.cfg.AuthorizationServers,
		"bearer_methods_supported": []string{"header"},
	}
	if len(h.cfg.Scopes) > 0 {
		meta["scopes_supported"] = h.cfg.Scopes
	}
	if h.cfg.CertificateBoundTokens {
		meta["tls_client_certificate_bound_access_tokens"] = true
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

func (h *HTTPHandler) authenticate(w http.ResponseWriter, r *http.Request) (principal.Principal, bool) {
	challenge := fmt.Sprintf(`Bearer resource_metadata=%q`, h.metaURL)
	if len(h.cfg.Scopes) > 0 {
		challenge += fmt.Sprintf(`, scope=%q`, strings.Join(h.cfg.Scopes, " "))
	}
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || token == "" {
		w.Header().Set("WWW-Authenticate", challenge)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return principal.Principal{}, false
	}
	var cert *x509.Certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		// Verified by the TLS layer against the client CAs.
		cert = r.TLS.PeerCertificates[0]
	}
	p, err := h.auth.Authenticate(r.Context(), strings.TrimSpace(token), cert)
	switch {
	case errors.Is(err, ErrInsufficientScope):
		w.Header().Set("WWW-Authenticate", challenge+`, error="insufficient_scope"`)
		http.Error(w, "insufficient scope", http.StatusForbidden)
		return principal.Principal{}, false
	case err != nil:
		h.log.Info("token rejected", "err", err, "remote", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", challenge+`, error="invalid_token"`)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return principal.Principal{}, false
	}
	if cert != nil {
		p.Cert = principal.NewCert(cert)
	}
	return p, true
}

// session returns the session named in the request if it belongs to p. A
// session of another principal is reported as unknown.
func (h *HTTPHandler) session(r *http.Request, p principal.Principal) *httpSession {
	id := r.Header.Get(sessionHeader)
	h.mu.Lock()
	s := h.sessions[id]
	h.mu.Unlock()
	if s == nil || !s.ownedBy(p) {
		return nil
	}
	return s
}

func (h *HTTPHandler) post(w http.ResponseWriter, r *http.Request, p principal.Principal, server string) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "request too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		writeJSONError(w, http.StatusBadRequest, jsonrpc.CodeInvalidRequest, "batching is not supported")
		return
	}
	m := &jsonrpc.Message{}
	if err := json.Unmarshal(body, m); err != nil {
		writeJSONError(w, http.StatusBadRequest, jsonrpc.CodeParseError, "parse error")
		return
	}
	if m.JSONRPC != jsonrpc.Version || (m.Method == "" && len(m.ID) == 0) {
		writeJSONError(w, http.StatusBadRequest, jsonrpc.CodeInvalidRequest, "invalid request")
		return
	}

	var s *httpSession
	if r.Header.Get(sessionHeader) == "" {
		if !m.IsRequest() || m.Method != "initialize" {
			http.Error(w, "missing "+sessionHeader, http.StatusBadRequest)
			return
		}
		s, err = h.newSession(p, server)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	} else if s = h.session(r, p); s == nil {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}

	if !m.IsRequest() {
		if err := s.push(r.Context(), m); err != nil {
			http.Error(w, "session ended", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	s.handleRequest(w, r, m, strings.Contains(r.Header.Get("Accept"), "text/event-stream"))
}

func (h *HTTPHandler) get(w http.ResponseWriter, r *http.Request, p principal.Principal) {
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		http.Error(w, "GET requires Accept: text/event-stream", http.StatusMethodNotAllowed)
		return
	}
	s := h.session(r, p)
	if s == nil {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	s.serveStream(w, r)
}

func (h *HTTPHandler) newSession(p principal.Principal, server string) (*httpSession, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	p.SessionID = hex.EncodeToString(b)
	s := &httpSession{
		h:          h,
		id:         p.SessionID,
		p:          p,
		in:         make(chan *jsonrpc.Message, streamBuffer),
		closed:     make(chan struct{}),
		pending:    map[string]*stream{},
		lastActive: time.Now(),
	}
	h.mu.Lock()
	h.sessions[s.id] = s
	h.mu.Unlock()
	hello, err := NewHello(server)
	if err != nil {
		return nil, err
	}
	go func() {
		h.serve(h.ctx, s, p, hello)
		_ = s.Close()
	}()
	return s, nil
}

func (h *HTTPHandler) remove(s *httpSession) {
	h.mu.Lock()
	if h.sessions[s.id] == s {
		delete(h.sessions, s.id)
	}
	h.mu.Unlock()
}

// reap closes sessions without open streams and without traffic for
// SessionIdle.
func (h *HTTPHandler) reap() {
	if h.cfg.SessionIdle <= 0 {
		return
	}
	t := time.NewTicker(min(reapInterval, h.cfg.SessionIdle))
	defer t.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-t.C:
		}
		h.mu.Lock()
		var idle []*httpSession
		for _, s := range h.sessions {
			if s.idleSince(h.cfg.SessionIdle) {
				idle = append(idle, s)
			}
		}
		h.mu.Unlock()
		for _, s := range idle {
			h.log.Info("closing idle HTTP session", "session", s.id)
			_ = s.Close()
		}
	}
}

func writeJSONError(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonrpc.NewError(nil, code, msg))
}

// --- sessions -----------------------------------------------------------

// httpSession adapts one MCP session to a jsonrpc.MessageConn. Client
// messages arrive in POST bodies. A response goes to the stream of the
// POST that carried its request; other server messages go to the most
// recently opened request stream, else the GET stream, else a bounded
// queue that the next stream drains.
type httpSession struct {
	h         *HTTPHandler
	id        string
	p         principal.Principal
	in        chan *jsonrpc.Message
	closed    chan struct{}
	closeOnce sync.Once

	mu         sync.Mutex
	pending    map[string]*stream // by client request id
	order      []*stream          // open SSE request streams, oldest first
	get        *stream
	queue      []*jsonrpc.Message
	lastActive time.Time
}

type stream struct {
	msgs chan *jsonrpc.Message
	done chan struct{}
}

func newStream() *stream {
	return &stream{msgs: make(chan *jsonrpc.Message, streamBuffer), done: make(chan struct{})}
}

func (st *stream) send(m *jsonrpc.Message) bool {
	select {
	case st.msgs <- m:
		return true
	case <-st.done:
		return false
	}
}

// ownedBy reports whether p may use the session: the same subject, over
// the same client certificate (if any), which policy may have relied on.
func (s *httpSession) ownedBy(p principal.Principal) bool {
	return s.p.Transport == p.Transport && s.p.Issuer == p.Issuer && s.p.Sub == p.Sub &&
		thumbprint(s.p.Cert) == thumbprint(p.Cert)
}

func thumbprint(c *principal.Cert) string {
	if c == nil {
		return ""
	}
	return c.Thumbprint
}

func (s *httpSession) idleSince(d time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending) == 0 && s.get == nil && time.Since(s.lastActive) > d
}

// Read implements jsonrpc.MessageConn.
func (s *httpSession) Read() (*jsonrpc.Message, error) {
	select {
	case m := <-s.in:
		return m, nil
	case <-s.closed:
		return nil, io.EOF
	}
}

// Write implements jsonrpc.MessageConn.
func (s *httpSession) Write(m *jsonrpc.Message) error {
	select {
	case <-s.closed:
		return io.ErrClosedPipe
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.IsResponse() {
		if st := s.pending[m.Key()]; st != nil {
			delete(s.pending, m.Key())
			st.send(m)
		}
		// The client left before the response: drop it.
		return nil
	}
	for i := len(s.order) - 1; i >= 0; i-- {
		if s.order[i].send(m) {
			return nil
		}
	}
	if s.get != nil && s.get.send(m) {
		return nil
	}
	if len(s.queue) >= maxQueued {
		s.queue = s.queue[1:]
	}
	s.queue = append(s.queue, m)
	return nil
}

// Close implements jsonrpc.MessageConn and ends the session.
func (s *httpSession) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.h.remove(s)
	})
	return nil
}

func (s *httpSession) push(ctx context.Context, m *jsonrpc.Message) error {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	select {
	case s.in <- m:
		return nil
	case <-s.closed:
		return io.ErrClosedPipe
	case <-ctx.Done():
		return ctx.Err()
	}
}

// drainQueue hands queued messages to st as far as its buffer allows,
// without blocking. Caller holds s.mu.
func (s *httpSession) drainQueue(st *stream) {
	for len(s.queue) > 0 {
		select {
		case st.msgs <- s.queue[0]:
			s.queue = s.queue[1:]
		default:
			return
		}
	}
}

func (s *httpSession) handleRequest(w http.ResponseWriter, r *http.Request, m *jsonrpc.Message, sse bool) {
	st := newStream()
	key := m.Key()
	s.mu.Lock()
	if _, dup := s.pending[key]; dup {
		s.mu.Unlock()
		writeJSONError(w, http.StatusBadRequest, jsonrpc.CodeInvalidRequest, "duplicate request id")
		return
	}
	s.pending[key] = st
	if sse {
		s.order = append(s.order, st)
		s.drainQueue(st)
	}
	s.mu.Unlock()
	defer func() {
		close(st.done)
		s.mu.Lock()
		if s.pending[key] == st {
			delete(s.pending, key)
		}
		s.order = slices.DeleteFunc(s.order, func(x *stream) bool { return x == st })
		s.lastActive = time.Now()
		s.mu.Unlock()
	}()

	if err := s.push(r.Context(), m); err != nil {
		http.Error(w, "session ended", http.StatusNotFound)
		return
	}
	w.Header().Set(sessionHeader, s.id)
	if !sse {
		select {
		case resp := <-st.msgs:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case <-r.Context().Done():
		case <-s.closed:
			http.Error(w, "session ended", http.StatusNotFound)
		}
		return
	}
	s.pipe(w, r, st, key)
}

// serveStream serves the GET stream for messages not tied to a request.
func (s *httpSession) serveStream(w http.ResponseWriter, r *http.Request) {
	st := newStream()
	s.mu.Lock()
	if s.get != nil {
		s.mu.Unlock()
		http.Error(w, "stream already open", http.StatusConflict)
		return
	}
	s.get = st
	s.drainQueue(st)
	s.mu.Unlock()
	defer func() {
		close(st.done)
		s.mu.Lock()
		if s.get == st {
			s.get = nil
		}
		s.lastActive = time.Now()
		s.mu.Unlock()
	}()
	w.Header().Set(sessionHeader, s.id)
	s.pipe(w, r, st, "")
}

// pipe writes st's messages as server-sent events until the response to
// request key (if any) was written, the client disconnects or the session
// ends.
func (s *httpSession) pipe(w http.ResponseWriter, r *http.Request, st *stream, key string) {
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}
	ping := time.NewTicker(keepAlive)
	defer ping.Stop()
	for {
		select {
		case m := <-st.msgs:
			b, err := json.Marshal(m)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", b); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			if key != "" && m.IsResponse() && m.Key() == key {
				return
			}
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		case <-r.Context().Done():
			return
		case <-s.closed:
			return
		}
	}
}
