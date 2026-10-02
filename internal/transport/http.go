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
	"strconv"
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
	sessionHeader = "Mcp-Session-Id"
	versionHeader = "MCP-Protocol-Version"
	metadataPath  = "/.well-known/oauth-protected-resource"
	maxBody       = jsonrpc.MaxMessageSize
	streamBuffer  = 64
	maxQueued     = 128
	// replayEvents is how many events each stream keeps for resumption.
	replayEvents = 256
	// resumeRetention is how long an answered request stream without a
	// connection can still be resumed.
	resumeRetention = 5 * time.Minute
	keepAlive       = 25 * time.Second
	reapInterval    = time.Minute
	pushTimeout     = 10 * time.Second
	sessionIDBytes  = 16
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
		streams:    map[int]*stream{},
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

// reap expires answered request streams nobody resumed and closes
// sessions without open streams and without traffic for SessionIdle.
func (h *HTTPHandler) reap() {
	interval := reapInterval
	if h.cfg.SessionIdle > 0 {
		interval = min(interval, h.cfg.SessionIdle)
	}
	t := time.NewTicker(interval)
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
			s.expireStreams(time.Now())
			if h.cfg.SessionIdle > 0 && s.idleSince(h.cfg.SessionIdle) {
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
// messages arrive in POST bodies. Server messages go out on SSE streams: a
// response on the stream of the POST that carried its request; other
// messages on the most recently opened request stream with a connection,
// else the GET stream if connected, else a bounded queue that the next
// stream drains.
//
// Resumability: every SSE event carries an id "<stream>-<seq>", and each
// stream keeps its last events, also while no connection is attached. A
// request stream whose connection broke keeps receiving its messages up
// to the response. A client resumes a stream with GET and Last-Event-ID:
// the events after that id are replayed, then the stream goes on (a
// request stream ends with its response).
type httpSession struct {
	h         *HTTPHandler
	id        string
	p         principal.Principal
	in        chan *jsonrpc.Message
	closed    chan struct{}
	closeOnce sync.Once

	mu         sync.Mutex
	streams    map[int]*stream    // resumable streams by number; 0 is the GET stream
	nextStream int                // number of the next request stream
	pending    map[string]*stream // streams awaiting a response, by client request id
	order      []*stream          // attached SSE request streams, oldest first
	queue      []*jsonrpc.Message
	lastActive time.Time
}

// stream is a logical stream of server messages; HTTP connections attach
// to and detach from it. Fields are guarded by the session's mu.
type stream struct {
	num      int
	key      string // client request id; "" for the GET stream
	sse      bool   // false: the response goes out as plain JSON
	events   []sseEvent
	next     int // seq of the next event; events start at 1
	attached bool
	conn     int           // generation of the attached connection
	done     bool          // request stream: its response was added
	detached time.Time     // when the last connection went away
	wake     chan struct{} // capacity 1: new events, for the attached connection
}

type sseEvent struct {
	seq      int
	data     []byte
	response bool
}

// add appends m to the stream's events. Caller holds the session's mu.
func (st *stream) add(m *jsonrpc.Message) {
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	resp := st.key != "" && m.IsResponse() && m.Key() == st.key
	st.events = append(st.events, sseEvent{seq: st.next, data: data, response: resp})
	st.next++
	if len(st.events) > replayEvents {
		st.events = st.events[len(st.events)-replayEvents:]
	}
	if resp {
		st.done = true
	}
	select {
	case st.wake <- struct{}{}:
	default:
	}
}

// eventsAfter returns the events after seq. Caller holds the session's mu.
func (st *stream) eventsAfter(seq int) []sseEvent {
	i := len(st.events)
	for i > 0 && st.events[i-1].seq > seq {
		i--
	}
	return slices.Clone(st.events[i:])
}

func newStream(num int, key string, sse bool) *stream {
	return &stream{num: num, key: key, sse: sse, next: 1, wake: make(chan struct{}, 1)}
}

// eventID formats the SSE id of event seq on stream num.
func eventID(num, seq int) string { return strconv.Itoa(num) + "-" + strconv.Itoa(seq) }

// parseEventID parses an SSE id from eventID.
func parseEventID(id string) (num, seq int, ok bool) {
	a, b, found := strings.Cut(id, "-")
	if !found {
		return 0, 0, false
	}
	num, err1 := strconv.Atoi(a)
	seq, err2 := strconv.Atoi(b)
	return num, seq, err1 == nil && err2 == nil && num >= 0 && seq >= 0
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
	for _, st := range s.streams {
		if st.attached {
			return false
		}
	}
	return len(s.pending) == 0 && time.Since(s.lastActive) > d
}

// Idle reports how long the session has had no traffic, and whether it
// may be ended to make room for another session of its principal: no
// stream attached and no request pending. The router uses it at the
// session limit (docs/architecture.md, decision D14).
func (s *httpSession) Idle() (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.streams {
		if st.attached {
			return 0, false
		}
	}
	return time.Since(s.lastActive), len(s.pending) == 0
}

// expireStreams drops request streams that are finished (or whose
// request was answered) and have had no connection for resumeRetention.
func (s *httpSession) expireStreams(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for num, st := range s.streams {
		if num != 0 && !st.attached && st.done && now.Sub(st.detached) > resumeRetention {
			delete(s.streams, num)
		}
	}
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
			st.add(m)
		}
		// The client left before a plain JSON response: drop it.
		return nil
	}
	for i := len(s.order) - 1; i >= 0; i-- {
		if st := s.order[i]; !st.done {
			st.add(m)
			return nil
		}
	}
	if get := s.streams[0]; get != nil && get.attached {
		get.add(m)
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

// drainQueue moves queued messages to st. Caller holds s.mu.
func (s *httpSession) drainQueue(st *stream) {
	for _, m := range s.queue {
		st.add(m)
	}
	s.queue = nil
}

// attach connects st to an HTTP connection, replacing one that is still
// attached (a client resuming a stream considers the old connection gone),
// and returns the connection's generation and wake channel. Caller holds
// s.mu.
func (s *httpSession) attach(st *stream) (int, chan struct{}) {
	if st.attached {
		close(st.wake) // ends the replaced connection's pipe
		st.wake = make(chan struct{}, 1)
		if len(st.events) > 0 {
			st.wake <- struct{}{}
		}
	}
	st.conn++
	st.attached = true
	if st.key != "" && st.sse && !st.done && !slices.Contains(s.order, st) {
		s.order = append(s.order, st)
	}
	if st.sse && (st.key == "" || !st.done) {
		s.drainQueue(st)
	}
	return st.conn, st.wake
}

// detach ends st's connection conn, unless another one replaced it.
func (s *httpSession) detach(st *stream, conn int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.conn != conn {
		return
	}
	st.attached = false
	st.detached = time.Now()
	s.order = slices.DeleteFunc(s.order, func(x *stream) bool { return x == st })
	s.lastActive = time.Now()
}

func (s *httpSession) handleRequest(w http.ResponseWriter, r *http.Request, m *jsonrpc.Message, sse bool) {
	key := m.Key()
	s.mu.Lock()
	if _, dup := s.pending[key]; dup {
		s.mu.Unlock()
		writeJSONError(w, http.StatusBadRequest, jsonrpc.CodeInvalidRequest, "duplicate request id")
		return
	}
	s.nextStream++
	st := newStream(s.nextStream, key, sse)
	s.pending[key] = st
	if sse {
		s.streams[st.num] = st
	}
	conn, wake := s.attach(st)
	s.mu.Unlock()

	if err := s.push(r.Context(), m); err != nil {
		s.mu.Lock()
		if s.pending[key] == st {
			delete(s.pending, key)
		}
		delete(s.streams, st.num)
		s.mu.Unlock()
		s.detach(st, conn)
		http.Error(w, "session ended", http.StatusNotFound)
		return
	}
	w.Header().Set(sessionHeader, s.id)
	if sse {
		// The stream outlives this connection: the client may resume it.
		defer s.detach(st, conn)
		s.pipe(w, r, st, 0, conn, wake)
		return
	}
	defer func() {
		s.mu.Lock()
		if s.pending[key] == st {
			delete(s.pending, key) // the client left: drop the response
		}
		s.mu.Unlock()
		s.detach(st, conn)
	}()
	for {
		s.mu.Lock()
		evs := st.eventsAfter(0)
		s.mu.Unlock()
		if len(evs) > 0 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(append(evs[len(evs)-1].data, '\n'))
			return
		}
		select {
		case <-wake:
		case <-r.Context().Done():
			return
		case <-s.closed:
			http.Error(w, "session ended", http.StatusNotFound)
			return
		}
	}
}

// serveStream serves a GET: the session's stream for messages not tied to
// a request, or, with Last-Event-ID, the resumption of the stream that
// event belongs to.
func (s *httpSession) serveStream(w http.ResponseWriter, r *http.Request) {
	cursor := -1 // plain GET: new events only
	num := 0
	if last := r.Header.Get("Last-Event-ID"); last != "" {
		var ok bool
		if num, cursor, ok = parseEventID(last); !ok {
			http.Error(w, "invalid Last-Event-ID", http.StatusBadRequest)
			return
		}
	}
	s.mu.Lock()
	st := s.streams[num]
	if st == nil && num == 0 {
		st = newStream(0, "", true)
		s.streams[0] = st
	}
	switch {
	case st == nil:
		s.mu.Unlock()
		http.Error(w, "unknown or expired Last-Event-ID", http.StatusBadRequest)
		return
	case st.attached && cursor < 0:
		s.mu.Unlock()
		http.Error(w, "stream already open", http.StatusConflict)
		return
	}
	if cursor < 0 {
		cursor = st.next - 1
	}
	conn, wake := s.attach(st)
	s.mu.Unlock()
	defer s.detach(st, conn)
	w.Header().Set(sessionHeader, s.id)
	s.pipe(w, r, st, cursor, conn, wake)
}

// pipe writes st's events after cursor as server-sent events until the
// response of a request stream was written, the client disconnects or
// the session ends.
func (s *httpSession) pipe(w http.ResponseWriter, r *http.Request, st *stream, cursor, conn int, wake chan struct{}) {
	flusher, _ := w.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	// Priming event: an id without data, so the client can resume even
	// before the first message (not dispatched by SSE clients).
	if _, err := fmt.Fprintf(w, "id: %s\ndata:\n\n", eventID(st.num, cursor)); err != nil {
		return
	}
	flush()
	ping := time.NewTicker(keepAlive)
	defer ping.Stop()
	for {
		s.mu.Lock()
		if st.conn != conn {
			s.mu.Unlock()
			return // replaced by a resuming connection
		}
		evs := st.eventsAfter(cursor)
		s.mu.Unlock()
		for _, ev := range evs {
			if _, err := fmt.Fprintf(w, "id: %s\nevent: message\ndata: %s\n\n", eventID(st.num, ev.seq), ev.data); err != nil {
				return
			}
			cursor = ev.seq
			if ev.response {
				flush()
				return
			}
		}
		flush()
		s.mu.Lock()
		answered := st.key != "" && st.done && cursor >= st.next-1
		s.mu.Unlock()
		if answered {
			return // resumed after the response was already delivered
		}
		select {
		case <-wake:
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			flush()
		case <-r.Context().Done():
			return
		case <-s.closed:
			return
		}
	}
}
