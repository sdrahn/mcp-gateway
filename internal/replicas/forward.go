package replicas

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Headers between replicas, set by the forwarding replica and trusted on
// the peer listener only (docs/architecture.md, section 5.12.5): who
// forwarded, the client's certificate as the forwarding replica's TLS
// layer verified it (base64 DER), and the client's address. On the
// public listener they are dropped.
const (
	ForwardedByHeader = "Mcp-Gateway-Forwarded-By"
	ClientCertHeader  = "Mcp-Gateway-Client-Cert"
	ClientAddrHeader  = "Mcp-Gateway-Client-Addr"
	// StateSeparator separates the replica's name from the rest of a
	// sign-in's state, so that its callback finds the replica that
	// started it.
	StateSeparator = "~"
)

var peerHeaders = []string{ForwardedByHeader, ClientCertHeader, ClientAddrHeader}

// Authenticator validates a request's bearer token as the HTTP listener
// does (authn.OAuth).
type Authenticator interface {
	Authenticate(ctx context.Context, token string, cert *x509.Certificate) (principal.Principal, error)
}

// Key is the key a principal's Lease is taken for: the one the router
// shares a principal's instances by.
func Key(p principal.Principal) string {
	return string(p.Transport) + "\x00" + p.Issuer + "\x00" + p.Sub
}

// Forwarder routes the requests of the public listener: a request of a
// principal another replica owns goes to it over the peer listener, as it
// came, streams included; the rest is served here (Local). The owner
// validates the token itself: the forwarding replica's validation only
// finds the owner, and a request with a token that does not validate is
// served here, which refuses it.
type Forwarder struct {
	Members *Members
	Owners  *Owners
	Auth    Authenticator
	// MCPPath is the listener's MCP base path ("/mcp"); SignInPaths the
	// sign-in's paths with a state ("/oauth/start/", "/oauth/callback").
	MCPPath     string
	SignInPaths []string
	// Cookies are cookies whose values start with the name of the
	// replica that holds what they stand for (the approval page's
	// sign-ins: approvalpage.RoutedCookies): a request with one goes
	// there.
	Cookies []string
	Local   http.Handler
	// Transport reaches the peers' listener (mTLS).
	Transport http.RoundTripper
	Log       *slog.Logger
}

func (f *Forwarder) log() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.Default()
}

func (f *Forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, h := range peerHeaders {
		r.Header.Del(h)
	}
	if replica := f.routedReplica(r); replica != "" && replica != f.Members.Name {
		if m, ok := f.Members.Live()[replica]; ok {
			f.forward(w, r, m)
			return
		}
		// Its replica is gone, and the sign-in with it: served here, which
		// says the sign-in is unknown.
	}
	if !f.isMCP(r.URL.Path) {
		f.Local.ServeHTTP(w, r)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		f.Local.ServeHTTP(w, r)
		return
	}
	var cert *x509.Certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert = r.TLS.PeerCertificates[0]
	}
	p, err := f.Auth.Authenticate(r.Context(), strings.TrimSpace(token), cert)
	if err != nil {
		f.Local.ServeHTTP(w, r)
		return
	}
	owner, err := f.Owners.Owner(r.Context(), Key(p))
	if err != nil {
		f.log().Warn("replicas: no owner for a principal; not served", "sub", p.Sub, "err", err)
		http.Error(w, "the gateway cannot serve this principal now; try again", http.StatusServiceUnavailable)
		return
	}
	if owner == f.Members.Name {
		f.Local.ServeHTTP(w, r)
		return
	}
	m, ok := f.Members.Live()[owner]
	if !ok {
		http.Error(w, "the gateway cannot serve this principal now; try again", http.StatusServiceUnavailable)
		return
	}
	f.forward(w, r, m)
}

func (f *Forwarder) isMCP(path string) bool {
	base := strings.TrimSuffix(f.MCPPath, "/")
	return path == base || strings.HasPrefix(path, base+"/")
}

// routedReplica returns the replica a request names: in a sign-in
// path's state, else in one of the Cookies ("" for none).
func (f *Forwarder) routedReplica(r *http.Request) string {
	if replica := f.signInReplica(r); replica != "" {
		return replica
	}
	for _, name := range f.Cookies {
		c, err := r.Cookie(name)
		if err != nil {
			continue
		}
		if replica, _, ok := strings.Cut(c.Value, StateSeparator); ok {
			return replica
		}
	}
	return ""
}

// signInReplica returns the replica named in a sign-in path's state ("").
func (f *Forwarder) signInReplica(r *http.Request) string {
	for _, p := range f.SignInPaths {
		var state string
		switch {
		case strings.HasSuffix(p, "/") && strings.HasPrefix(r.URL.Path, p):
			state = strings.TrimPrefix(r.URL.Path, p)
		case r.URL.Path == p:
			state = r.URL.Query().Get("state")
		default:
			continue
		}
		if replica, _, ok := strings.Cut(state, StateSeparator); ok {
			return replica
		}
	}
	return ""
}

// forward sends r to m's peer listener and its answer back as it comes.
func (f *Forwarder) forward(w http.ResponseWriter, r *http.Request, m Member) {
	target := &url.URL{Scheme: "https", Host: m.Address}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Set(ForwardedByHeader, f.Members.Name)
			pr.Out.Header.Set(ClientAddrHeader, pr.In.RemoteAddr)
			if pr.In.TLS != nil && len(pr.In.TLS.PeerCertificates) > 0 {
				pr.Out.Header.Set(ClientCertHeader, base64.StdEncoding.EncodeToString(pr.In.TLS.PeerCertificates[0].Raw))
			}
		},
		Transport: f.Transport,
		// Streams (SSE) pass through as they come.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			f.log().Warn("replicas: forwarding to the owner failed", "replica", m.Name, "err", err)
			http.Error(w, "the gateway cannot serve this principal now; try again", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// PeerHandler serves the peer listener: requests other replicas forwarded,
// over mTLS with the replicas' certificate (the listener's TLS layer
// verified it). The client's certificate and address come from the
// forwarding replica's headers; a request of a principal this replica
// does not own (any more) is refused (421), and the client tries again
// (D24): no replica takes a principal on a peer's word.
type PeerHandler struct {
	Forwarder *Forwarder
	// Internal, if set, serves the paths below InternalPrefix: what the
	// replicas ask each other themselves (internal/cluster), not
	// clients' requests.
	Internal       http.Handler
	InternalPrefix string
}

func (h *PeerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f := h.Forwarder
	if r.Header.Get(ForwardedByHeader) == "" || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "the peer listener serves the gateway's replicas only", http.StatusForbidden)
		return
	}
	if h.Internal != nil && h.InternalPrefix != "" && strings.HasPrefix(r.URL.Path, h.InternalPrefix) {
		h.Internal.ServeHTTP(w, r)
		return
	}
	// The client's view, not the forwarding replica's.
	state := tls.ConnectionState{Version: r.TLS.Version, CipherSuite: r.TLS.CipherSuite, HandshakeComplete: true, ServerName: r.TLS.ServerName}
	if raw := r.Header.Get(ClientCertHeader); raw != "" {
		der, err := base64.StdEncoding.DecodeString(raw)
		cert, cerr := x509.ParseCertificate(der)
		if err != nil || cerr != nil {
			http.Error(w, "a forwarded client certificate that does not parse", http.StatusBadRequest)
			return
		}
		state.PeerCertificates = []*x509.Certificate{cert}
	}
	r2 := r.Clone(r.Context())
	r2.TLS = &state
	if addr := r.Header.Get(ClientAddrHeader); addr != "" {
		r2.RemoteAddr = addr
	}
	for _, name := range peerHeaders {
		r2.Header.Del(name)
	}
	if f.isMCP(r2.URL.Path) {
		token, ok := strings.CutPrefix(r2.Header.Get("Authorization"), "Bearer ")
		if ok && token != "" {
			var cert *x509.Certificate
			if len(state.PeerCertificates) > 0 {
				cert = state.PeerCertificates[0]
			}
			if p, err := f.Auth.Authenticate(r2.Context(), strings.TrimSpace(token), cert); err == nil {
				if owner, err := f.Owners.Owner(r2.Context(), Key(p)); err != nil || owner != f.Members.Name {
					http.Error(w, "this replica does not serve the principal; try again", http.StatusMisdirectedRequest)
					return
				}
			}
		}
	}
	f.Local.ServeHTTP(w, r2)
}
