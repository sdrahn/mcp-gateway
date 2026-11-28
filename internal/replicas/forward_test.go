package replicas

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/kube/kubetest"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// tokens is an Authenticator: a token is its principal's name.
type tokens struct{}

func (tokens) Authenticate(_ context.Context, token string, _ *x509.Certificate) (principal.Principal, error) {
	if token == "bad" {
		return principal.Principal{}, errors.New("invalid token")
	}
	return principal.Principal{Transport: principal.TransportHTTP, Issuer: "https://idp", Sub: token}, nil
}

// pki is a CA and certificates it issued.
type pki struct {
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
	pool  *x509.CertPool
	child int64
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{ca: ca, key: key, pool: pool, child: 1}
}

func (p *pki) issue(t *testing.T, name string) tls.Certificate {
	t.Helper()
	p.child++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.child), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// replica is a replica under test: its Forwarder (the public listener's
// handler) and its peer listener.
type replica struct {
	name string
	fwd  *Forwarder
	peer *httptest.Server
	// seen is what its Local handler saw last.
	seen chan *http.Request
}

func newReplica(t *testing.T, api *kubetest.Secrets, p *pki, name string) *replica {
	t.Helper()
	rp := &replica{name: name, seen: make(chan *http.Request, 10)}
	local := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rp.seen <- r
		if r.URL.Path == "/mcp/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "data: first from %s\n\n", name)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = fmt.Fprintf(w, "served by %s", name)
	})
	peerCert := p.issue(t, "mcp-gateway-peer")
	srv := httptest.NewUnstartedServer(nil)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{peerCert}, ClientCAs: p.pool, ClientAuth: tls.RequireAndVerifyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	rp.peer = srv
	m := &Members{Client: api.Client(), Namespace: "gw", Name: name, Address: strings.TrimPrefix(srv.URL, "https://")}
	if err := m.Join(context.Background()); err != nil {
		t.Fatal(err)
	}
	rp.fwd = &Forwarder{Members: m, Owners: &Owners{Client: api.Client(), Namespace: "gw", Members: m, Idle: time.Minute},
		Auth: tokens{}, MCPPath: "/mcp", SignInPaths: []string{"/oauth/start/", "/oauth/callback"}, Local: local,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{peerCert}, RootCAs: p.pool,
			ServerName: "mcp-gateway-peer"}}}
	srv.Config.Handler = &PeerHandler{Forwarder: rp.fwd}
	return rp
}

func (rp *replica) request(method, path, token string, cert *x509.Certificate, hdr http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://gw.example"+path, nil)
	r.RemoteAddr = "192.0.2.7:4711"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		r.Header[k] = v
	}
	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	w := httptest.NewRecorder()
	rp.fwd.ServeHTTP(w, r)
	return w
}

func refreshAll(t *testing.T, rs ...*replica) {
	t.Helper()
	for _, r := range rs {
		if err := r.fwd.Members.refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

// A principal's request reaches its owner through any replica: with the
// client's address and certificate as the first replica saw them, and
// spoofed peer headers dropped.
func TestForward(t *testing.T) {
	api := kubetest.NewSecrets(t)
	p := newPKI(t)
	a, b := newReplica(t, api, p, "gw-a"), newReplica(t, api, p, "gw-b")
	refreshAll(t, a, b)
	if w := b.request("POST", "/mcp/fs", "alice", nil, nil); w.Body.String() != "served by gw-b" {
		t.Fatalf("at b: %d %s", w.Code, w.Body)
	}
	<-b.seen
	client := p.issue(t, "alice-laptop").Leaf
	spoof := http.Header{ClientAddrHeader: {"10.9.9.9:1"}, ForwardedByHeader: {"gw-x"}}
	w := a.request("POST", "/mcp/fs", "alice", client, spoof)
	if w.Body.String() != "served by gw-b" {
		t.Fatalf("at a: %d %s", w.Code, w.Body)
	}
	got := <-b.seen
	if got.RemoteAddr != "192.0.2.7:4711" {
		t.Errorf("client address at the owner %q", got.RemoteAddr)
	}
	if got.TLS == nil || len(got.TLS.PeerCertificates) != 1 || got.TLS.PeerCertificates[0].Subject.CommonName != "alice-laptop" {
		t.Errorf("client certificate at the owner: %+v", got.TLS)
	}
	for _, h := range peerHeaders {
		if got.Header.Get(h) != "" {
			t.Errorf("header %s reached the owner's handler", h)
		}
	}
	// bob's first request is at a: a's.
	if w := a.request("POST", "/mcp/fs", "bob", nil, nil); w.Body.String() != "served by gw-a" {
		t.Fatalf("bob at a: %s", w.Body)
	}
	<-a.seen
	// Without a valid token, or not MCP: served here.
	if w := a.request("POST", "/mcp/fs", "bad", nil, nil); w.Body.String() != "served by gw-a" {
		t.Fatalf("bad token: %s", w.Body)
	}
	<-a.seen
	if w := a.request("GET", "/approvals/x", "alice", nil, nil); w.Body.String() != "served by gw-a" {
		t.Fatalf("approval page: %s", w.Body)
	}
	<-a.seen
}

// A stream passes through as it comes.
func TestForwardStream(t *testing.T) {
	api := kubetest.NewSecrets(t)
	p := newPKI(t)
	a, b := newReplica(t, api, p, "gw-a"), newReplica(t, api, p, "gw-b")
	refreshAll(t, a, b)
	if _, err := b.fwd.Owners.Owner(context.Background(), Key(principal.Principal{Transport: principal.TransportHTTP, Issuer: "https://idp", Sub: "alice"})); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(a.fwd)
	defer front.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", front.URL+"/mcp/stream", nil)
	req.Header.Set("Authorization", "Bearer alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: first from gw-b\n" {
		t.Fatalf("first event %q %v", line, err)
	}
}

// requestBody is request with a body.
func (rp *replica) requestBody(path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://gw.example"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	rp.fwd.ServeHTTP(w, r)
	return w
}

// An owner that gave the principal up (it drains) before the forwarding
// replica saw it: asked again, the request is served by the new owner,
// with its body, and the client sees no 421.
func TestForwardOwnerGaveUp(t *testing.T) {
	api := kubetest.NewSecrets(t)
	p := newPKI(t)
	a, b := newReplica(t, api, p, "gw-a"), newReplica(t, api, p, "gw-b")
	refreshAll(t, a, b)
	if w := b.request("POST", "/mcp/fs", "alice", nil, nil); w.Body.String() != "served by gw-b" {
		t.Fatalf("at b: %s", w.Body)
	}
	<-b.seen
	if w := a.request("POST", "/mcp/fs", "alice", nil, nil); w.Body.String() != "served by gw-b" {
		t.Fatalf("at a, before: %s", w.Body)
	}
	<-b.seen
	if err := b.fwd.Members.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	refreshAll(t, a, b)
	b.fwd.Owners.releaseAll()
	w := a.requestBody("/mcp/fs", "alice", `{"jsonrpc":"2.0","id":7}`)
	if w.Code != http.StatusOK || w.Body.String() != "served by gw-a" {
		t.Fatalf("at a, after b gave alice up: %d %s", w.Code, w.Body)
	}
	got := <-a.seen
	if body, _ := io.ReadAll(got.Body); string(body) != `{"jsonrpc":"2.0","id":7}` {
		t.Errorf("the body at the new owner: %q", body)
	}
	select {
	case <-b.seen:
		t.Error("b served alice after giving her up")
	default:
	}
}

// An owner that went before the forwarding replica saw it (its peer
// listener closed, its replica Lease gone): asked again, with the
// replicas listed anew, another serves the principal.
func TestForwardOwnerGone(t *testing.T) {
	api := kubetest.NewSecrets(t)
	p := newPKI(t)
	a, b := newReplica(t, api, p, "gw-a"), newReplica(t, api, p, "gw-b")
	refreshAll(t, a, b)
	if w := b.request("POST", "/mcp/fs", "alice", nil, nil); w.Body.String() != "served by gw-b" {
		t.Fatalf("at b: %s", w.Body)
	}
	<-b.seen
	b.peer.Close()
	b.fwd.Members.leave()
	if w := a.requestBody("/mcp/fs", "alice", "{}"); w.Code != http.StatusOK || w.Body.String() != "served by gw-a" {
		t.Fatalf("at a, after b went: %d %s", w.Code, w.Body)
	}
	<-a.seen
}

// The peer listener serves replicas only, and refuses a principal its
// replica does not own (421: the client tries again).
func TestPeerRefuses(t *testing.T) {
	api := kubetest.NewSecrets(t)
	p := newPKI(t)
	a, b := newReplica(t, api, p, "gw-a"), newReplica(t, api, p, "gw-b")
	refreshAll(t, a, b)
	// Without a client certificate: the TLS layer refuses.
	if _, err := http.Get(b.peer.URL + "/mcp/fs"); err == nil {
		t.Error("peer listener without a client certificate")
	}
	peer := &http.Client{Transport: a.fwd.Transport}
	// A replica's certificate, but not forwarded.
	resp, err := peer.Get(b.peer.URL + "/mcp/fs")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("not forwarded: %d", resp.StatusCode)
	}
	// alice is a's: b refuses her forwarded request.
	if _, err := a.fwd.Owners.Owner(context.Background(), "http\x00https://idp\x00alice"); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", b.peer.URL+"/mcp/fs", nil)
	req.Header.Set(ForwardedByHeader, "gw-a")
	req.Header.Set("Authorization", "Bearer alice")
	resp, err = peer.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("not the owner: %d %s", resp.StatusCode, body)
	}
}

// A sign-in's callback and start page reach the replica named in its
// state; one of a replica that is gone is served here.
func TestForwardSignIn(t *testing.T) {
	api := kubetest.NewSecrets(t)
	p := newPKI(t)
	a, b := newReplica(t, api, p, "gw-a"), newReplica(t, api, p, "gw-b")
	refreshAll(t, a, b)
	if w := a.request("GET", "/oauth/callback?state=gw-b~xyz&code=c", "", nil, nil); w.Body.String() != "served by gw-b" {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	if got := <-b.seen; got.URL.Query().Get("code") != "c" {
		t.Errorf("query at b: %s", got.URL.RawQuery)
	}
	if w := a.request("GET", "/oauth/start/gw-b~xyz", "", nil, nil); w.Body.String() != "served by gw-b" {
		t.Fatalf("start: %s", w.Body)
	}
	<-b.seen
	if w := a.request("GET", "/oauth/callback?state=gw-gone~xyz", "", nil, nil); w.Body.String() != "served by gw-a" {
		t.Fatalf("gone replica: %s", w.Body)
	}
	<-a.seen
}

// A request with a cookie that names a replica reaches it (the approval
// page's sign-ins); one of a replica that is gone, or without a name, is
// served here.
func TestForwardCookies(t *testing.T) {
	api := kubetest.NewSecrets(t)
	p := newPKI(t)
	a, b := newReplica(t, api, p, "gw-a"), newReplica(t, api, p, "gw-b")
	refreshAll(t, a, b)
	a.fwd.Cookies = []string{"__Host-session"}
	for _, tc := range []struct{ cookie, want string }{
		{"gw-b~xyz", "served by gw-b"},
		{"gw-a~xyz", "served by gw-a"},
		{"gw-gone~xyz", "served by gw-a"},
		{"xyz", "served by gw-a"},
	} {
		hdr := http.Header{"Cookie": {"other=gw-b~1; __Host-session=" + tc.cookie}}
		w := a.request("GET", "/approvals/a-1", "", nil, hdr)
		if w.Body.String() != tc.want {
			t.Errorf("cookie %s: %d %s", tc.cookie, w.Code, w.Body)
			continue
		}
		if strings.HasSuffix(tc.want, "gw-b") {
			<-b.seen
		} else {
			<-a.seen
		}
	}
	// Only the cookies named route.
	if w := a.request("GET", "/approvals/", "", nil, http.Header{"Cookie": {"other=gw-b~1"}}); w.Body.String() != "served by gw-a" {
		t.Errorf("another cookie: %s", w.Body)
	}
	<-a.seen
}

// The peer listener serves the replicas' own requests below its
// internal prefix, to replicas only; clients' forwarded requests go on as
// before.
func TestPeerInternal(t *testing.T) {
	api := kubetest.NewSecrets(t)
	p := newPKI(t)
	a, b := newReplica(t, api, p, "gw-a"), newReplica(t, api, p, "gw-b")
	refreshAll(t, a, b)
	b.peer.Config.Handler = &PeerHandler{Forwarder: b.fwd, InternalPrefix: "/peer/v1/",
		Internal: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, "internal "+r.URL.Path) })}
	peer := &http.Client{Transport: a.fwd.Transport}
	req, _ := http.NewRequest("GET", b.peer.URL+"/peer/v1/instances", nil)
	req.Header.Set(ForwardedByHeader, "gw-a")
	resp, err := peer.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "internal /peer/v1/instances" {
		t.Errorf("internal: %d %s", resp.StatusCode, body)
	}
	// Not without the peer header, nor without the replicas' certificate.
	resp, err = peer.Get(b.peer.URL + "/peer/v1/instances")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("without the header: %d", resp.StatusCode)
	}
	if _, err := http.Get(b.peer.URL + "/peer/v1/instances"); err == nil {
		t.Error("without a certificate")
	}
	// The public listener does not reach it.
	if w := a.request("GET", "/peer/v1/instances", "", nil, nil); w.Body.String() != "served by gw-a" {
		t.Errorf("public listener: %s", w.Body)
	}
	<-a.seen
}

// A draining replica sends a principal it gave up to its taker, which
// still remembers the draining one as the owner (seen within the last
// few seconds): the taker reads the Lease again rather than refuse
// (421), and serves the principal.
func TestForwardToTakerWithStaleOwner(t *testing.T) {
	api := kubetest.NewSecrets(t)
	p := newPKI(t)
	a, b := newReplica(t, api, p, "gw-a"), newReplica(t, api, p, "gw-b")
	refreshAll(t, a, b)
	if w := a.request("POST", "/mcp/fs", "alice", nil, nil); w.Body.String() != "served by gw-a" {
		t.Fatalf("at a: %s", w.Body)
	}
	<-a.seen
	// b forwards alice to a, and remembers a as her owner.
	if w := b.request("POST", "/mcp/fs", "alice", nil, nil); w.Body.String() != "served by gw-a" {
		t.Fatalf("at b: %s", w.Body)
	}
	<-a.seen
	if err := a.fwd.Members.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	refreshAll(t, a, b)
	a.fwd.Owners.releaseAll()
	w := a.requestBody("/mcp/fs", "alice", "{}")
	if w.Code != http.StatusOK || w.Body.String() != "served by gw-b" {
		t.Fatalf("at a after it drained: %d %s", w.Code, w.Body)
	}
	<-b.seen
}
