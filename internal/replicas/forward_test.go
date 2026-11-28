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
