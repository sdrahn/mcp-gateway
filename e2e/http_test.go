package e2e

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// idp is a minimal OIDC provider: discovery document and JWKS.
type idp struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newIdP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i := &idp{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": i.srv.URL, "jwks_uri": i.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		enc := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig",
			"n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	i.srv = httptest.NewServer(mux)
	t.Cleanup(i.srv.Close)
	return i
}

func (i *idp) token(t *testing.T, sub, aud string) string {
	t.Helper()
	return i.tokenWith(t, sub, aud, nil)
}

// tokenWith issues a token with extra claims.
func (i *idp) tokenWith(t *testing.T, sub, aud string, extra jwt.MapClaims) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": i.srv.URL, "aud": aud, "sub": sub, "scope": "mcp",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(i.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// selfSigned writes a certificate for 127.0.0.1 and returns a pool
// trusting it.
func selfSigned(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mcp-gateway-test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeFile(t, certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeFile(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// remote is an MCP client speaking Streamable HTTP.
type remote struct {
	t       *testing.T
	client  *http.Client
	url     string
	token   string
	session string
}

func (c *remote) post(body any, sse bool) *http.Response {
	c.t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		c.t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, c.url, strings.NewReader(string(b)))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if sse {
		req.Header.Set("Accept", "application/json, text/event-stream")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

// call posts a request and decodes a JSON response.
func (c *remote) call(id int, method string, params any) msg {
	c.t.Helper()
	resp := c.post(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}, false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		c.t.Fatalf("%s: HTTP %d", method, resp.StatusCode)
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); c.session == "" {
		c.session = sid
	}
	var m msg
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		c.t.Fatal(err)
	}
	return m
}

func sse(t *testing.T, resp *http.Response) <-chan msg {
	out := make(chan msg, 8)
	go func() {
		defer close(out)
		defer func() { _ = resp.Body.Close() }()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64<<10), 16<<20)
		for sc.Scan() {
			if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				var m msg
				if json.Unmarshal([]byte(data), &m) == nil {
					out <- m
				}
			}
		}
	}()
	return out
}

func nextEvent(t *testing.T, ch <-chan msg) msg {
	t.Helper()
	select {
	case m, ok := <-ch:
		if !ok {
			t.Fatal("stream ended")
		}
		return m
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
	return msg{}
}

func TestRemoteHTTP(t *testing.T) {
	home, err := os.MkdirTemp("", "mcpgw-remote")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	writeFile(t, filepath.Join(home, "hello.txt"), "hello remote")

	provider := newIdP(t)
	certFile, keyFile, pool := selfSigned(t, home)
	port := freePort(t)
	audience := fmt.Sprintf("https://127.0.0.1:%d/mcp", port)

	// The remote principal is not mapped to a local account; policy binds
	// its token subject.
	rbac := fmt.Sprintf(`{
	  "roles": {"developer": {"permissions": [
	    {"server": "fs", "tool": "read_*"},
	    {"server": "fs", "tool": "write_file", "require_approval": true,
	     "approval_channel": "form", "args": {"path": %q}}
	  ]}},
	  "bindings": {"groups": {}, "users": {"u-remote": ["developer"]}}
	}`, "^"+regexp.QuoteMeta(home)+"/")
	e := setup(t, rbac, map[string]string{"fs": home}, fmt.Sprintf(`http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s
  scopes: [mcp]
`, port, certFile, keyFile, provider.srv.URL, audience))

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	// Wait for the HTTPS listener.
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/.well-known/oauth-protected-resource/mcp", port))
		if err == nil {
			var meta map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&meta)
			_ = resp.Body.Close()
			if meta["resource"] != audience {
				t.Fatalf("metadata %v", meta)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway HTTPS not up: %v\n%s", err, e.gwLogs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	c := &remote{t: t, client: client, url: audience + "/fs"}
	init := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{"elicitation": map[string]any{}},
		"clientInfo":      map[string]any{"name": "remote-e2e"},
	}}

	t.Run("unauthenticated", func(t *testing.T) {
		resp := c.post(init, false)
		_ = resp.Body.Close()
		if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
			t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		bad := &remote{t: t, client: client, url: c.url, token: provider.token(t, "u-remote", "https://elsewhere/mcp")}
		resp := bad.post(init, false)
		_ = resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})

	c.token = provider.token(t, "u-remote", audience)
	t.Run("initialize", func(t *testing.T) {
		m := c.call(1, "initialize", init["params"])
		if !strings.Contains(string(m.Result), "mcp-fs-demo") || c.session == "" {
			t.Fatalf("initialize: %s (session %q)", m.Result, c.session)
		}
		resp := c.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, false)
		_ = resp.Body.Close()
		if resp.StatusCode != 202 {
			t.Fatalf("initialized: %d", resp.StatusCode)
		}
	})

	t.Run("tools/list filtered", func(t *testing.T) {
		if got := listNames(t, c.call(2, "tools/list", map[string]any{}), "tools", "name"); got != "read_file,write_file" {
			t.Fatalf("tools = %s", got)
		}
	})

	t.Run("allowed read", func(t *testing.T) {
		text, isErr := toolResult(t, c.call(3, "tools/call", map[string]any{"name": "read_file", "arguments": map[string]any{"path": "hello.txt"}}))
		if isErr || text != "hello remote" {
			t.Fatalf("got %q %v", text, isErr)
		}
	})

	t.Run("approval over SSE", func(t *testing.T) {
		target := filepath.Join(home, "remote.txt")
		resp := c.post(map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{
			"name": "write_file", "arguments": map[string]any{"path": target, "content": "from afar"},
		}}, true)
		events := sse(t, resp)
		el := nextEvent(t, events)
		if el.Method != "elicitation/create" {
			t.Fatalf("want elicitation, got %+v", el)
		}
		ack := c.post(map[string]any{"jsonrpc": "2.0", "id": el.ID, "result": map[string]any{
			"action": "accept", "content": map[string]any{"scope": "once"},
		}}, false)
		_ = ack.Body.Close()
		if ack.StatusCode != 202 {
			t.Fatalf("answer: %d", ack.StatusCode)
		}
		text, isErr := toolResult(t, nextEvent(t, events))
		if isErr || !strings.HasPrefix(text, "wrote") {
			t.Fatalf("got %q %v", text, isErr)
		}
		if b, err := os.ReadFile(target); err != nil || string(b) != "from afar" {
			t.Fatalf("file %q %v", b, err)
		}
	})

	t.Run("other principal cannot use the session", func(t *testing.T) {
		mallory := &remote{t: t, client: client, url: c.url, session: c.session, token: provider.token(t, "u-mallory", audience)}
		resp := mallory.post(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "tools/list"}, false)
		_ = resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})

	t.Run("audit shows the remote principal", func(t *testing.T) {
		if !strings.Contains(e.gwLogs.String(), `"sub":"u-remote"`) {
			t.Fatal("no audit record for u-remote")
		}
	})

	t.Run("delete session", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, c.url, nil)
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Mcp-Session-Id", c.session)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 204 {
			t.Fatalf("delete: %d", resp.StatusCode)
		}
	})
}
