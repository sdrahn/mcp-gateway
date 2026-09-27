package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// clientCA creates a CA (written to dir/client-ca.pem) and returns a
// function issuing client certificates from it.
func clientCA(t *testing.T, dir string) (caFile string, issue func(cn string) tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "mcp-gateway-test-client-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	caFile = filepath.Join(dir, "client-ca.pem")
	writeFile(t, caFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})))
	serial := int64(200)
	return caFile, func(cn string) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial++
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
}

func thumbprint(c tls.Certificate) string {
	sum := sha256.Sum256(c.Certificate[0])
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestRemoteMTLS(t *testing.T) {
	home, err := os.MkdirTemp("", "mcpgw-mtls")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	writeFile(t, filepath.Join(home, "hello.txt"), "hello mtls")

	provider := newIdP(t)
	certFile, keyFile, pool := selfSigned(t, home)
	caFile, issue := clientCA(t, home)
	port := freePort(t)
	audience := fmt.Sprintf("https://127.0.0.1:%d/mcp", port)

	// Reading needs a client certificate.
	rbac := `{
	  "roles": {"agent": {"permissions": [
	    {"server": "fs", "tool": "read_*", "require_client_cert": true}
	  ]}},
	  "bindings": {"groups": {}, "users": {"u-agent": ["agent"]}}
	}`
	setup(t, rbac, map[string]string{"fs": home}, fmt.Sprintf(`http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s
  client_ca_file: %s
  client_auth: optional
`, port, certFile, keyFile, provider.srv.URL, audience, caFile))

	agentCert, otherCert := issue("agent-1"), issue("agent-2")
	clientWith := func(certs ...tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: certs}}}
	}
	withCert, noCert := clientWith(agentCert), clientWith()

	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := noCert.Get(fmt.Sprintf("https://127.0.0.1:%d/.well-known/oauth-protected-resource/mcp", port))
		if err == nil {
			var meta map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&meta)
			_ = resp.Body.Close()
			if meta["tls_client_certificate_bound_access_tokens"] != true {
				t.Fatalf("metadata %v", meta)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway HTTPS not up: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	init := map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "mtls-e2e"}}
	bound := func(c tls.Certificate) string {
		return provider.tokenWith(t, "u-agent", audience, jwt.MapClaims{"cnf": map[string]any{"x5t#S256": thumbprint(c)}})
	}
	status := func(client *http.Client, token string) int {
		c := &remote{t: t, client: client, url: audience + "/fs", token: token}
		resp := c.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": init}, false)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("bound token without certificate", func(t *testing.T) {
		if got := status(noCert, bound(agentCert)); got != 401 {
			t.Fatalf("got %d", got)
		}
	})
	t.Run("bound token with another certificate", func(t *testing.T) {
		if got := status(clientWith(otherCert), bound(agentCert)); got != 401 {
			t.Fatalf("got %d", got)
		}
	})
	t.Run("certificate from an unknown CA", func(t *testing.T) {
		_, rogue := clientCA(t, t.TempDir())
		c := &remote{t: t, client: clientWith(rogue("agent-1")), url: audience + "/fs", token: provider.token(t, "u-agent", audience)}
		body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
		req, _ := http.NewRequest(http.MethodPost, c.url, body)
		if resp, err := c.client.Do(req); err == nil {
			_ = resp.Body.Close()
			t.Fatalf("handshake accepted: %d", resp.StatusCode)
		}
	})

	read := func(t *testing.T, client *http.Client, token string) (string, bool) {
		c := &remote{t: t, client: client, url: audience + "/fs", token: token}
		c.call(1, "initialize", init)
		resp := c.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, false)
		_ = resp.Body.Close()
		return toolResult(t, c.call(2, "tools/call", map[string]any{"name": "read_file", "arguments": map[string]any{"path": "hello.txt"}}))
	}
	t.Run("bound token with its certificate", func(t *testing.T) {
		if text, isErr := read(t, withCert, bound(agentCert)); isErr || text != "hello mtls" {
			t.Fatalf("got %q %v", text, isErr)
		}
	})
	t.Run("policy requires the certificate", func(t *testing.T) {
		if text, isErr := read(t, noCert, provider.token(t, "u-agent", audience)); !isErr || !strings.Contains(text, "no matching permission") {
			t.Fatalf("got %q %v", text, isErr)
		}
	})
}
