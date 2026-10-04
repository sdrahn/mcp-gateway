package main

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/oauth/oauthtest"
)

// serveHTTP is privsrv's other mode (privsrv -http ADDR): an MCP server
// that speaks Streamable HTTP, for the VM test of servers defined with
// url (cmd/mcp-http-connector).
func serveHTTP(addr string) error {
	return http.ListenAndServe(addr, mcpHandler())
}

// serveHTTPS is serveHTTP over TLS (privsrv -https ADDR CERTFILE), with
// a self-signed certificate for mcp.vmtest.
func serveHTTPS(addr, certFile string) error {
	cert, err := selfSigned("mcp.vmtest", certFile)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: addr, Handler: mcpHandler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	return srv.ListenAndServeTLS("", "")
}

// serveOAuth is an MCP server that needs each user to sign in, with its
// authorization server (internal/oauth/oauthtest), over TLS for
// https://auth.vmtest (privsrv -oauth ADDR CERTFILE): the authorization
// endpoint signs in the account its "login" parameter names at once.
func serveOAuth(addr, certFile string) error {
	cert, err := selfSigned("auth.vmtest", certFile)
	if err != nil {
		return err
	}
	as := &oauthtest.Server{Base: "https://auth.vmtest", AccountParam: "login"}
	srv := &http.Server{Addr: addr, Handler: as, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	return srv.ListenAndServeTLS("", "")
}

// selfSigned makes a certificate for name and writes it to certFile,
// which the test adds to the system's trusted certificates.
func selfSigned(name, certFile string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// serveProxy is an HTTP proxy that only tunnels (privsrv -proxy ADDR),
// and only for Proxy-Authorization: Basic vmtest:proxypass; it logs each
// tunnel to stderr.
func serveProxy(addr string) error {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("vmtest:proxypass"))
	return http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Proxy-Authorization") != want {
			w.Header().Set("Proxy-Authenticate", `Basic realm="vmtest"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		up, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		fmt.Fprintln(os.Stderr, "privsrv proxy: CONNECT", r.Host)
		w.WriteHeader(http.StatusOK)
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		go func() { _, _ = io.Copy(up, rw); _ = up.Close() }()
		_, _ = io.Copy(conn, up)
		_ = conn.Close()
	}))
}

// mcpHandler is the server: its one tool, whoami, answers with the
// Authorization and Proxy-Authorization headers it got, so the test sees
// the credential arrive and the proxy's stay with the proxy; tools/call
// answers on an event stream, the rest as JSON.
func mcpHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var m message
		if json.Unmarshal(body, &m) != nil || len(m.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var res any
		switch m.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "vmtest")
			res = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "privsrv-http"}}
		case "tools/list":
			res = map[string]any{"tools": []any{map[string]any{"name": "whoami", "inputSchema": schema()}}}
		case "tools/call":
			if r.Header.Get("Mcp-Session-Id") != "vmtest" {
				http.Error(w, "no session", http.StatusBadRequest)
				return
			}
			out, _ := json.Marshal(message{JSONRPC: "2.0", ID: m.ID, Result: map[string]any{
				"content": []any{map[string]any{"type": "text", "text": "authorization: " + r.Header.Get("Authorization") +
					"; proxy-authorization: " + cmp.Or(r.Header.Get("Proxy-Authorization"), "(none)")}}}})
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "id: 1\ndata: %s\n\n", out)
			return
		default:
			res = map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(message{JSONRPC: "2.0", ID: m.ID, Result: res})
	})
}
