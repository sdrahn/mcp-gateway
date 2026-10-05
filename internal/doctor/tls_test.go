package doctor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// writePair writes a self-signed certificate for names, valid from
// notBefore to notAfter, and its key into dir.
func writePair(t *testing.T, dir string, names []string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gw"},
		DNSNames: names, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, keyFile
}

func TestTLS(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	cert, key := writePair(t, dir, []string{"gw.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	h := config.HTTP{Listen: ":8443", CertFile: cert, KeyFile: key, Audience: "https://gw.example.com:8443/mcp"}
	me := Account{Name: "me", UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	label := func(t string) func(string) (string, error) {
		return func(string) (string, error) { return t, nil }
	}

	if rs := TLS(config.HTTP{}, me, nil, now); len(rs) != 0 {
		t.Errorf("without the listener: %+v", rs)
	}
	rs := TLS(h, me, label("mcpgw_etc_t"), now)
	if len(rs) != 1 || rs[0].Status != OK || !strings.Contains(rs[0].Summary, "gw.example.com") ||
		len(rs[0].Details) != 1 || !strings.Contains(rs[0].Details[0], "self-signed") {
		t.Fatalf("good pair: %+v", rs)
	}

	// Another account: the key (0600) and the directory (0700) are ours.
	other := Account{Name: "mcp-gateway", UID: 4242, GID: 4242}
	if rs := TLS(h, other, nil, now); rs[0].Status != Fail || !strings.Contains(rs[0].Summary, "mcp-gateway") ||
		!strings.Contains(rs[0].Details[0], "chgrp mcp-gateway") {
		t.Errorf("unreadable: %+v", rs)
	}
	// A label the gateway's domain may not read.
	if rs := TLS(h, me, label("admin_home_t"), now); rs[0].Status != Fail || !strings.Contains(rs[0].Summary, "admin_home_t") {
		t.Errorf("label: %+v", rs)
	}
	// Another host.
	h2 := h
	h2.Audience = "https://dreadnought.example.com:8443/mcp"
	if rs := TLS(h2, me, nil, now); rs[0].Status != Warn || !strings.Contains(rs[0].Summary, "does not name dreadnought.example.com") {
		t.Errorf("host: %+v", rs)
	}
	// Expired, and expiring soon.
	if rs := TLS(h, me, nil, now.Add(100*24*time.Hour)); rs[0].Status != Fail || !strings.Contains(rs[0].Summary, "expired") {
		t.Errorf("expired: %+v", rs)
	}
	if rs := TLS(h, me, nil, now.Add(80*24*time.Hour)); rs[0].Status != Warn || !strings.Contains(rs[0].Summary, "expires") {
		t.Errorf("expiring: %+v", rs)
	}
	// A key that is not the certificate's.
	_, otherKey := writePair(t, t.TempDir(), []string{"x"}, now.Add(-time.Hour), now.Add(time.Hour))
	h3 := h
	h3.KeyFile = otherKey
	if rs := TLS(h3, me, nil, now); rs[0].Status != Fail || !strings.Contains(rs[0].Summary, "do not load") {
		t.Errorf("mismatched key: %+v", rs)
	}
	// A missing file.
	h4 := h
	h4.CertFile = filepath.Join(dir, "missing.pem")
	if rs := TLS(h4, me, nil, now); rs[0].Status != Fail || !strings.Contains(rs[0].Summary, "cert_file") {
		t.Errorf("missing: %+v", rs)
	}
}
