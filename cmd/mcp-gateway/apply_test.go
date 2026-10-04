package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/notify"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/router"
)

// writeCert writes a self-signed certificate for cn and its key to dir.
func writeCert(t *testing.T, dir, cn string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, cn+".pem"), filepath.Join(dir, cn+".key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func servedName(t *testing.T, c *certStore) string {
	t.Helper()
	cert, err := c.getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestApplyConfig(t *testing.T) {
	dir := t.TempDir()
	oldCert, oldKey := writeCert(t, dir, "old.example")
	newCert, newKey := writeCert(t, dir, "new.example")
	running := &config.Gateway{}
	running.HTTP = config.HTTP{Listen: ":8443", CertFile: oldCert, KeyFile: oldKey}
	running.Approvals.ControlSocket = "/run/x.sock"

	certs := &certStore{}
	if err := certs.load(oldCert, oldKey); err != nil {
		t.Fatal(err)
	}
	mail, err := notify.NewEmail(config.Email{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := broker.New(broker.Options{Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	opa := pep.NewOPA("/nonexistent", time.Second)
	r := &router.Router{Log: slog.New(slog.DiscardHandler)}
	log := slog.New(slog.DiscardHandler)

	next := *running
	next.HTTP.CertFile, next.HTTP.KeyFile = newCert, newKey
	next.Notifications.Email = config.Email{SMTP: "localhost:25", From: "gw@x", To: "{user}"}
	next.Approvals.URLTemplate = "https://gw/{id}"
	if err := applyConfig(log, &next, running, certs, mail, b, opa, r); err != nil {
		t.Fatal(err)
	}
	if got := servedName(t, certs); got != "new.example" {
		t.Fatalf("certificate %q", got)
	}
	if !mail.Enabled() || b.ApprovalURL("a") != "https://gw/a" {
		t.Fatal("mail or approvals not applied")
	}

	// A certificate that does not load changes nothing at all.
	bad := next
	bad.HTTP.CertFile = filepath.Join(dir, "missing.pem")
	bad.Notifications.Email = config.Email{}
	bad.Approvals.URLTemplate = ""
	if err := applyConfig(log, &bad, running, certs, mail, b, opa, r); err == nil {
		t.Fatal("missing certificate accepted")
	}
	if servedName(t, certs) != "new.example" || !mail.Enabled() || b.ApprovalURL("a") == "" {
		t.Fatal("a failed reload changed the configuration")
	}

	// A password file that cannot be read changes nothing either.
	bad = next
	bad.HTTP.CertFile, bad.HTTP.KeyFile = oldCert, oldKey
	bad.Notifications.Email.Username, bad.Notifications.Email.PasswordFile = "gw", filepath.Join(dir, "missing")
	if err := applyConfig(log, &bad, running, certs, mail, b, opa, r); err == nil {
		t.Fatal("missing password file accepted")
	}
	if servedName(t, certs) != "new.example" {
		t.Fatal("certificate changed although the reload failed")
	}
}
