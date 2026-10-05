package doctor

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// Account is the account a file must be readable for (the gateway's).
type Account struct {
	Name     string
	UID, GID uint32
	Groups   []uint32 // supplementary groups
}

// tlsReadableTypes are the SELinux types of files the gateway's domain
// (mcpgw_t) reads: its configuration (/etc/mcp-gateway), certificates
// (/etc/pki, /etc/ssl) and /usr.
var tlsReadableTypes = []string{"mcpgw_etc_t", "cert_t", "usr_t"}

// tlsExpirySoon is how long before its expiry a certificate is warned
// about.
const tlsExpirySoon = 14 * 24 * time.Hour

// TLS checks the HTTP listener's certificate and key (http.cert_file,
// http.key_file): that they load as a pair, that acct can read them
// (each directory on the way too), that the gateway's SELinux domain may
// read them (fileType, if not nil, returns a file's type), that the
// certificate has not expired and that it names the host of
// http.audience, which clients connect to. A key the gateway cannot read
// keeps it from starting; mcp-gateway --check, which runs as root, does
// not notice. It returns nothing without the HTTP listener.
func TLS(h config.HTTP, acct Account, fileType func(string) (string, error), now time.Time) []Result {
	if h.Listen == "" {
		return nil
	}
	r := Result{Check: "TLS"}
	fail := func(summary string, details ...string) []Result {
		r.Status, r.Summary, r.Details = Fail, summary, details
		return []Result{r}
	}
	for _, f := range []struct{ key, path string }{{"cert_file", h.CertFile}, {"key_file", h.KeyFile}} {
		if err := readableBy(f.path, acct); err != nil {
			return fail(fmt.Sprintf("%s %s: %v: the gateway cannot start its HTTP listener", f.key, f.path, err),
				fmt.Sprintf("let %s read it, e.g. chgrp %s %s && chmod 0640 %s, and keep it under /etc/mcp-gateway",
					acct.Name, acct.Name, f.path, f.path))
		}
		if fileType == nil {
			continue
		}
		if t, err := fileType(f.path); err == nil && !slices.Contains(tlsReadableTypes, t) {
			return fail(fmt.Sprintf("%s %s is labeled %s, which the gateway's SELinux domain may not read: it cannot start its HTTP listener", f.key, f.path, t),
				"put it under /etc/mcp-gateway (for example /etc/mcp-gateway/tls) and run restorecon -R /etc/mcp-gateway,",
				"or under /etc/pki (cert_t); the domain reads "+strings.Join(tlsReadableTypes, ", "))
		}
	}
	pair, err := tls.LoadX509KeyPair(h.CertFile, h.KeyFile)
	if err != nil {
		return fail(fmt.Sprintf("cert_file and key_file do not load: %v", err),
			"cert_file holds the certificate (PEM, the chain after it), key_file its private key (PEM)")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fail(fmt.Sprintf("cert_file %s: %v", h.CertFile, err))
	}
	switch {
	case now.After(cert.NotAfter):
		return fail(fmt.Sprintf("the certificate expired on %s: clients refuse it", cert.NotAfter.Format(time.DateOnly)),
			"replace cert_file and key_file; the gateway reloads them without a restart")
	case now.Before(cert.NotBefore):
		return fail(fmt.Sprintf("the certificate is valid only from %s: clients refuse it (is the clock right?)", cert.NotBefore.Format(time.DateOnly)))
	}
	if host := audienceHost(h.Audience); host != "" && cert.VerifyHostname(host) != nil {
		r.Status = Warn
		r.Summary = fmt.Sprintf("the certificate does not name %s, the host of http.audience: clients connecting to it refuse the certificate", host)
		r.Details = []string{"it names " + certNames(cert) + "; issue one whose subjectAltName includes " + host}
		return []Result{r}
	}
	if left := cert.NotAfter.Sub(now); left < tlsExpirySoon {
		r.Status = Warn
		r.Summary = fmt.Sprintf("the certificate expires on %s, in %d days", cert.NotAfter.Format(time.DateOnly), int(left.Hours()/24))
		r.Details = []string{"replace cert_file and key_file before; the gateway reloads them without a restart"}
		return []Result{r}
	}
	r.Status = OK
	r.Summary = fmt.Sprintf("certificate for %s, valid until %s", certNames(cert), cert.NotAfter.Format(time.DateOnly))
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil {
		r.Details = []string{"self-signed: clients must trust it (their CA store, or e.g. NODE_EXTRA_CA_CERTS)"}
	}
	return []Result{r}
}

// audienceHost returns the host of an audience URL, "" if there is none.
func audienceHost(audience string) string {
	u, err := url.Parse(audience)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// certNames lists the names and addresses a certificate is for.
func certNames(c *x509.Certificate) string {
	names := slices.Clone(c.DNSNames)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		return "no host (no subjectAltName; CN " + c.Subject.CommonName + " does not count)"
	}
	return strings.Join(names, ", ")
}

// readableBy reports why acct cannot read path (each directory on the way
// must let it search), or nil.
func readableBy(path string, acct Account) error {
	if path == "" {
		return fmt.Errorf("not set")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return err
	}
	if !permits(fi, acct, 4) {
		return fmt.Errorf("not readable by %s (%s)", acct.Name, describe(fi))
	}
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		di, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if !permits(di, acct, 1) {
			return fmt.Errorf("%s cannot enter %s (%s)", acct.Name, dir, describe(di))
		}
		if dir == "/" || dir == filepath.Dir(dir) {
			return nil
		}
	}
}

// permits reports whether acct has bit (4 read, 1 execute/search) on fi.
func permits(fi os.FileInfo, acct Account, bit os.FileMode) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	mode := fi.Mode().Perm()
	switch {
	case acct.UID == 0:
		return true
	case st.Uid == acct.UID:
		return mode&(bit<<6) != 0
	case st.Gid == acct.GID || slices.Contains(acct.Groups, st.Gid):
		return mode&(bit<<3) != 0
	}
	return mode&bit != 0
}

// describe says who owns fi and its mode, for a message.
func describe(fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fi.Mode().String()
	}
	return fmt.Sprintf("owner %d, group %d, mode %04o", st.Uid, st.Gid, fi.Mode().Perm())
}

// listenPort returns the port of a listen address (":8443",
// "host:8443") and whether it listens on loopback only.
func listenPort(listen string) (port string, loopback bool) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", false
	}
	if host == "localhost" {
		return port, true
	}
	ip := net.ParseIP(host)
	return port, ip != nil && ip.IsLoopback()
}
