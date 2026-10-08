// Package egress builds the HTTP clients of the programs that reach
// servers outside the host for the gateway (mcp-http-connector,
// mcp-oauth-helper): they connect only to the addresses the gateway
// resolved for them (-resolve), or through the proxy a definition names,
// never one from the environment, and read secrets for their headers
// from $CREDENTIALS_DIRECTORY.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/landlock"
)

// CredentialRef is a reference to a credential in a header value,
// ${CREDENTIAL:name}.
var CredentialRef = regexp.MustCompile(`\$\{CREDENTIAL:([A-Za-z0-9_][A-Za-z0-9_.-]{0,63})\}`)

// ReadCredential reads the credential name from credDir, without a
// trailing line break.
func ReadCredential(credDir, name string) (string, error) {
	if credDir == "" {
		return "", fmt.Errorf("credential %s: no $CREDENTIALS_DIRECTORY", name)
	}
	if strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return "", fmt.Errorf("credential %q: not a credential name", name)
	}
	b, err := os.ReadFile(filepath.Join(credDir, name))
	if err != nil {
		return "", fmt.Errorf("credential %s: %w", name, err)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// ParseHeaders parses "Name: value" lines of flag, replacing
// ${CREDENTIAL:name} by the credential read from credDir.
func ParseHeaders(flag string, lines []string, credDir string) (http.Header, error) {
	h := http.Header{}
	for _, line := range lines {
		k, v, ok := strings.Cut(line, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" {
			return nil, fmt.Errorf("%s: want \"Name: value\", got %q", flag, line)
		}
		var credErr error
		v = CredentialRef.ReplaceAllStringFunc(v, func(ref string) string {
			s, err := ReadCredential(credDir, CredentialRef.FindStringSubmatch(ref)[1])
			if err != nil {
				credErr = fmt.Errorf("%s %s: %w", flag, k, err)
			}
			return s
		})
		if credErr != nil {
			return nil, credErr
		}
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("%s %s: the value has a line break", flag, k)
		}
		h.Add(k, v)
	}
	return h, nil
}

// ParseProxy parses a -proxy URL: http:// or https://, a host, no user
// information (credentials go into proxy headers).
func ParseProxy(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("-proxy: want http://host:port or https://host:port, got %q", s)
	}
	return u, nil
}

// Options configure Transport.
type Options struct {
	// Resolve are "host:port:address" entries: connections to host:port
	// go to address instead (the program's domain cannot resolve names).
	Resolve []string
	// Proxy, if set, is the proxy to tunnel through; ProxyHeader is sent
	// with each CONNECT.
	Proxy       *url.URL
	ProxyHeader http.Header
}

// Transport returns an HTTP transport that dials the addresses of
// o.Resolve, or o.Proxy; it never takes a proxy from the environment.
func Transport(o Options) (*http.Transport, error) {
	dialTo := map[string]string{} // host:port to address:port
	for _, r := range o.Resolve {
		parts := strings.SplitN(r, ":", 3)
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || net.ParseIP(strings.Trim(parts[2], "[]")) == nil {
			return nil, fmt.Errorf("-resolve: want host:port:address, got %q", r)
		}
		dialTo[net.JoinHostPort(parts[0], parts[1])] = net.JoinHostPort(strings.Trim(parts[2], "[]"), parts[1])
	}
	if o.Proxy == nil && len(o.ProxyHeader) > 0 {
		return nil, errors.New("-proxy-header: only with -proxy")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	t := &http.Transport{
		Proxy:              nil,
		ProxyConnectHeader: o.ProxyHeader,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if to, ok := dialTo[address]; ok {
				address = to
			}
			return dialer.DialContext(ctx, network, address)
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   8,
	}
	if o.Proxy != nil {
		t.Proxy = http.ProxyURL(o.Proxy)
	}
	return t, nil
}

// Loopback reports whether host is the local host (localhost or a
// loopback address), the only host plain http:// may reach.
func Loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Landlock returns the trees and ports of a program that connects for
// the gateway (docs/architecture.md D19): beyond landlock.Base, the CA
// certificates and resolver configuration (landlock.Network) and its
// credentials; TCP to the ports it may connect to: o.Proxy's when it
// tunnels, else those of target and of o.Resolve, and 53 for a name it
// resolves itself. Without any port known (no target, resolve or
// proxy), TCP is left to the unit.
func Landlock(o Options, target *url.URL, credDir string) landlock.Rules {
	r := landlock.Rules{Read: slices.Clone(landlock.Network)}
	if credDir != "" {
		r.Read = append(r.Read, credDir)
	}
	var ports []int
	add := func(port string) {
		if n, err := strconv.Atoi(port); err == nil && n > 0 && n < 65536 && !slices.Contains(ports, n) {
			ports = append(ports, n)
		}
	}
	switch {
	case o.Proxy != nil:
		add(urlPort(o.Proxy))
	default:
		if target != nil {
			add(urlPort(target))
		}
		for _, e := range o.Resolve {
			if parts := strings.SplitN(e, ":", 3); len(parts) == 3 {
				add(parts[1])
			}
		}
	}
	if len(ports) > 0 {
		add("53")
		slices.Sort(ports)
		r.TCPConnect = ports
	}
	return r
}

// urlPort is the port of u, or its scheme's.
func urlPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}
