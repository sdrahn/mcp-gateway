package main

// approvals and grants against a gateway on another host (--gateway URL;
// docs/architecture.md, section 11, step 39 stage D): the approver signs
// in with the identity provider the gateway names, with the OAuth device
// flow (RFC 8628: a code to confirm in any browser, so the host needs
// none), as the gateway's command-line client. The ID token and refresh
// token are kept per gateway in a file only the user can read; the ID
// token is the bearer token of the gateway's approval API, which answers
// as the control API does.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// remoteSession is a sign-in to a gateway's approval API, as its file
// keeps it.
type remoteSession struct {
	Gateway       string `json:"gateway"` // origin, https://host:port
	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id"`
	TokenEndpoint string `json:"token_endpoint"`
	IDToken       string `json:"id_token"`
	RefreshToken  string `json:"refresh_token,omitempty"`
}

// remoteHTTP reaches gateways and identity providers: the system's CA
// certificates, the environment's proxy.
var remoteHTTP = &http.Client{Timeout: 30 * time.Second}

// gatewayOrigin is the origin of a --gateway URL (https://host[:port],
// or a URL there, e.g. its MCP URL).
func gatewayOrigin(s string) (string, error) {
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("--gateway %q: not a URL", s)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("--gateway %q: the approval API is on the gateway's HTTPS listener", s)
	}
	return "https://" + u.Host, nil
}

// sessionFile is where the sign-in to origin is kept:
// $XDG_CONFIG_HOME/mcp-gateway-admin/gateways/<host_port>.json.
func sessionFile(origin string) (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	host := strings.TrimPrefix(origin, "https://")
	name := strings.Map(func(r rune) rune {
		if r == '.' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return '_'
	}, host)
	return filepath.Join(dir, "mcp-gateway-admin", "gateways", name+".json"), nil
}

// loadSession reads the sign-in to origin. A file others may read is
// refused: it holds the user's tokens.
func loadSession(origin string) (*remoteSession, string, error) {
	path, err := sessionFile(origin)
	if err != nil {
		return nil, "", err
	}
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, path, fmt.Errorf("not signed in to %s: mcp-gateway-admin approvals login --gateway %s", origin, origin)
	}
	if err != nil {
		return nil, path, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, path, fmt.Errorf("%s may be read by others (mode %04o), and it holds your sign-in: chmod 600 %s, or sign in again", path, fi.Mode().Perm(), path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, path, err
	}
	var s remoteSession
	if err := json.Unmarshal(data, &s); err != nil || s.IDToken == "" || s.Gateway != origin {
		return nil, path, fmt.Errorf("%s is not a sign-in to %s: mcp-gateway-admin approvals login --gateway %s", path, origin, origin)
	}
	return &s, path, nil
}

// save writes s to path, readable by the user only.
func (s *remoteSession) save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".session-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// tokenExpiry is when an ID token expires, from its exp claim (read, not
// verified: the gateway verifies it); zero if it has none.
func tokenExpiry(tok string) time.Time {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var c struct {
		Exp float64 `json:"exp"`
	}
	if json.Unmarshal(b, &c) != nil || c.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(int64(c.Exp), 0)
}

// fresh returns a current ID token: the kept one, or a new one for the
// refresh token when it expires within a minute (saved to path).
func (s *remoteSession) fresh(ctx context.Context, path string) (string, error) {
	if exp := tokenExpiry(s.IDToken); exp.IsZero() || time.Until(exp) > time.Minute {
		return s.IDToken, nil
	}
	again := fmt.Errorf("your sign-in to %s has expired: mcp-gateway-admin approvals login --gateway %s", s.Gateway, s.Gateway)
	if s.RefreshToken == "" {
		return "", again
	}
	t, err := tokenRequest(ctx, s.TokenEndpoint, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {s.RefreshToken}, "client_id": {s.ClientID},
	})
	if err != nil || t.IDToken == "" {
		return "", again
	}
	s.IDToken = t.IDToken
	if t.RefreshToken != "" {
		s.RefreshToken = t.RefreshToken
	}
	if err := s.save(path); err != nil {
		return "", err
	}
	return s.IDToken, nil
}

// tokens is a token endpoint's answer.
type tokens struct {
	IDToken          string `json:"id_token"`
	RefreshToken     string `json:"refresh_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func tokenRequest(ctx context.Context, endpoint string, form url.Values) (tokens, error) {
	var t tokens
	err := postForm(ctx, endpoint, form, &t)
	if err == nil && t.Error != "" {
		err = oauthError(t.Error, t.ErrorDescription)
	}
	return t, err
}

func oauthError(code, desc string) error {
	if desc != "" {
		return fmt.Errorf("%s: %s", code, desc)
	}
	return errors.New(code)
}

// postForm posts form to endpoint and decodes the JSON answer into v,
// error answers too (OAuth errors are JSON with status 400).
func postForm(ctx context.Context, endpoint string, form url.Values, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := remoteHTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %s", endpoint, resp.Status)
	}
	return nil
}

func getJSON(ctx context.Context, u string, v any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := remoteHTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, errors.New(apiMessage(resp.StatusCode, data))
	}
	return resp.StatusCode, json.Unmarshal(data, v)
}

// remoteLogin signs in to the gateway at origin with the device flow:
// it asks the gateway for its identity provider and client, starts the
// device authorization there, prints where to confirm, and waits for the
// tokens.
func remoteLogin(ctx context.Context, origin string, stdout, stderr io.Writer) int {
	var client struct {
		Issuer   string `json:"issuer"`
		ClientID string `json:"client_id"`
	}
	if _, err := getJSON(ctx, origin+"/approvals/api/v1/client", &client); err != nil {
		sayf(stderr, "mcp-gateway-admin: %s: %v", origin, err)
		return exitUnreachable
	}
	var md struct {
		Issuer              string `json:"issuer"`
		DeviceAuthorization string `json:"device_authorization_endpoint"`
		TokenEndpoint       string `json:"token_endpoint"`
	}
	discovery := strings.TrimSuffix(client.Issuer, "/") + "/.well-known/openid-configuration"
	if _, err := getJSON(ctx, discovery, &md); err != nil {
		sayf(stderr, "mcp-gateway-admin: the identity provider %s: %v", client.Issuer, err)
		return exitUnreachable
	}
	switch {
	case md.Issuer != client.Issuer:
		sayf(stderr, "mcp-gateway-admin: the identity provider calls itself %q, the gateway names %q", md.Issuer, client.Issuer)
		return exitRefused
	case md.DeviceAuthorization == "" || md.TokenEndpoint == "":
		sayf(stderr, "mcp-gateway-admin: the identity provider %s offers no device authorization (device_authorization_endpoint)", client.Issuer)
		return exitRefused
	}
	var da struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
		Error                   string `json:"error"`
		ErrorDescription        string `json:"error_description"`
	}
	if err := postForm(ctx, md.DeviceAuthorization, url.Values{"client_id": {client.ClientID}, "scope": {"openid"}}, &da); err != nil || da.Error != "" {
		if err == nil {
			err = oauthError(da.Error, da.ErrorDescription)
		}
		sayf(stderr, "mcp-gateway-admin: device authorization at %s: %v", client.Issuer, err)
		return exitRefused
	}
	where := da.VerificationURI
	if da.VerificationURIComplete != "" {
		where = da.VerificationURIComplete
	}
	sayf(stderr, "To sign in to %s, open %s in a browser and confirm the code %s.", origin, where, da.UserCode)
	if da.ExpiresIn <= 0 {
		da.ExpiresIn = 600
	}
	interval := time.Duration(max(da.Interval, 1)) * time.Second
	deadline := time.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			say(stderr, "mcp-gateway-admin: not signed in")
			return exitRefused
		case <-time.After(interval):
		}
		t, err := tokenRequest(ctx, md.TokenEndpoint, url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {da.DeviceCode}, "client_id": {client.ClientID},
		})
		switch {
		case t.Error == "authorization_pending":
			continue
		case t.Error == "slow_down":
			interval += 5 * time.Second
			continue
		case err != nil:
			sayf(stderr, "mcp-gateway-admin: signing in: %v", err)
			return exitRefused
		case t.IDToken == "":
			say(stderr, "mcp-gateway-admin: signing in: the identity provider sent no ID token (is openid among the client's scopes?)")
			return exitRefused
		}
		s := &remoteSession{Gateway: origin, Issuer: client.Issuer, ClientID: client.ClientID, TokenEndpoint: md.TokenEndpoint,
			IDToken: t.IDToken, RefreshToken: t.RefreshToken}
		path, err := sessionFile(origin)
		if err == nil {
			err = s.save(path)
		}
		if err != nil {
			say(stderr, "mcp-gateway-admin: keeping the sign-in:", err)
			return 1
		}
		cc := s.client(path)
		var who struct {
			Name   string   `json:"name"`
			Groups []string `json:"groups"`
		}
		if _, rc := cc.list(stderr, "/v1/whoami", &who); rc != 0 {
			return rc
		}
		groups := ""
		if len(who.Groups) > 0 {
			groups = " (groups " + strings.Join(who.Groups, ", ") + ")"
		}
		sayf(stdout, "signed in to %s as %s%s; kept in %s", origin, who.Name, groups, path)
		return 0
	}
	say(stderr, "mcp-gateway-admin: the code expired before it was confirmed")
	return exitRefused
}

// remoteLogout forgets the sign-in to origin.
func remoteLogout(origin string, stdout, stderr io.Writer) int {
	path, err := sessionFile(origin)
	if err != nil {
		say(stderr, "mcp-gateway-admin:", err)
		return 1
	}
	switch err := os.Remove(path); {
	case errors.Is(err, os.ErrNotExist):
		sayf(stdout, "not signed in to %s", origin)
	case err != nil:
		say(stderr, "mcp-gateway-admin:", err)
		return 1
	default:
		sayf(stdout, "signed out of %s (removed %s)", origin, path)
	}
	return 0
}

// bearer adds the session's current ID token to each request.
type bearer struct {
	s    *remoteSession
	path string
	next http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	tok, err := b.s.fresh(r.Context(), b.path)
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	return b.next.RoundTrip(r)
}

// client is a control client for the gateway's approval API.
func (s *remoteSession) client(path string) *controlClient {
	next := remoteHTTP.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	return &controlClient{base: s.Gateway + "/approvals/api", remote: s.Gateway,
		http: &http.Client{Timeout: 30 * time.Second, Transport: bearer{s: s, path: path, next: next}}}
}

// newRemoteClient is the control client for --gateway URL, signed in.
func newRemoteClient(gateway string) (*controlClient, error) {
	origin, err := gatewayOrigin(gateway)
	if err != nil {
		return nil, err
	}
	s, path, err := loadSession(origin)
	if err != nil {
		return nil, err
	}
	return s.client(path), nil
}

// remoteUnreachable says why a gateway's approval API did not answer.
func remoteUnreachable(origin string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if strings.Contains(err.Error(), "sign") { // from fresh: says what to do
		return err
	}
	return fmt.Errorf("the gateway at %s does not answer: %w", origin, err)
}

// signedOut is the message of a 401 from the approval API.
func signedOut(origin string) string {
	return fmt.Sprintf("your sign-in to %s is not accepted (expired, or for another client): mcp-gateway-admin approvals login --gateway %s", origin, origin)
}
