// Package httpsetup sets up and checks the gateway's HTTP listener for
// remote agents (mcp-gateway-admin setup http): it fills in the http
// block of gateway.yaml from a few answers, and checks what the gateway
// and its clients need beyond it, end to end: the identity provider's
// metadata and keys, that the gateway's SELinux domain may reach the
// identity provider and bind the port, a token as the gateway would take
// it (whom it makes the principal, and why it is refused), and the
// listener as a client sees it. The certificate and the firewall are
// checked as the doctor checks them (doctor.TLS, doctor.Firewall).
package httpsetup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sdrahn/mcp-gateway/internal/authn"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

// Answers are what the administrator tells about the setup; empty ones
// keep what the http block has.
type Answers struct {
	// URL is the gateway's public MCP URL, as clients use it
	// (http.audience); http.listen takes its port.
	URL            string
	Issuer         string
	CertFile       string
	KeyFile        string
	GroupsClaim    string
	LocalUserClaim string
	Scopes         []string
}

// Block returns the http block cur with the answers filled in. It
// leaves the keys it does not ask about (allowed_origins, mTLS, …) as
// they are.
func Block(cur config.HTTP, a Answers) (config.HTTP, error) {
	h := cur
	if a.URL != "" {
		u, err := url.Parse(a.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return h, fmt.Errorf("the URL must be the https:// URL clients use, e.g. https://gw.example.com:8443/mcp, got %q", a.URL)
		}
		if u.Path == "" || u.Path == "/" {
			u.Path = "/mcp"
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		h.Audience = u.String()
		h.Listen = ":" + port
	}
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&h.Issuer, a.Issuer)
	set(&h.CertFile, a.CertFile)
	set(&h.KeyFile, a.KeyFile)
	set(&h.GroupsClaim, a.GroupsClaim)
	set(&h.LocalUserClaim, a.LocalUserClaim)
	if a.Scopes != nil {
		h.Scopes = a.Scopes
	}
	var missing []string
	for _, k := range []struct{ name, v, flag string }{
		{"audience", h.Audience, "-url"}, {"issuer", h.Issuer, "-issuer"},
		{"cert_file", h.CertFile, "-cert"}, {"key_file", h.KeyFile, "-key"},
	} {
		if k.v == "" {
			missing = append(missing, fmt.Sprintf("http.%s (%s)", k.name, k.flag))
		}
	}
	if len(missing) > 0 {
		return h, fmt.Errorf("not set yet: %s", strings.Join(missing, ", "))
	}
	return h, nil
}

// metadata is what the checks read from the identity provider's
// discovery document (OpenID Connect Discovery, RFC 8414).
type metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

// IdentityProvider checks the identity provider at h.Issuer as the
// gateway uses it: its discovery document
// (<issuer>/.well-known/openid-configuration, which the gateway reads),
// that the document names the issuer exactly as tokens carry it, and
// that the key set (jwks_uri, or http.jwks_url) has keys the gateway can
// verify tokens with. It notes what agents need: authorization code with
// PKCE (S256), and dynamic client registration for agents that register
// themselves.
func IdentityProvider(ctx context.Context, h config.HTTP, client *http.Client) []doctor.Result {
	r := doctor.Result{Check: "identity provider"}
	fail := func(summary string, details ...string) []doctor.Result {
		r.Status, r.Summary, r.Details = doctor.Fail, summary, details
		return []doctor.Result{r}
	}
	discovery := strings.TrimSuffix(h.Issuer, "/") + "/.well-known/openid-configuration"
	var md metadata
	if err := getJSON(ctx, client, discovery, &md); err != nil {
		if h.JWKSURL == "" {
			return fail(fmt.Sprintf("%s: %v", discovery, err), reachHint(err, h.Issuer)...)
		}
		// With http.jwks_url the gateway does without discovery.
		md.Issuer = h.Issuer
		r.Details = append(r.Details, fmt.Sprintf("%s: %v; the gateway takes the keys from http.jwks_url", discovery, err))
	}
	if md.Issuer != h.Issuer {
		return fail(fmt.Sprintf("the identity provider calls itself %q, http.issuer is %q: tokens carry the former, so the gateway refuses them all", md.Issuer, h.Issuer),
			"set http.issuer (-issuer) to "+md.Issuer)
	}
	jwks := md.JWKSURI
	if h.JWKSURL != "" {
		jwks = h.JWKSURL
	}
	if jwks == "" {
		return fail("the discovery document names no jwks_uri: the gateway cannot verify tokens",
			"set http.jwks_url to the identity provider's key set")
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := getJSON(ctx, client, jwks, &set); err != nil {
		return fail(fmt.Sprintf("key set %s: %v", jwks, err), reachHint(err, jwks)...)
	}
	signing := 0
	for _, k := range set.Keys {
		if (k.Kty == "RSA" || k.Kty == "EC" || k.Kty == "OKP") && k.Use != "enc" {
			signing++
		}
	}
	if signing == 0 {
		return fail(fmt.Sprintf("key set %s has no signing key (RSA, EC or OKP): the gateway refuses every token", jwks))
	}
	r.Status = doctor.OK
	r.Summary = fmt.Sprintf("%s: %d signing key(s)", h.Issuer, signing)
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" {
		r.Status = doctor.Warn
		r.Details = append(r.Details, "no authorization_endpoint or token_endpoint: interactive agents cannot get a token from it")
	}
	if !slices.Contains(md.CodeChallengeMethods, "S256") {
		r.Status = doctor.Warn
		r.Details = append(r.Details, "it does not announce PKCE with S256 (code_challenge_methods_supported), which MCP clients require")
	}
	if md.RegistrationEndpoint == "" {
		r.Details = append(r.Details, "no dynamic client registration: register the agents as clients in the identity provider and give them the client id (e.g. claude mcp add --client-id)")
	} else {
		r.Details = append(r.Details, "dynamic client registration at "+md.RegistrationEndpoint+": agents may register themselves")
	}
	return []doctor.Result{r}
}

// reachHint says what to do about an identity provider the checks could
// not reach as the gateway does.
func reachHint(err error, target string) []string {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	switch {
	case errors.As(err, &unknown):
		return []string{"the gateway verifies the identity provider's certificate with the system's CA certificates:",
			"add the CA that signed it, e.g. cp idp-ca.pem /etc/pki/trust/anchors/ && update-ca-certificates"}
	case errors.As(err, &hostname):
		return []string{"the identity provider's certificate does not name the host in " + target}
	}
	return []string{"the gateway fetches it at start and when it sees an unknown key id; check the URL, and that this host reaches it"}
}

func getJSON(ctx context.Context, client *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return ue.Err // the URL is said already
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v); err != nil {
		return fmt.Errorf("not JSON: %v", err)
	}
	return nil
}

// Port types of the gateway's SELinux domain (selinux/mcp_gateway.te):
// the HTTP listener binds mcp_port_t; the identity provider is reached on
// an HTTP port (http_port_t: 443, 8443, …) or a proxy port
// (http_cache_port_t: 8080, …).
var (
	listenPortTypes = []string{"mcp_port_t"}
	idpPortTypes    = []string{"http_port_t", "http_cache_port_t"}
)

// SELinuxPorts checks the SELinux labels of the listener's port and the
// identity provider's port against what the gateway's domain may use.
// labels is "semanage port -l" (type, protocol, ports per line). The
// gateway does not start with a port it may not bind; it refuses every
// token when it may not reach the identity provider for its keys.
func SELinuxPorts(h config.HTTP, labels string) []doctor.Result {
	label := portLabels(labels)
	var rs []doctor.Result
	if _, port, err := net.SplitHostPort(h.Listen); err == nil && port != "" {
		r := doctor.Result{Check: "SELinux port", Status: doctor.OK}
		t := label(port)
		if slices.Contains(listenPortTypes, t) {
			r.Summary = fmt.Sprintf("the gateway may listen on port %s (%s)", port, t)
		} else {
			r.Status = doctor.Fail
			r.Summary = fmt.Sprintf("port %s is labeled %s: the gateway's SELinux domain may not listen on it, so the gateway does not start", port, orNone(t))
			r.Details = []string{fmt.Sprintf("semanage port -a -t mcp_port_t -p tcp %s 2>/dev/null || semanage port -m -t mcp_port_t -p tcp %s", port, port)}
		}
		rs = append(rs, r)
	}
	if u, err := url.Parse(h.Issuer); err == nil && u.Host != "" {
		port := u.Port()
		if port == "" {
			port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
		}
		r := doctor.Result{Check: "SELinux port", Status: doctor.OK}
		t := label(port)
		if slices.Contains(idpPortTypes, t) {
			r.Summary = fmt.Sprintf("the gateway may reach the identity provider on port %s (%s)", port, t)
		} else {
			r.Status = doctor.Fail
			r.Summary = fmt.Sprintf("the identity provider's port %s is labeled %s: the gateway's SELinux domain may not connect to it, so it cannot fetch the keys and refuses every token", port, orNone(t))
			r.Details = []string{fmt.Sprintf("semanage port -a -t http_port_t -p tcp %s, or run the identity provider on an HTTP port (443, 8443)", port)}
		}
		rs = append(rs, r)
	}
	return rs
}

func orNone(t string) string {
	if t == "" {
		return "with no type of its own"
	}
	return t
}

// portLabels returns the type labeling a TCP port in "semanage port -l"
// output (lines "type tcp 80, 8008-8009"); a port in several entries has
// the one of the narrowest range, as the policy has it (local entries
// added with semanage are the narrowest).
func portLabels(out string) func(port string) string {
	type entry struct {
		t      string
		lo, hi int
	}
	var es []entry
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "tcp" {
			continue
		}
		for _, p := range strings.Split(strings.Join(f[2:], ""), ",") {
			lo, hi, ok := strings.Cut(p, "-")
			if !ok {
				hi = lo
			}
			l, err1 := strconv.Atoi(lo)
			h, err2 := strconv.Atoi(hi)
			if err1 == nil && err2 == nil {
				es = append(es, entry{f[0], l, h})
			}
		}
	}
	return func(port string) string {
		n, err := strconv.Atoi(port)
		if err != nil {
			return ""
		}
		best, width := "", -1
		for _, e := range es {
			if n >= e.lo && n <= e.hi && (width < 0 || e.hi-e.lo < width) {
				best, width = e.t, e.hi-e.lo
			}
		}
		return best
	}
}

// Token checks a token as the gateway takes it (authn.OAuth with h) and
// says whom it makes the principal, or why the gateway refuses it, from
// the token's claims (read without verifying them, to explain). With the
// role data (nil if not readable), it also tells the ceiling the token's
// scopes set (section 6.7). The token itself is never printed.
func Token(ctx context.Context, h config.HTTP, client *http.Client, token string, roleData []byte) []doctor.Result {
	r := doctor.Result{Check: "token"}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		r.Status, r.Summary = doctor.Fail, "not a JWT: "+err.Error()
		r.Details = []string{"the gateway takes JWT access tokens; an opaque token cannot be checked here"}
		return []doctor.Result{r}
	}
	p, err := authn.NewOAuth(h, client).Authenticate(ctx, token, nil)
	if err != nil {
		r.Status = doctor.Fail
		r.Summary = "the gateway refuses it: " + err.Error()
		r.Details = refusal(h, claims)
		return []doctor.Result{r}
	}
	r.Status = doctor.OK
	r.Summary = "accepted: principal " + p.Sub
	if p.UID != nil {
		r.Summary += fmt.Sprintf(" (local account, uid %d)", *p.UID)
	}
	if len(p.Groups) > 0 {
		r.Details = append(r.Details, "groups: "+strings.Join(p.Groups, ", "))
	}
	r.Details = append(r.Details, "roles bind to "+p.Sub+" (user) or to these groups (chapter 6)")
	if _, ok := claims[h.GroupsClaim]; !ok {
		r.Status = doctor.Warn
		r.Details = append(r.Details, fmt.Sprintf("the token has no %q claim, so roles bound to groups do not apply; claims it has: %s", h.GroupsClaim, claimNames(claims)),
			"in Keycloak: a Group Membership mapper on the client's dedicated scope, token claim name "+h.GroupsClaim+", Full group path off, Add to access token on")
	}
	if h.LocalUserClaim != "" && p.UID == nil {
		name, _ := claims[h.LocalUserClaim].(string)
		if name == "" {
			r.Details = append(r.Details, fmt.Sprintf("no %q claim: servers with run_as: principal run as a dynamic user", h.LocalUserClaim))
		} else {
			r.Details = append(r.Details, fmt.Sprintf("%s %q is no local account: servers with run_as: principal run as a dynamic user", h.LocalUserClaim, name))
		}
	}
	if len(p.Scopes) > 0 {
		r.Details = append(r.Details, "scopes: "+strings.Join(p.Scopes, " "))
	}
	if roleData != nil {
		r.Details = append(r.Details, ceilingText(roleData, p.Scopes))
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		r.Details = append(r.Details, "expires "+exp.Format(time.RFC3339))
	}
	return []doctor.Result{r}
}

// ceilingText says what the role data's scopes map lets a token with
// scopes do at most.
func ceilingText(roleData []byte, scopes []string) string {
	c, err := policydata.CeilingOf(roleData, scopes)
	switch {
	case err != nil:
		return "ceiling: the role data cannot be read: " + err.Error()
	case !c.Map:
		return "ceiling: none (the role data has no scopes map; the token's scopes do not narrow its roles)"
	case len(c.Scopes) == 0:
		return "ceiling: none (none of the token's scopes is in the role data's scopes map, and there is no default)"
	case c.Unlimited:
		return "ceiling: " + strings.Join(c.Scopes, ", ") + " (unlimited; the roles decide)"
	}
	var what []string
	if len(c.Roles) > 0 {
		what = append(what, "roles "+strings.Join(c.Roles, ", "))
	}
	if c.Permissions == 1 {
		what = append(what, "1 permission")
	} else if c.Permissions > 1 {
		what = append(what, fmt.Sprintf("%d permissions", c.Permissions))
	}
	if len(what) == 0 {
		what = append(what, "nothing")
	}
	return "ceiling: " + strings.Join(c.Scopes, ", ") + " (" + strings.Join(what, ", ") +
		"); within the roles, only this is allowed, the rest is denied (over HTTPS with an insufficient_scope challenge)"
}

// refusal explains, from its claims, why the gateway refuses a token.
func refusal(h config.HTTP, c jwt.MapClaims) []string {
	var ds []string
	if iss, _ := c.GetIssuer(); iss != h.Issuer {
		ds = append(ds, fmt.Sprintf("issuer: the token's is %q, http.issuer is %q", iss, h.Issuer))
	}
	if aud, _ := c.GetAudience(); !slices.Contains(aud, h.Audience) {
		ds = append(ds, fmt.Sprintf("audience: the token is for %s, http.audience is %q", orNothing(aud), h.Audience),
			"the identity provider must put the gateway's URL in aud: in Keycloak, an Audience mapper (included custom audience "+h.Audience+") on the client's dedicated scope")
	}
	if exp, err := c.GetExpirationTime(); err == nil && exp != nil && time.Now().After(exp.Add(time.Minute)) {
		ds = append(ds, "the token expired at "+exp.Format(time.RFC3339)+": get a fresh one")
	}
	if len(h.Scopes) > 0 {
		have := strings.Fields(fmt.Sprint(c["scope"]))
		for _, s := range h.Scopes {
			if !slices.Contains(have, s) {
				ds = append(ds, fmt.Sprintf("scope: the token lacks %q (http.scopes); the agent must request it", s))
			}
		}
	}
	if len(ds) == 0 {
		ds = append(ds, "the signature does not verify with the identity provider's keys, or the token is bound to a client certificate")
	}
	return ds
}

func orNothing(aud []string) string {
	if len(aud) == 0 {
		return "no audience"
	}
	return strings.Join(aud, ", ")
}

func claimNames(c jwt.MapClaims) string {
	names := make([]string, 0, len(c))
	for k := range c {
		names = append(names, k)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// Listener checks the HTTP listener as a client reaches it at
// http.audience: the protected resource metadata (RFC 9728) answers and
// names the issuer, with the certificate verified as clients verify it,
// and, with a token, an initialize is accepted. If nothing listens, the
// gateway was not restarted since http.listen changed.
func Listener(ctx context.Context, h config.HTTP, client *http.Client, token string) []doctor.Result {
	r := doctor.Result{Check: "listener"}
	u, err := url.Parse(h.Audience)
	if err != nil {
		r.Status, r.Summary = doctor.Fail, err.Error()
		return []doctor.Result{r}
	}
	meta := u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource" + strings.TrimSuffix(u.Path, "/")
	var md struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	err = getJSON(ctx, client, meta, &md)
	var unknown x509.UnknownAuthorityError
	switch {
	case errors.As(err, &unknown):
		// Self-signed or a private CA: the listener answers, but clients
		// must trust the certificate. Look again without verifying.
		insecure := &http.Client{Timeout: client.Timeout, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- only to tell a listener with an untrusted certificate from none, and to try the token there
		client = insecure
		if err2 := getJSON(ctx, insecure, meta, &md); err2 != nil {
			r.Status, r.Summary = doctor.Fail, fmt.Sprintf("%s: %v", meta, err2)
			return []doctor.Result{r}
		}
		r.Status = doctor.Warn
		r.Details = append(r.Details, "clients do not trust its certificate ("+err.Error()+"): give them the CA that signed it, or use a certificate from a CA they trust")
	case err != nil:
		r.Status = doctor.Fail
		r.Summary = fmt.Sprintf("%s: %v", meta, err)
		var dns *net.DNSError
		var op *net.OpError
		switch {
		case errors.As(err, &dns):
			r.Details = []string{"this host cannot resolve " + u.Hostname() + ": clients must, so put it in DNS (or /etc/hosts here to check)"}
		case errors.As(err, &op) && op.Op == "dial":
			r.Details = []string{"nothing answers there: http.listen takes effect at start, so systemctl restart mcp-gateway.service;",
				"if the gateway listens (journal: msg=listening) and this host still cannot connect, the firewall is in the way"}
		}
		return []doctor.Result{r}
	default:
		r.Status = doctor.OK
	}
	if md.Resource != h.Audience || !slices.Contains(md.AuthorizationServers, h.Issuer) {
		r.Status = doctor.Warn
		r.Details = append(r.Details, fmt.Sprintf("it announces resource %q and authorization servers %v: the running gateway has another http block; restart it (http.listen) or check mcp-gateway-admin doctor", md.Resource, md.AuthorizationServers))
	}
	r.Summary = "answers at " + meta
	if token == "" || r.Status == doctor.Fail {
		return []doctor.Result{r}
	}
	status, err := initialize(ctx, client, h.Audience, token)
	switch {
	case err != nil:
		r.Details = append(r.Details, "initialize with the token: "+err.Error())
	case status == http.StatusOK:
		r.Details = append(r.Details, "initialize with the token: accepted")
	default:
		r.Status = doctor.Fail
		r.Details = append(r.Details, fmt.Sprintf("initialize with the token: HTTP %d (see the token check; the gateway's journal says why: token rejected)", status))
	}
	return []doctor.Result{r}
}

// initialize opens and ends an MCP session at endpoint with token, and
// returns the status of the initialize.
func initialize(ctx context.Context, client *http.Client, endpoint, token string) (int, error) {
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-gateway-admin setup http","version":"1"}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		del, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
		if err == nil {
			del.Header.Set("Authorization", "Bearer "+token)
			del.Header.Set("Mcp-Session-Id", sid)
			if dr, err := client.Do(del); err == nil {
				_ = dr.Body.Close()
			}
		}
	}
	return resp.StatusCode, nil
}
