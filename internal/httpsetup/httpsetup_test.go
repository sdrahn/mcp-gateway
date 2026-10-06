package httpsetup

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
)

func TestBlock(t *testing.T) {
	cur := config.HTTP{AllowedOrigins: []string{"https://app"}, CertFile: "/old/cert.pem", KeyFile: "/old/key.pem"}
	h, err := Block(cur, Answers{URL: "https://gw.example.com:8443", Issuer: "https://idp/realms/mcp", Scopes: []string{"mcp"}})
	if err != nil {
		t.Fatal(err)
	}
	if h.Listen != ":8443" || h.Audience != "https://gw.example.com:8443/mcp" || h.Issuer != "https://idp/realms/mcp" {
		t.Errorf("block: %+v", h)
	}
	if h.CertFile != "/old/cert.pem" || len(h.AllowedOrigins) != 1 || len(h.Scopes) != 1 {
		t.Errorf("kept keys lost: %+v", h)
	}
	if h, _ := Block(config.HTTP{}, Answers{URL: "https://gw/mcp", Issuer: "https://idp", CertFile: "c", KeyFile: "k"}); h.Listen != ":443" {
		t.Errorf("default port: %q", h.Listen)
	}
	for _, bad := range []string{"http://gw/mcp", "gw:8443", "https:///mcp"} {
		if _, err := Block(config.HTTP{}, Answers{URL: bad}); err == nil || !strings.Contains(err.Error(), "https://") {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, err := Block(config.HTTP{}, Answers{URL: "https://gw/mcp"}); err == nil || !strings.Contains(err.Error(), "http.issuer (-issuer)") {
		t.Errorf("missing: %v", err)
	}
}

// Edit sets the asked keys and keeps the rest of the file, comments
// included.
func TestEdit(t *testing.T) {
	in := `# the gateway
version: 1
socket: /run/mcp-gateway/mcp.sock # local
http:
  allowed_origins: [https://app]
  issuer: https://old
`
	h := config.HTTP{Listen: ":8443", CertFile: "/c", KeyFile: "/k", Issuer: "https://idp", Audience: "https://gw:8443/mcp", GroupsClaim: "groups", Scopes: []string{"mcp"}}
	out, changes, err := Edit([]byte(in), h)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"# the gateway", "socket: /run/mcp-gateway/mcp.sock # local", "allowed_origins: ['https://app']",
		"issuer: https://idp", "listen: :8443", "audience: https://gw:8443/mcp", "scopes: [mcp]"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if len(changes) != 7 || changes[3] != (Change{"http.issuer", "https://old", "https://idp"}) {
		t.Errorf("changes: %+v", changes)
	}
	if _, again, _ := Edit(out, h); len(again) != 0 {
		t.Errorf("second edit changed %+v", again)
	}
	out, _, err = Edit(nil, h)
	if err != nil || !strings.Contains(string(out), "version: 1\nhttp:\n  listen:") {
		t.Errorf("empty file: %v\n%s", err, out)
	}
}

// Write replaces the file only with one the gateway loads.
func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	h := config.HTTP{Listen: ":8443", CertFile: cert, KeyFile: key, Issuer: "https://idp", Audience: "https://gw:8443/mcp"}
	changes, err := Write(path, filepath.Join(dir, "vendor.yaml"), h)
	if err != nil || len(changes) != 5 {
		t.Fatalf("write: %v %+v", err, changes)
	}
	g, err := config.LoadGateway(path)
	if err != nil || g.HTTP.Audience != h.Audience {
		t.Fatalf("written: %v %+v", err, g)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", fi.Mode())
	}
	bad := h
	bad.Audience = "https://gw2/mcp"
	bad.Issuer = "not a url"
	if _, err := Write(path, "", bad); err == nil || !strings.Contains(err.Error(), "unchanged") {
		t.Errorf("invalid: %v", err)
	}
	if g, _ := config.LoadGateway(path); g == nil || g.HTTP.Audience != h.Audience {
		t.Error("an invalid configuration replaced the file")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".gateway.yaml.*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

const semanageOut = `http_cache_port_t              tcp      8080, 8118, 8123, 10001-10010
http_port_t                    tcp      80, 81, 443, 488, 8008, 8009, 8443, 9000
mcp_port_t                     tcp      9443
unreserved_port_t              tcp      1024-32767, 32768-60999
`

func TestSELinuxPorts(t *testing.T) {
	rs := SELinuxPorts(config.HTTP{Listen: ":9443", Issuer: "https://idp:8080/realms/mcp"}, semanageOut)
	if len(rs) != 2 || rs[0].Status != doctor.OK || rs[1].Status != doctor.OK {
		t.Errorf("labeled: %+v", rs)
	}
	rs = SELinuxPorts(config.HTTP{Listen: ":8443", Issuer: "https://idp:5556"}, semanageOut)
	if rs[0].Status != doctor.Fail || !strings.Contains(rs[0].Summary, "labeled http_port_t") || !strings.Contains(rs[0].Details[0], "semanage port -a -t mcp_port_t -p tcp 8443") {
		t.Errorf("listen: %+v", rs[0])
	}
	if rs[1].Status != doctor.Fail || !strings.Contains(rs[1].Summary, "unreserved_port_t") {
		t.Errorf("idp: %+v", rs[1])
	}
	if rs := SELinuxPorts(config.HTTP{Listen: "gw:443", Issuer: "https://idp"}, semanageOut); rs[1].Status != doctor.OK {
		t.Errorf("default https port: %+v", rs)
	}
}

// idp is an identity provider for the tests: discovery and a key set
// over TLS, and tokens signed with its key.
type idp struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	issuer string
	md     map[string]any
	keys   bool
}

func newIdP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{key: key, keys: true}
	mux := http.NewServeMux()
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	p.issuer = p.srv.URL + "/realms/mcp"
	p.md = map[string]any{
		"issuer": p.issuer, "jwks_uri": p.srv.URL + "/certs",
		"authorization_endpoint": p.srv.URL + "/auth", "token_endpoint": p.srv.URL + "/token",
		"code_challenge_methods_supported": []string{"plain", "S256"},
	}
	mux.HandleFunc("/realms/mcp/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(p.md)
	})
	mux.HandleFunc("/certs", func(w http.ResponseWriter, _ *http.Request) {
		keys := []map[string]string{}
		if p.keys {
			keys = append(keys, map[string]string{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	return p
}

func (p *idp) token(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIdentityProvider(t *testing.T) {
	p := newIdP(t)
	ctx := context.Background()
	h := config.HTTP{Issuer: p.issuer}
	rs := IdentityProvider(ctx, h, p.srv.Client())
	if rs[0].Status != doctor.OK || !strings.Contains(rs[0].Summary, "1 signing key") ||
		!strings.Contains(strings.Join(rs[0].Details, "\n"), "no dynamic client registration") {
		t.Errorf("ok: %+v", rs[0])
	}

	// The identity provider's own name wins: Keycloak behind a proxy
	// or with another host name.
	p.md["issuer"] = "https://idp.example.com/realms/mcp"
	rs = IdentityProvider(ctx, h, p.srv.Client())
	if rs[0].Status != doctor.Fail || !strings.Contains(rs[0].Details[0], "set http.issuer (-issuer) to https://idp.example.com/realms/mcp") {
		t.Errorf("issuer: %+v", rs[0])
	}
	p.md["issuer"] = p.issuer

	// With http.jwks_url the gateway does without discovery.
	rs = IdentityProvider(ctx, config.HTTP{Issuer: p.srv.URL + "/elsewhere", JWKSURL: p.srv.URL + "/certs"}, p.srv.Client())
	if rs[0].Status != doctor.Warn || !strings.Contains(strings.Join(rs[0].Details, "\n"), "takes the keys from http.jwks_url") {
		t.Errorf("jwks_url: %+v", rs[0])
	}

	p.md["code_challenge_methods_supported"] = []string{"plain"}
	if rs = IdentityProvider(ctx, h, p.srv.Client()); rs[0].Status != doctor.Warn {
		t.Errorf("no S256: %+v", rs[0])
	}
	p.keys = false
	if rs = IdentityProvider(ctx, h, p.srv.Client()); rs[0].Status != doctor.Fail || !strings.Contains(rs[0].Summary, "no signing key") {
		t.Errorf("no keys: %+v", rs[0])
	}

	// A certificate from a CA the system does not trust.
	rs = IdentityProvider(ctx, h, &http.Client{Timeout: time.Second})
	if rs[0].Status != doctor.Fail || !strings.Contains(strings.Join(rs[0].Details, " "), "update-ca-certificates") {
		t.Errorf("unknown CA: %+v", rs[0])
	}
}

func TestToken(t *testing.T) {
	p := newIdP(t)
	ctx := context.Background()
	h := config.HTTP{Issuer: p.issuer, Audience: "https://gw:8443/mcp", GroupsClaim: "groups", LocalUserClaim: "preferred_username"}
	exp := time.Now().Add(time.Hour).Unix()

	tok := p.token(t, jwt.MapClaims{"iss": p.issuer, "aud": h.Audience, "sub": "0b5e-uuid", "exp": exp,
		"groups": []string{"mcp-admins"}, "preferred_username": "no-such-user-here"})
	rs := Token(ctx, h, p.srv.Client(), tok, nil)
	d := strings.Join(rs[0].Details, "\n")
	if rs[0].Status != doctor.OK || rs[0].Summary != "accepted: principal 0b5e-uuid" ||
		!strings.Contains(d, "groups: mcp-admins") || !strings.Contains(d, "is no local account") {
		t.Errorf("accepted: %+v", rs[0])
	}
	if strings.Contains(rs[0].Summary+d, tok) {
		t.Error("the token was printed")
	}

	// No groups claim: Keycloak without a Group Membership mapper.
	tok = p.token(t, jwt.MapClaims{"iss": p.issuer, "aud": h.Audience, "sub": "u", "exp": exp})
	if rs = Token(ctx, h, p.srv.Client(), tok, nil); rs[0].Status != doctor.Warn || !strings.Contains(strings.Join(rs[0].Details, "\n"), "Group Membership mapper") {
		t.Errorf("no groups: %+v", rs[0])
	}

	// Keycloak's default audience is "account".
	tok = p.token(t, jwt.MapClaims{"iss": p.issuer, "aud": "account", "sub": "u", "exp": exp})
	rs = Token(ctx, h, p.srv.Client(), tok, nil)
	if rs[0].Status != doctor.Fail || !strings.Contains(rs[0].Details[0], "the token is for account") || !strings.Contains(rs[0].Details[1], "Audience mapper") {
		t.Errorf("audience: %+v", rs[0])
	}

	h.Scopes = []string{"mcp"}
	tok = p.token(t, jwt.MapClaims{"iss": p.issuer, "aud": h.Audience, "sub": "u", "exp": exp, "scope": "openid"})
	if rs = Token(ctx, h, p.srv.Client(), tok, nil); rs[0].Status != doctor.Fail || !strings.Contains(strings.Join(rs[0].Details, " "), `lacks "mcp"`) {
		t.Errorf("scope: %+v", rs[0])
	}
	if rs = Token(ctx, h, p.srv.Client(), "opaque", nil); rs[0].Status != doctor.Fail || !strings.Contains(rs[0].Summary, "not a JWT") {
		t.Errorf("opaque: %+v", rs[0])
	}

	// With the role data: the scopes and the ceiling they set.
	roles := []byte(`{"scopes": {"mcp:read": {"roles": ["viewer"], "permissions": [{"server": "git", "tool": "log"}]}, "mcp:admin": {"unlimited": true}}}`)
	for scope, want := range map[string]string{
		"mcp mcp:read":  "ceiling: mcp:read (roles viewer, 1 permission); within the roles, only this is allowed",
		"mcp mcp:admin": "ceiling: mcp:admin (unlimited; the roles decide)",
		"mcp":           "ceiling: none (none of the token's scopes is in the role data's scopes map, and there is no default)",
	} {
		tok = p.token(t, jwt.MapClaims{"iss": p.issuer, "aud": h.Audience, "sub": "u", "exp": exp, "scope": scope, "groups": []string{}})
		d := strings.Join(Token(ctx, h, p.srv.Client(), tok, roles)[0].Details, "\n")
		if !strings.Contains(d, "scopes: "+scope) || !strings.Contains(d, want) {
			t.Errorf("%s: %s", scope, d)
		}
	}
	tok = p.token(t, jwt.MapClaims{"iss": p.issuer, "aud": h.Audience, "sub": "u", "exp": exp, "scope": "mcp"})
	if d := strings.Join(Token(ctx, h, p.srv.Client(), tok, []byte(`{"roles": {}}`))[0].Details, "\n"); !strings.Contains(d, "ceiling: none (the role data has no scopes map") {
		t.Errorf("no map: %s", d)
	}
}

func TestListener(t *testing.T) {
	var audience, issuer string
	initialized := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/oauth-protected-resource/mcp":
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": audience, "authorization_servers": []string{issuer}})
		case r.URL.Path == "/mcp" && r.Method == http.MethodPost:
			if r.Header.Get("Authorization") != "Bearer good" {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			initialized = true
			w.Header().Set("Mcp-Session-Id", "s1")
			_, _ = w.Write([]byte(`{}`))
		case r.URL.Path == "/mcp" && r.Method == http.MethodDelete:
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	audience, issuer = srv.URL+"/mcp", "https://idp"
	h := config.HTTP{Audience: audience, Issuer: issuer}
	ctx := context.Background()

	rs := Listener(ctx, h, srv.Client(), "good")
	if rs[0].Status != doctor.OK || !initialized || !strings.Contains(strings.Join(rs[0].Details, ""), "accepted") {
		t.Errorf("ok: %+v", rs[0])
	}
	if rs = Listener(ctx, h, srv.Client(), "bad"); rs[0].Status != doctor.Fail || !strings.Contains(rs[0].Details[0], "HTTP 401") {
		t.Errorf("refused token: %+v", rs[0])
	}
	// Clients that do not know the CA: the listener answers, they
	// must trust its certificate.
	initialized = false
	if rs = Listener(ctx, h, &http.Client{Timeout: time.Second}, "good"); rs[0].Status != doctor.Warn || !strings.Contains(rs[0].Details[0], "do not trust its certificate") || !initialized {
		t.Errorf("untrusted: %+v", rs[0])
	}
	// The running gateway has another http block (not restarted).
	h2 := h
	h2.Issuer = "https://other"
	if rs = Listener(ctx, h2, srv.Client(), ""); rs[0].Status != doctor.Warn || !strings.Contains(rs[0].Details[0], "restart") {
		t.Errorf("other block: %+v", rs[0])
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "https://" + l.Addr().String() + "/mcp"
	_ = l.Close()
	if rs = Listener(ctx, config.HTTP{Audience: closed}, srv.Client(), ""); rs[0].Status != doctor.Fail || !strings.Contains(strings.Join(rs[0].Details, " "), "systemctl restart mcp-gateway.service") {
		t.Errorf("closed: %+v", rs[0])
	}
}
