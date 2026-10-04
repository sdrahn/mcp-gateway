package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAS is a resource server and its authorization server on one host.
func fakeAS(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="`+srv.URL+`/meta/mcp"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /meta/mcp", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"resource": srv.URL + "/mcp", "authorization_servers": []string{srv.URL + "/as"}, "scopes_supported": []string{"read"}})
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/as", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"issuer": srv.URL + "/as", "authorization_endpoint": srv.URL + "/as/authorize",
			"token_endpoint": srv.URL + "/as/token", "registration_endpoint": srv.URL + "/as/register",
			"revocation_endpoint": srv.URL + "/as/revoke", "code_challenge_methods_supported": []string{"S256"}})
	})
	mux.HandleFunc("POST /as/register", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		if m["token_endpoint_auth_method"] != "none" {
			writeJSON(w, 400, map[string]string{"error": "invalid_client_metadata"})
			return
		}
		writeJSON(w, 201, map[string]string{"client_id": "dyn-1"})
	})
	mux.HandleFunc("POST /as/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user, pass, basic := r.BasicAuth()
		switch {
		case basic && (user != "conf" || pass != "s3cret"):
			writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		case r.Form.Get("resource") != srv.URL+"/mcp":
			writeJSON(w, 400, map[string]string{"error": "invalid_target"})
		case r.Form.Get("grant_type") == "authorization_code" && r.Form.Get("code") == "good" && r.Form.Get("code_verifier") != "":
			writeJSON(w, 200, map[string]any{"access_token": "at-1", "token_type": "bearer", "expires_in": 3600, "refresh_token": "rt-1", "scope": "read"})
		case r.Form.Get("grant_type") == "refresh_token" && r.Form.Get("refresh_token") == "rt-1":
			writeJSON(w, 200, map[string]any{"access_token": "at-2", "token_type": "Bearer", "expires_in": 3600})
		default:
			writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "bad code"})
		}
	})
	mux.HandleFunc("POST /as/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("token") == "" {
			w.WriteHeader(400)
		}
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDo(t *testing.T) {
	srv := fakeAS(t)
	ctx := context.Background()
	c := srv.Client()

	r := Do(ctx, c, Request{Op: OpResource, URL: srv.URL + "/mcp"}, "")
	if r.Err() != nil || r.Resource.AuthorizationServers[0] != srv.URL+"/as" {
		t.Fatalf("resource: %+v", r)
	}
	r = Do(ctx, c, Request{Op: OpServer, URL: srv.URL + "/as"}, "")
	if r.Err() != nil || r.Server.TokenEndpoint != srv.URL+"/as/token" {
		t.Fatalf("server: %+v", r)
	}
	r = Do(ctx, c, Request{Op: OpRegister, URL: srv.URL + "/as/register", RedirectURI: "https://gw/oauth/callback"}, "")
	if r.Err() != nil || r.Client.ClientID != "dyn-1" {
		t.Fatalf("register: %+v", r)
	}
	tok := Request{Op: OpToken, URL: srv.URL + "/as/token", GrantType: "authorization_code", Code: "good",
		CodeVerifier: NewVerifier(), RedirectURI: "https://gw/oauth/callback", ClientID: "dyn-1", Resource: srv.URL + "/mcp"}
	r = Do(ctx, c, tok, "")
	if r.Err() != nil || r.Token.AccessToken != "at-1" || r.Token.RefreshToken != "rt-1" || r.Token.ExpiresIn != 3600 {
		t.Fatalf("token: %+v", r)
	}
	tok.Code = "bad"
	if r = Do(ctx, c, tok, ""); !IsInvalidGrant(r.Err()) || !strings.Contains(r.Err().Error(), "bad code") {
		t.Errorf("bad code: %+v", r)
	}
	ref := Request{Op: OpToken, URL: srv.URL + "/as/token", GrantType: "refresh_token", RefreshToken: "rt-1", ClientID: "dyn-1", Resource: srv.URL + "/mcp"}
	if r = Do(ctx, c, ref, ""); r.Err() != nil || r.Token.AccessToken != "at-2" {
		t.Errorf("refresh: %+v", r)
	}

	// A confidential client's secret from a credential: HTTP Basic.
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "oauth"), []byte("s3cret\n"), 0o600)
	ref.ClientID, ref.ClientSecretCredential = "conf", "oauth"
	if r = Do(ctx, c, ref, dir); r.Err() != nil {
		t.Errorf("confidential: %+v", r)
	}
	ref.ClientSecretCredential = "missing"
	if r = Do(ctx, c, ref, dir); r.Error != HelperError {
		t.Errorf("missing credential: %+v", r)
	}

	if r = Do(ctx, c, Request{Op: OpRevoke, URL: srv.URL + "/as/revoke", Token: "rt-1", ClientID: "dyn-1"}, ""); r.Err() != nil {
		t.Errorf("revoke: %+v", r)
	}
	if r = Do(ctx, c, Request{Op: OpToken, URL: "http://example.com/token"}, ""); r.Error != HelperError || !strings.Contains(r.ErrorDescription, "https") {
		t.Errorf("plain http elsewhere: %+v", r)
	}
	if r = Do(ctx, c, Request{Op: "nope", URL: srv.URL}, ""); r.Error != HelperError {
		t.Errorf("unknown op: %+v", r)
	}
}

func TestServerMetadataCheck(t *testing.T) {
	m := ServerMetadata{AuthorizationEndpoint: "https://as/authorize", TokenEndpoint: "https://as/token"}
	if err := m.Check(); err == nil || !strings.Contains(err.Error(), "S256") {
		t.Errorf("no PKCE: %v", err)
	}
	m.CodeChallengeMethodsSupported = []string{"plain", "S256"}
	if err := m.Check(); err != nil {
		t.Error(err)
	}
	m.TokenEndpoint = "http://as/token"
	if err := m.Check(); err == nil {
		t.Error("http token endpoint accepted")
	}
}

func TestAuthURL(t *testing.T) {
	v := NewVerifier()
	u, err := AuthURL("https://as.example.com/authorize?x=1", AuthParams{ClientID: "c", RedirectURI: "https://gw/oauth/callback",
		Scope: "read write", State: "st", Verifier: v, Resource: "https://mcp.example.com/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"x=1", "response_type=code", "client_id=c", "code_challenge=" + Challenge(v), "code_challenge_method=S256",
		"state=st", "scope=read+write", "resource=https%3A%2F%2Fmcp.example.com%2Fmcp", "redirect_uri=https%3A%2F%2Fgw%2Foauth%2Fcallback"} {
		if !strings.Contains(u, want) {
			t.Errorf("%s lacks %s", u, want)
		}
	}
	// RFC 7636 appendix B.
	if got := Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("challenge %s", got)
	}
}

func TestAuthParam(t *testing.T) {
	v := []string{`Basic realm="x"`, `Bearer realm="a,b", resource_metadata="https://h/m", error="invalid_token"`}
	if got := authParam(v, "resource_metadata"); got != "https://h/m" {
		t.Errorf("got %q", got)
	}
	if got := authParam(v, "scope"); got != "" {
		t.Errorf("got %q", got)
	}
}
