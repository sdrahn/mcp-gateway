// Package oauthtest is a fake MCP server with its authorization server,
// for tests of signing in (unit tests, and the VM test through privsrv):
// protected resource metadata, authorization server metadata, dynamic
// registration, an authorization endpoint that signs in at once, token
// and revocation endpoints, and an MCP endpoint (Streamable HTTP, JSON
// answers) that requires an access token it issued and whose tool
// whoami answers with the account the token is for.
package oauthtest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Server is the fake. Set its fields before serving.
type Server struct {
	// Base is the URL the server is reached at, e.g. https://as.test:8443
	// (set by the caller once it listens).
	Base string
	// Account is who signs in at the authorization endpoint ("alice"
	// if empty); AccountParam, if set, takes it from that query
	// parameter of the authorization request instead (tests).
	Account      string
	AccountParam string
	// ExpiresIn is the access tokens' lifetime (default 1 h).
	ExpiresIn time.Duration
	// NoRegistration and CIMD say what the metadata offers.
	NoRegistration bool
	CIMD           bool

	mu       sync.Mutex
	codes    map[string]grant  // code to grant
	access   map[string]string // access token to account
	refresh  map[string]string // refresh token to account
	revoked  []string
	refreshN int
}

type grant struct {
	account, challenge, redirect, clientID, resource string
}

// Resource is the MCP endpoint's URL.
func (s *Server) Resource() string { return s.Base + "/mcp" }

// Issuer is the authorization server's issuer.
func (s *Server) Issuer() string { return s.Base + "/as" }

// Revoked returns the tokens revoked so far.
func (s *Server) Revoked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.revoked...)
}

// Refreshes returns how many refreshes were answered.
func (s *Server) Refreshes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshN
}

// ExpireAccessTokens makes every issued access token invalid (the next
// call of the MCP endpoint gets 401).
func (s *Server) ExpireAccessTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.access = nil
}

func token() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/mcp":
		s.mcp(w, r)
	case r.URL.Path == "/.well-known/oauth-protected-resource/mcp" || r.URL.Path == "/.well-known/oauth-protected-resource":
		writeJSON(w, 200, map[string]any{"resource": s.Resource(), "authorization_servers": []string{s.Issuer()},
			"scopes_supported": []string{"mcp.read"}})
	case r.URL.Path == "/.well-known/oauth-authorization-server/as":
		m := map[string]any{"issuer": s.Issuer(), "authorization_endpoint": s.Base + "/as/authorize",
			"token_endpoint": s.Base + "/as/token", "revocation_endpoint": s.Base + "/as/revoke",
			"code_challenge_methods_supported": []string{"S256"}, "client_id_metadata_document_supported": s.CIMD}
		if !s.NoRegistration {
			m["registration_endpoint"] = s.Base + "/as/register"
		}
		writeJSON(w, 200, m)
	case r.URL.Path == "/as/register" && r.Method == http.MethodPost:
		var m map[string]any
		if json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&m) != nil {
			oauthError(w, 400, "invalid_client_metadata", "not JSON")
			return
		}
		writeJSON(w, 201, map[string]any{"client_id": "client-" + token(), "redirect_uris": m["redirect_uris"]})
	case r.URL.Path == "/as/authorize":
		s.authorize(w, r)
	case r.URL.Path == "/as/token" && r.Method == http.MethodPost:
		s.token(w, r)
	case r.URL.Path == "/as/revoke" && r.Method == http.MethodPost:
		_ = r.ParseForm()
		s.mu.Lock()
		t := r.PostForm.Get("token")
		s.revoked = append(s.revoked, t)
		delete(s.refresh, t)
		delete(s.access, t)
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

// authorize signs the account in at once and redirects to redirect_uri
// with a code (a real server shows a login and consent page).
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redirect.Host == "" {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "PKCE S256 and response_type=code required", http.StatusBadRequest)
		return
	}
	account := s.Account
	if s.AccountParam != "" && q.Get(s.AccountParam) != "" {
		account = q.Get(s.AccountParam)
	}
	if account == "" {
		account = "alice"
	}
	code := token()
	s.mu.Lock()
	if s.codes == nil {
		s.codes = map[string]grant{}
	}
	s.codes[code] = grant{account: account, challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"),
		clientID: q.Get("client_id"), resource: q.Get("resource")}
	s.mu.Unlock()
	back := redirect.Query()
	back.Set("code", code)
	back.Set("state", q.Get("state"))
	redirect.RawQuery = back.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f := r.PostForm
	if f.Get("resource") != s.Resource() {
		oauthError(w, 400, "invalid_target", "resource must be "+s.Resource())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var account string
	switch f.Get("grant_type") {
	case "authorization_code":
		g, ok := s.codes[f.Get("code")]
		delete(s.codes, f.Get("code"))
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		switch {
		case !ok:
			oauthError(w, 400, "invalid_grant", "unknown or used code")
			return
		case base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge:
			oauthError(w, 400, "invalid_grant", "PKCE verification failed")
			return
		case f.Get("redirect_uri") != g.redirect || f.Get("resource") != g.resource:
			oauthError(w, 400, "invalid_grant", "redirect_uri or resource differ")
			return
		}
		account = g.account
	case "refresh_token":
		a, ok := s.refresh[f.Get("refresh_token")]
		if !ok {
			oauthError(w, 400, "invalid_grant", "unknown refresh token")
			return
		}
		delete(s.refresh, f.Get("refresh_token")) // rotated
		account = a
		s.refreshN++
	default:
		oauthError(w, 400, "unsupported_grant_type", f.Get("grant_type"))
		return
	}
	at, rt := token(), token()
	if s.access == nil {
		s.access = map[string]string{}
	}
	if s.refresh == nil {
		s.refresh = map[string]string{}
	}
	s.access[at], s.refresh[rt] = account, account
	exp := s.ExpiresIn
	if exp == 0 {
		exp = time.Hour
	}
	writeJSON(w, 200, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(exp.Seconds()),
		"refresh_token": rt, "scope": "mcp.read"})
}

// mcp is the MCP endpoint: JSON answers only, and every request needs an
// issued access token.
func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	account, ok := s.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	s.mu.Unlock()
	if !ok {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, s.Base))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	case http.MethodDelete:
		w.WriteHeader(http.StatusOK)
		return
	}
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&m) != nil || len(m.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var res any
	switch m.Method {
	case "initialize":
		w.Header().Set("Mcp-Session-Id", "s-"+account)
		res = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{"name": "oauthtest"}}
	case "tools/list":
		res = map[string]any{"tools": []any{map[string]any{"name": "whoami", "inputSchema": map[string]any{"type": "object"}}}}
	case "tools/call":
		res = map[string]any{"content": []any{map[string]any{"type": "text", "text": "signed in as " + account}}}
	default:
		res = map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": res})
}
