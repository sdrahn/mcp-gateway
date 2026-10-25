package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// remoteFake is a gateway's approval API and its identity provider with
// the device flow, in one server: ID tokens are unsigned JWT-shaped
// strings "h.<claims>.s" (the CLI reads only exp; the API checks them).
type remoteFake struct {
	srv       *httptest.Server
	mu        sync.Mutex
	confirmed bool
	ttl       time.Duration
	polls     int
	refreshes int
	decided   []string
	auths     []string
}

func fakeJWT(sub string, exp time.Time) string {
	c, _ := json.Marshal(map[string]any{"sub": sub, "exp": exp.Unix()})
	return "h." + base64.RawURLEncoding.EncodeToString(c) + ".s"
}

func newRemoteFake(t *testing.T) *remoteFake {
	t.Helper()
	f := &remoteFake{ttl: time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /approvals/api/v1/client", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.srv.URL + "/idp", "client_id": "approvals-cli"})
	})
	mux.HandleFunc("GET /idp/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.srv.URL + "/idp",
			"device_authorization_endpoint": f.srv.URL + "/idp/device", "token_endpoint": f.srv.URL + "/idp/token"})
	})
	mux.HandleFunc("POST /idp/device", func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("client_id") != "approvals-cli" {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "dc", "user_code": "ABCD-EFGH",
			"verification_uri": f.srv.URL + "/idp/device", "verification_uri_complete": f.srv.URL + "/idp/device?user_code=ABCD-EFGH",
			"expires_in": 30, "interval": 1})
	})
	mux.HandleFunc("POST /idp/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.PostFormValue("grant_type") {
		case "urn:ietf:params:oauth:grant-type:device_code":
			f.polls++
			if !f.confirmed {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": fakeJWT("jack", time.Now().Add(f.ttl)), "refresh_token": "rt-1"})
		case "refresh_token":
			f.refreshes++
			if r.PostFormValue("refresh_token") != "rt-1" {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": fakeJWT("jack", time.Now().Add(time.Hour)), "refresh_token": "rt-1"})
		}
	})
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			f.mu.Lock()
			f.auths = append(f.auths, tok)
			f.mu.Unlock()
			if exp := tokenExpiry(tok); exp.IsZero() || time.Now().After(exp) {
				w.WriteHeader(401)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "the sign-in is not accepted"})
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /approvals/api/v1/whoami", authed(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "jack", "groups": []string{"ops"}})
	}))
	mux.HandleFunc("GET /approvals/api/v1/approvals", authed(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[{"id":"a-0123456789abcdef","principal":{"sub":"ivy","transport":"unix","client":{}},"server":"fs","name":"read_file","action":"tools/call","scopes":["once","1h"],"waiting":true}]`)
	}))
	mux.HandleFunc("POST /approvals/api/v1/approvals/{id}", authed(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.decided = append(f.decided, r.PathValue("id")+" "+b["decision"]+" "+b["scope"])
		f.mu.Unlock()
		w.WriteHeader(204)
	}))
	mux.HandleFunc("GET /approvals/api/v1/grants", authed(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[]`)
	}))
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	old := remoteHTTP
	remoteHTTP = f.srv.Client()
	t.Cleanup(func() { remoteHTTP = old })
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	return f
}

func runCmd(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	rc := run(args, &out, &errb)
	return rc, out.String(), errb.String()
}

func TestRemoteLogin(t *testing.T) {
	f := newRemoteFake(t)
	gw := f.srv.URL
	if rc, _, stderr := runCmd("approvals", "--gateway", gw); rc != exitRefused || !strings.Contains(stderr, "not signed in to "+gw) {
		t.Errorf("before login: %d %s", rc, stderr)
	}
	go func() {
		time.Sleep(1500 * time.Millisecond)
		f.mu.Lock()
		f.confirmed = true
		f.mu.Unlock()
	}()
	rc, stdout, stderr := runCmd("approvals", "login", "--gateway", gw)
	if rc != 0 || !strings.Contains(stderr, "confirm the code ABCD-EFGH") || !strings.Contains(stderr, "/idp/device?user_code=ABCD-EFGH") ||
		!strings.Contains(stdout, "signed in to "+gw+" as jack (groups ops)") {
		t.Fatalf("login: %d %s %s", rc, stdout, stderr)
	}
	if f.polls < 2 {
		t.Errorf("polls %d: authorization_pending not waited for", f.polls)
	}
	path, _ := sessionFile(gw)
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("session file %v %v", fi, err)
	}
	if di, _ := os.Stat(filepath.Dir(path)); di.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", di.Mode())
	}

	rc, stdout, _ = runCmd("approvals", "--gateway", gw)
	if rc != 0 || !strings.Contains(stdout, "fs/read_file") {
		t.Errorf("list: %d %s", rc, stdout)
	}
	rc, stdout, _ = runCmd("approvals", "approve", "a-01", "--yes", "--gateway", gw)
	if rc != 0 || !strings.Contains(stdout, "approved a-012345") || len(f.decided) != 1 || f.decided[0] != "a-0123456789abcdef approve once" {
		t.Errorf("approve: %d %s %v", rc, stdout, f.decided)
	}
	if rc, _, _ = runCmd("grants", "--gateway", gw); rc != 0 {
		t.Errorf("grants: %d", rc)
	}

	// An expired ID token is renewed with the refresh token, and kept.
	var s remoteSession
	data, _ := os.ReadFile(path)
	_ = json.Unmarshal(data, &s)
	s.IDToken = fakeJWT("jack", time.Now().Add(-time.Minute))
	if err := s.save(path); err != nil {
		t.Fatal(err)
	}
	if rc, _, stderr = runCmd("approvals", "--gateway", gw); rc != 0 || f.refreshes != 1 {
		t.Errorf("refresh: %d %d %s", rc, f.refreshes, stderr)
	}
	data, _ = os.ReadFile(path)
	_ = json.Unmarshal(data, &s)
	if time.Until(tokenExpiry(s.IDToken)) < 30*time.Minute {
		t.Error("the renewed token is not kept")
	}
	// Without a refresh token: sign in again.
	s.IDToken, s.RefreshToken = fakeJWT("jack", time.Now().Add(-time.Minute)), ""
	_ = s.save(path)
	if rc, _, stderr = runCmd("approvals", "--gateway", gw); rc == 0 || !strings.Contains(stderr, "has expired: mcp-gateway-admin approvals login --gateway "+gw) {
		t.Errorf("expired: %d %s", rc, stderr)
	}
	// A token the gateway does not take (the fake: no exp).
	s.IDToken = "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"jack"}`)) + ".s"
	_ = s.save(path)
	if rc, _, stderr = runCmd("approvals", "--gateway", gw); rc != exitRefused || !strings.Contains(stderr, "is not accepted") {
		t.Errorf("refused token: %d %s", rc, stderr)
	}

	// A file others may read is not used.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if rc, _, stderr = runCmd("approvals", "--gateway", gw); rc == 0 || !strings.Contains(stderr, "may be read by others (mode 0644)") {
		t.Errorf("mode 0644: %d %s", rc, stderr)
	}
	if rc, stdout, _ = runCmd("approvals", "logout", "--gateway", gw); rc != 0 || !strings.Contains(stdout, "signed out of "+gw) {
		t.Errorf("logout: %d %s", rc, stdout)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("session file still there")
	}
}

func TestGatewayOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"gw.example.com:9443":                "https://gw.example.com:9443",
		"https://gw.example.com:9443/mcp":    "https://gw.example.com:9443",
		"https://gw.example.com/approvals/x": "https://gw.example.com",
	} {
		if got, err := gatewayOrigin(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	if _, err := gatewayOrigin("http://gw.example.com"); err == nil {
		t.Error("http accepted")
	}
}
