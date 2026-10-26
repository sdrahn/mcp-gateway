package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// serveIdP is an OpenID provider for the gateway's own HTTP listener
// (privsrv -idp ADDR CERTFILE [CLIENT...]), over TLS for
// https://idp.vmtest: OIDC discovery and the key set the gateway
// validates tokens with, and GET /token, which hands out the access
// token its parameters describe, for the test to send as a remote agent
// would:
//
//	sub, aud, scope, preferred_username, groups (comma-separated)
//	exp    seconds from now (default 3600; negative: expired)
//	key    "other": signed with a key not in the key set
//
// For the gateway's approval page it also signs users in with the
// authorization code flow and PKCE (S256), for the clients given as
// ID[:SECRET]=REDIRECT_URI: GET /login?user=U[&groups=A,B] signs U in at
// the provider (a cookie, as a real provider's session; no form), then
// GET /authorize sends the browser back to the client's redirect URI
// with a code, and POST /oauth/token trades it for an ID token (sub and
// preferred_username U, the groups, the nonce). /authorize refuses an
// unknown client or redirect URI with 400, as providers do, and shows a
// sign-in form (200) to a browser no one signed in with, or when the
// client asks for the password again (prompt=login). GET /logout (the
// end_session_endpoint) ends the provider's sign-in and sends the browser
// to the client's post_logout_redirect_uri, which must be its redirect
// URI with /signed-out for /callback, and needs an id_token_hint. Discovery
// answers at every path ending in /.well-known/openid-configuration,
// always naming https://idp.vmtest: an http.issuer with a path is an
// issuer that does not match.
//
// A client given as ID=device is a public client of the device flow
// (RFC 8628), for mcp-gateway-admin approvals login --gateway: POST
// /device/code hands out a code, GET /device?user_code=CODE confirms it
// for the user /login signed in (without, a sign-in form), and POST
// /oauth/token answers authorization_pending until then, then with an ID
// token (5 minutes) and a refresh token, which renews it.
func serveIdP(addr, certFile string, clientArgs []string) error {
	cert, err := selfSigned("idp.vmtest", certFile)
	if err != nil {
		return err
	}
	const issuer = "https://idp.vmtest"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	clients := map[string]idpClient{}
	for _, a := range clientArgs {
		id, uri, ok := strings.Cut(a, "=")
		if !ok {
			return fmt.Errorf("client %q: want ID[:SECRET]=REDIRECT_URI", a)
		}
		id, secret, _ := strings.Cut(id, ":")
		clients[id] = idpClient{secret: secret, redirectURI: uri}
	}
	var mu sync.Mutex
	codes := map[string]idpCode{}
	devices := map[string]*idpCode{} // by device code; user set when confirmed
	userCodes := map[string]string{} // user code → device code
	refreshes := map[string]idpCode{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{path...}", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks",
			"authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/oauth/token",
			"device_authorization_endpoint":                  issuer + "/device/code",
			"end_session_endpoint":                           issuer + "/logout",
			"code_challenge_methods_supported":               []string{"S256"},
			"authorization_response_iss_parameter_supported": true,
		})
	})
	who := func(r *http.Request) map[string]string {
		var u map[string]string
		if ck, err := r.Cookie("idp_user"); err == nil {
			raw, _ := base64.RawURLEncoding.DecodeString(ck.Value)
			_ = json.Unmarshal(raw, &u)
		}
		return u
	}
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		v, _ := json.Marshal(map[string]string{"user": r.URL.Query().Get("user"), "groups": r.URL.Query().Get("groups")})
		http.SetCookie(w, &http.Cookie{Name: "idp_user", Value: b64(v), Path: "/", Secure: true, HttpOnly: true})
		_, _ = fmt.Fprintf(w, "signed in at the identity provider as %s\n", r.URL.Query().Get("user"))
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		c, ok := clients[q.Get("client_id")]
		switch {
		case !ok:
			http.Error(w, "unknown client "+q.Get("client_id"), http.StatusBadRequest)
			return
		case q.Get("redirect_uri") != c.redirectURI:
			http.Error(w, "redirect_uri "+q.Get("redirect_uri")+" is not registered for "+q.Get("client_id"), http.StatusBadRequest)
			return
		case q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
			http.Error(w, "authorization code with PKCE S256 only", http.StatusBadRequest)
			return
		}
		u := who(r)
		if u["user"] == "" || q.Get("prompt") == "login" {
			// As a provider's sign-in form: the request itself is fine.
			_, _ = fmt.Fprint(w, "<form>sign in at the identity provider (GET /login?user=...)</form>\n")
			return
		}
		code := b64(randomBytes(16))
		mu.Lock()
		codes[code] = idpCode{client: q.Get("client_id"), challenge: q.Get("code_challenge"), nonce: q.Get("nonce"),
			user: u["user"], groups: u["groups"], expires: time.Now().Add(time.Minute)}
		mu.Unlock()
		back := url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {issuer}}
		http.Redirect(w, r, c.redirectURI+"?"+back.Encode(), http.StatusFound)
	})
	mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		c, ok := clients[q.Get("client_id")]
		after := strings.TrimSuffix(c.redirectURI, "/callback") + "/signed-out"
		if !ok || q.Get("post_logout_redirect_uri") != after || q.Get("id_token_hint") == "" {
			http.Error(w, "unknown client, post_logout_redirect_uri or no id_token_hint", http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "idp_user", Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true})
		http.Redirect(w, r, after, http.StatusFound)
	})
	idToken := func(cd idpCode, aud string) (string, error) {
		now := time.Now()
		claims := map[string]any{"iss": issuer, "sub": cd.user, "aud": aud, "preferred_username": cd.user,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
		if cd.nonce != "" {
			claims["nonce"] = cd.nonce
		}
		if cd.groups != "" {
			claims["groups"] = strings.Split(cd.groups, ",")
		}
		return signES256(key, "k1", claims)
	}
	mux.HandleFunc("POST /device/code", func(w http.ResponseWriter, r *http.Request) {
		c, ok := clients[r.PostFormValue("client_id")]
		switch {
		case !ok:
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "invalid_client", "error_description": "unknown client " + r.PostFormValue("client_id")})
			return
		case c.redirectURI != "device":
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "unauthorized_client", "error_description": "the device grant is not enabled for " + r.PostFormValue("client_id")})
			return
		}
		dc, uc := b64(randomBytes(16)), strings.ToUpper(fmt.Sprintf("%x", randomBytes(4)))
		mu.Lock()
		devices[dc] = &idpCode{client: r.PostFormValue("client_id"), expires: time.Now().Add(5 * time.Minute)}
		userCodes[uc] = dc
		mu.Unlock()
		writeJSON(w, map[string]any{"device_code": dc, "user_code": uc, "verification_uri": issuer + "/device",
			"verification_uri_complete": issuer + "/device?user_code=" + uc, "expires_in": 300, "interval": 1})
	})
	mux.HandleFunc("GET /device", func(w http.ResponseWriter, r *http.Request) {
		u := who(r)
		if u["user"] == "" {
			_, _ = fmt.Fprint(w, "<form>sign in at the identity provider (GET /login?user=...), then confirm the code</form>\n")
			return
		}
		mu.Lock()
		d := devices[userCodes[r.URL.Query().Get("user_code")]]
		if d != nil {
			d.user, d.groups = u["user"], u["groups"]
		}
		mu.Unlock()
		if d == nil {
			http.Error(w, "unknown code", http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, "confirmed for %s\n", u["user"])
	})
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		fail := func(status int, code string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
		}
		switch r.PostFormValue("grant_type") {
		case "urn:ietf:params:oauth:grant-type:device_code", "refresh_token":
			id := r.PostFormValue("client_id")
			mu.Lock()
			var cd idpCode
			ok := false
			if r.PostFormValue("grant_type") == "refresh_token" {
				cd, ok = refreshes[r.PostFormValue("refresh_token")]
			} else if d := devices[r.PostFormValue("device_code")]; d != nil {
				if d.user == "" {
					mu.Unlock()
					fail(http.StatusBadRequest, "authorization_pending")
					return
				}
				cd, ok = *d, true
				delete(devices, r.PostFormValue("device_code"))
			}
			mu.Unlock()
			if !ok || cd.client != id || time.Now().After(cd.expires) && r.PostFormValue("grant_type") != "refresh_token" {
				fail(http.StatusBadRequest, "invalid_grant")
				return
			}
			tok, err := idToken(cd, id)
			if err != nil {
				fail(http.StatusInternalServerError, "server_error")
				return
			}
			rt := r.PostFormValue("refresh_token")
			if rt == "" {
				rt = b64(randomBytes(16))
				mu.Lock()
				refreshes[rt] = cd
				mu.Unlock()
			}
			writeJSON(w, map[string]any{"access_token": b64(randomBytes(16)), "token_type": "Bearer", "expires_in": 300,
				"id_token": tok, "refresh_token": rt})
			return
		}
		id, secret, basic := r.BasicAuth()
		if basic {
			id, _ = url.QueryUnescape(id)
			secret, _ = url.QueryUnescape(secret)
		} else {
			id = r.PostFormValue("client_id")
		}
		c, ok := clients[id]
		if !ok || secret != c.secret {
			fail(http.StatusUnauthorized, "invalid_client")
			return
		}
		mu.Lock()
		cd, ok := codes[r.PostFormValue("code")]
		delete(codes, r.PostFormValue("code"))
		mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if !ok || cd.client != id || time.Now().After(cd.expires) || b64(sum[:]) != cd.challenge ||
			r.PostFormValue("grant_type") != "authorization_code" || r.PostFormValue("redirect_uri") != c.redirectURI {
			fail(http.StatusBadRequest, "invalid_grant")
			return
		}
		tok, err := idToken(cd, id)
		if err != nil {
			fail(http.StatusInternalServerError, "server_error")
			return
		}
		writeJSON(w, map[string]any{"access_token": b64(randomBytes(16)), "token_type": "Bearer", "expires_in": 300, "id_token": tok})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []any{map[string]any{
			"kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256",
			"x": b64(pad32(key.X.Bytes())), "y": b64(pad32(key.Y.Bytes())),
		}}})
	})
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		exp := 3600
		if s := q.Get("exp"); s != "" {
			if exp, err = strconv.Atoi(s); err != nil {
				http.Error(w, "exp: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		now := time.Now()
		claims := map[string]any{"iss": issuer, "sub": q.Get("sub"), "aud": q.Get("aud"),
			"iat": now.Unix(), "exp": now.Add(time.Duration(exp) * time.Second).Unix()}
		for _, c := range []string{"scope", "preferred_username"} {
			if v := q.Get(c); v != "" {
				claims[c] = v
			}
		}
		if g := q.Get("groups"); g != "" {
			claims["groups"] = strings.Split(g, ",")
		}
		signer, kid := key, "k1"
		if q.Get("key") == "other" {
			signer, kid = other, "k2"
		}
		tok, err := signES256(signer, kid, claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprint(w, tok)
	})
	srv := &http.Server{Addr: addr, Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServeTLS("", "")
}

// signES256 makes a JWS (compact form) of claims with key.
func signES256(key *ecdsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64(append(pad32(r.Bytes()), pad32(s.Bytes())...)), nil
}

type idpClient struct{ secret, redirectURI string }

type idpCode struct {
	client, challenge, nonce, user, groups string
	expires                                time.Time
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pad32 left-pads a P-256 coordinate or signature half to 32 bytes.
func pad32(b []byte) []byte {
	return append(make([]byte, 32-len(b)), b...)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
