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
	"strconv"
	"strings"
	"time"
)

// serveIdP is an OpenID provider for the gateway's own HTTP listener
// (privsrv -idp ADDR CERTFILE), over TLS for https://idp.vmtest: OIDC
// discovery and the key set the gateway validates tokens with, and
// /token, which hands out the access token its parameters describe, for
// the test to send as a remote agent would:
//
//	sub, aud, scope, preferred_username, groups (comma-separated)
//	exp    seconds from now (default 3600; negative: expired)
//	key    "other": signed with a key not in the key set
func serveIdP(addr, certFile string) error {
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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
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

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pad32 left-pads a P-256 coordinate or signature half to 32 bytes.
func pad32(b []byte) []byte {
	return append(make([]byte, 32-len(b)), b...)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
