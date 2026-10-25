package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// serveWebhook is an approval webhook receiver (privsrv -webhook ADDR
// CERTFILE SECRETFILE), over TLS for https://hooks.vmtest, as a chat bot
// or ticket system would be: it checks the signature of each post
// (X-MCP-Gateway-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">
// with the secret in SECRETFILE, computed here on its own, not with the
// gateway's code), answers 401 to a post that fails it, and keeps the
// posts for the test:
//
//	GET /posts           what it got: [{"event", "verified", "body"}]
//	POST /decide         calls the gateway back for a pending approval it
//	                     got, with the form fields id, decision, scope,
//	                     approver and mode: "signed" (default),
//	                     "unsigned", "stale" (signed ten minutes ago),
//	                     "wrong-secret", "as-post" (signed as a post is,
//	                     which is no callback's signature), or "replay"
//	                     (the last signed callback sent again, byte for
//	                     byte); with hook, to that webhook's callback (as
//	                     its receiver, sharing the secret); answers
//	                     {"status", "body"}: the gateway's answer
//	POST /redirect       answers 307 to http://hooks.vmtest/stolen
func serveWebhook(addr, certFile, secretFile string) error {
	cert, err := selfSigned("hooks.vmtest", certFile)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(secretFile)
	if err != nil {
		return err
	}
	secret := []byte(strings.TrimSpace(string(raw)))
	// sign signs a callback: the HMAC covers "callback.<t>.<body>" (a
	// post's covers "<t>.<body>"), or as a post with asPost.
	sign := func(key, body []byte, t time.Time, asPost bool) string {
		ts := strconv.FormatInt(t.Unix(), 10)
		m := hmac.New(sha256.New, key)
		if !asPost {
			m.Write([]byte("callback."))
		}
		m.Write([]byte(ts + "."))
		m.Write(body)
		return "t=" + ts + ",v1=" + hex.EncodeToString(m.Sum(nil))
	}
	verify := func(body []byte, header string) bool {
		var ts, sig string
		for _, part := range strings.Split(header, ",") {
			k, v, _ := strings.Cut(part, "=")
			switch k {
			case "t":
				ts = v
			case "v1":
				sig = v
			}
		}
		t, err := strconv.ParseInt(ts, 10, 64)
		if err != nil || time.Since(time.Unix(t, 0)).Abs() > 5*time.Minute {
			return false
		}
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(ts + "."))
		m.Write(body)
		return hmac.Equal([]byte(sig), []byte(hex.EncodeToString(m.Sum(nil))))
	}
	type post struct {
		Event    string          `json:"event"`
		Verified bool            `json:"verified"`
		Body     json.RawMessage `json:"body"`
	}
	var (
		mu        sync.Mutex
		posts     []post
		callbacks = map[string]string{} // approval id → callback URL
		last      struct {
			url, sig string
			body     []byte
		}
	)
	// The gateway's certificate is in the system's trust store; the
	// gateway is reached directly.
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil}}
	mux := http.NewServeMux()
	// A receiver URL that redirects: the gateway must not follow it.
	mux.HandleFunc("POST /redirect", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(os.Stderr, "webhook: post to /redirect, sent on to http://hooks.vmtest/stolen\n")
		http.Redirect(w, r, "http://hooks.vmtest/stolen", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("POST /hook", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		ok := verify(body, r.Header.Get("X-MCP-Gateway-Signature"))
		var ev struct{ ID, Callback string }
		_ = json.Unmarshal(body, &ev)
		mu.Lock()
		posts = append(posts, post{r.Header.Get("X-MCP-Gateway-Event"), ok, json.RawMessage(body)})
		if ok && ev.Callback != "" {
			callbacks[ev.ID] = ev.Callback
		}
		mu.Unlock()
		fmt.Fprintf(os.Stderr, "webhook: %s verified=%v %s\n", r.Header.Get("X-MCP-Gateway-Event"), ok, body)
		if !ok {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /posts", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, append([]post{}, posts...))
	})
	mux.HandleFunc("POST /decide", func(w http.ResponseWriter, r *http.Request) {
		id, mode := r.FormValue("id"), r.FormValue("mode")
		mu.Lock()
		target := callbacks[id]
		replay := last
		mu.Unlock()
		if hook := r.FormValue("hook"); hook != "" && target != "" {
			// As another webhook's receiver, sharing the secret.
			target = target[:strings.LastIndex(target, "/")+1] + hook
		}
		var body []byte
		var sig string
		switch mode {
		case "replay":
			if replay.body == nil {
				http.Error(w, "nothing to replay", http.StatusConflict)
				return
			}
			target, body, sig = replay.url, replay.body, replay.sig
		default:
			if target == "" {
				http.Error(w, "no post for "+id, http.StatusNotFound)
				return
			}
			d := map[string]string{"id": id, "decision": r.FormValue("decision"), "approver": r.FormValue("approver")}
			if s := r.FormValue("scope"); s != "" {
				d["scope"] = s
			}
			body, _ = json.Marshal(d)
			switch mode {
			case "", "signed":
				sig = sign(secret, body, time.Now(), false)
				mu.Lock()
				last.url, last.sig, last.body = target, sig, body
				mu.Unlock()
			case "stale":
				sig = sign(secret, body, time.Now().Add(-10*time.Minute), false)
			case "wrong-secret":
				sig = sign([]byte("not the webhook's secret, but long"), body, time.Now(), false)
			case "as-post":
				sig = sign(secret, body, time.Now(), true)
			case "unsigned":
			default:
				http.Error(w, "unknown mode "+mode, http.StatusBadRequest)
				return
			}
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if sig != "" {
			req.Header.Set("X-MCP-Gateway-Signature", sig)
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		fmt.Fprintf(os.Stderr, "webhook: callback %s mode=%s: %d %s\n", id, mode, resp.StatusCode, b)
		writeJSON(w, map[string]any{"status": resp.StatusCode, "body": string(b)})
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	return srv.ListenAndServeTLS("", "")
}
