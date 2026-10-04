package signin

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"time"
)

// callbackTimeout bounds the code exchange the callback waits for.
const callbackTimeout = time.Minute

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{{.Title}}</title>
<style>body{font-family:sans-serif;max-width:40em;margin:4em auto;padding:0 1em;line-height:1.5}</style>
</head><body><h1>{{.Title}}</h1><p>{{.Text}}</p></body></html>
`))

// Handler serves the callback (GET /oauth/callback) and the client ID
// metadata document (GET /oauth/client.json) on the gateway's HTTP
// listener. Neither needs a bearer token: the callback is bound to its
// pending sign-in by the state, which only the principal got.
func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/callback", m.callback)
	mux.HandleFunc("GET /oauth/client.json", m.clientMetadata)
	return mux
}

func (m *Manager) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), callbackTimeout)
	defer cancel()
	pd, err := m.Complete(ctx, q.Get("state"), q.Get("code"), q.Get("error"), q.Get("error_description"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	data := struct{ Title, Text string }{"Signed in", ""}
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		data.Title, data.Text = "Sign-in failed", err.Error()
		if pd != nil {
			data.Text = "Signing in to " + pd.Server + " failed: " + err.Error()
		}
	} else {
		data.Text = "You are signed in to " + pd.Server + ". Return to your agent; it goes on by itself."
	}
	_ = page.Execute(w, data)
}

func (m *Manager) clientMetadata(w http.ResponseWriter, _ *http.Request) {
	if m.ClientMetadataURL == "" {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=3600")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client_id":                  m.ClientMetadataURL,
		"client_name":                "mcp-gateway",
		"redirect_uris":              []string{m.RedirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}
