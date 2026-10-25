package approvalpage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
)

// The approval API for the command line on another host (mcp-gateway-admin
// approvals --gateway; docs/architecture.md, step 39 stage D): the
// control API's approvals, grants and events, under /approvals/api, for
// an approver who signed in with the device flow as the client
// DeviceClientID. Its bearer token is that sign-in's ID token, nothing
// else: an agent's access token is for http.audience, not this client,
// and no cookie counts (so no other site can make a browser call it).
//
//	GET    /approvals/api/v1/client         the identity provider and client to sign in with
//	GET    /approvals/api/v1/whoami         who the token makes the approver
//	GET    /approvals/api/v1/approvals
//	GET    /approvals/api/v1/approvals/{id}
//	POST   /approvals/api/v1/approvals/{id} {"decision": "approve"|"deny", "scope": "once"}
//	GET    /approvals/api/v1/grants
//	DELETE /approvals/api/v1/grants/{id}
//	GET    /approvals/api/v1/events         server-sent events, until the token expires
//
// The fields are the control API's (internal/control).

// ViaRemote is how decisions made through the API are audited.
const ViaRemote = "remote-cli"

// eventKeepAlive is the interval of SSE comments on an idle events
// stream.
var eventKeepAlive = 25 * time.Second

func (pg *Page) apiRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /approvals/api/v1/client", pg.apiClient)
	mux.HandleFunc("GET /approvals/api/v1/whoami", pg.api(func(w http.ResponseWriter, r *http.Request, a broker.Approver, _ time.Time) {
		pg.audit(true, a.Name, "", ViaRemote)
		writeJSON(w, http.StatusOK, a)
	}))
	mux.HandleFunc("GET /approvals/api/v1/approvals", pg.api(func(w http.ResponseWriter, r *http.Request, a broker.Approver, _ time.Time) {
		writeJSON(w, http.StatusOK, pg.Broker.ListPending(r.Context(), a))
	}))
	mux.HandleFunc("GET /approvals/api/v1/approvals/{id}", pg.api(func(w http.ResponseWriter, r *http.Request, a broker.Approver, _ time.Time) {
		p, err := pg.Broker.GetPending(r.Context(), a, r.PathValue("id"))
		if err != nil {
			apiError(w, http.StatusNotFound, "no such approval")
			return
		}
		writeJSON(w, http.StatusOK, p)
	}))
	mux.HandleFunc("POST /approvals/api/v1/approvals/{id}", pg.api(pg.apiDecide))
	mux.HandleFunc("GET /approvals/api/v1/grants", pg.api(func(w http.ResponseWriter, r *http.Request, a broker.Approver, _ time.Time) {
		writeJSON(w, http.StatusOK, pg.Broker.ListGrants(r.Context(), a))
	}))
	mux.HandleFunc("DELETE /approvals/api/v1/grants/{id}", pg.api(func(w http.ResponseWriter, r *http.Request, a broker.Approver, _ time.Time) {
		if err := pg.Broker.RevokeGrantVia(r.Context(), a, r.PathValue("id"), ViaRemote); err != nil {
			apiError(w, http.StatusNotFound, "no such grant")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("GET /approvals/api/v1/events", pg.api(pg.apiEvents))
	mux.HandleFunc("/approvals/api/", func(w http.ResponseWriter, _ *http.Request) {
		apiError(w, http.StatusNotFound, "no such endpoint")
	})
}

// apiClient tells the command line where to sign in.
func (pg *Page) apiClient(w http.ResponseWriter, _ *http.Request) {
	if pg.DeviceClientID == "" {
		apiError(w, http.StatusNotFound, "this gateway takes no sign-ins of the command line (approvals.page.device_client_id)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"issuer": pg.Issuer, "client_id": pg.DeviceClientID})
}

// api authenticates a request with its bearer token, the ID token of a
// device-flow sign-in as DeviceClientID, and passes on the approver and
// until when the token is accepted.
func (pg *Page) api(h func(http.ResponseWriter, *http.Request, broker.Approver, time.Time)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if pg.DeviceClientID == "" {
			apiError(w, http.StatusNotFound, "this gateway takes no sign-ins of the command line (approvals.page.device_client_id)")
			return
		}
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-gateway approvals"`)
			apiError(w, http.StatusUnauthorized, "sign in first (mcp-gateway-admin approvals login --gateway URL)")
			return
		}
		p, err := pg.Tokens.ApproverToken(r.Context(), strings.TrimSpace(raw), pg.DeviceClientID)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-gateway approvals", error="invalid_token"`)
			apiError(w, http.StatusUnauthorized, "the sign-in is not accepted: "+err.Error())
			return
		}
		h(w, r, approverOf(p), p.Expires)
	}
}

func (pg *Page) apiDecide(w http.ResponseWriter, r *http.Request, a broker.Approver, _ time.Time) {
	var body struct {
		Decision string `json:"decision"`
		Scope    string `json:"scope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.Decision != "approve" && body.Decision != "deny" {
		apiError(w, http.StatusBadRequest, `decision must be "approve" or "deny"`)
		return
	}
	g, err := pg.Broker.ResolveVia(r.Context(), a, r.PathValue("id"), body.Decision == "approve", body.Scope, ViaRemote)
	switch {
	case errors.Is(err, broker.ErrNotFound), errors.Is(err, broker.ErrForbidden):
		apiError(w, http.StatusNotFound, "no such approval")
	case errors.Is(err, broker.ErrBadScope):
		apiError(w, http.StatusBadRequest, "scope not offered")
	case err != nil:
		pg.Log.Warn("approval API: deciding", "id", r.PathValue("id"), "err", err)
		apiError(w, http.StatusInternalServerError, "internal error")
	case g == nil:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusOK, g)
	}
}

// apiEvent is an event of /approvals/api/v1/events, as the control API's.
type apiEvent struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	New     bool            `json:"new,omitempty"`
	Pending *broker.Pending `json:"pending,omitempty"`
	URL     string          `json:"url,omitempty"`
}

// apiEvents streams the approvals a may decide on, first the pending
// ones, then changes, until the token expires (the command line signs
// in again and reconnects).
func (pg *Page) apiEvents(w http.ResponseWriter, r *http.Request, a broker.Approver, expires time.Time) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		apiError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	ctx := r.Context()
	if !expires.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, expires)
		defer cancel()
	}
	ch, stop := pg.Broker.Subscribe()
	defer stop()
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	sent := map[string]bool{}
	write := func(ev apiEvent) bool {
		data, err := json.Marshal(ev)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "event: approval\ndata: %s\n\n", data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	for _, p := range pg.Broker.ListPending(ctx, a) {
		sent[p.ID] = true
		if !write(apiEvent{Type: "pending", ID: p.ID, Pending: &p, URL: pg.Broker.ApprovalURL(p.ID)}) {
			return
		}
	}
	flusher.Flush()
	ping := time.NewTicker(eventKeepAlive)
	defer ping.Stop()
	for {
		select {
		case ev := <-ch:
			switch {
			case ev.Type == "pending" && ev.Pending != nil && pg.Broker.MayApprove(ctx, a, *ev.Pending):
				sent[ev.ID] = true
				if !write(apiEvent{Type: ev.Type, ID: ev.ID, New: ev.New, Pending: ev.Pending, URL: pg.Broker.ApprovalURL(ev.ID)}) {
					return
				}
			case ev.Type == "resolved" && sent[ev.ID]:
				delete(sent, ev.ID)
				if !write(apiEvent{Type: ev.Type, ID: ev.ID}) {
					return
				}
			}
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
