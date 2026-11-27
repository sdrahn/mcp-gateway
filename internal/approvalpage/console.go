package approvalpage

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/control"
)

// The console's API (docs/architecture.md, section 5.12.7, roadmap step
// 48): the control API's routes on the HTTPS listener, below
// /console/api/v1/ as below /v1/ on the control socket, with the caller
// the approval page's sign-in made instead of a local account. What the
// caller sees and does is the approver rules' decision, as on the
// socket (remote-user:<sub>, remote-group:<group>); a signed-in caller
// is never root.
//
// A request is signed in by either
//
//   - the page's session cookie, as in the console in a browser: a
//     request other than GET and HEAD carries the session's CSRF token in
//     X-CSRF-Token (GET /console/api/v1/session gives it) and comes from
//     the page's origin, as the page's own forms do; or
//   - the ID token of a device-flow sign-in as approvals.page.
//     device_client_id, as a bearer token (mcp-gateway-admin --gateway);
//     then no cookie counts.
//
// Decisions are audited with via=console (via=remote-cli with a bearer
// token), and every request that changes something with an
// mcp-console-action record: who, what, and the answer's status.
//
//	GET /console/api/v1/session    the caller, and the CSRF token of a cookie's session
//	... /console/api/v1/<route>    the control API's /v1/<route>

const (
	// ViaConsole is how decisions through the console are audited.
	ViaConsole = "console"
	// csrfHeader carries the session's CSRF token.
	csrfHeader = "X-CSRF-Token"
	consoleAPI = "/console/api/v1/"
)

// consoleSession is the body of GET /console/api/v1/session.
type consoleSession struct {
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
	Issuer string   `json:"issuer,omitempty"`
	// CSRF is the token a cookie's session sends in X-CSRF-Token; empty
	// for a bearer token.
	CSRF    string    `json:"csrf,omitempty"`
	Expires time.Time `json:"expires,omitzero"`
}

// consoleRoutes serves the console's API, if the page has the control
// API to serve.
func (pg *Page) consoleRoutes(mux *http.ServeMux) {
	if pg.Control == nil {
		return
	}
	mux.HandleFunc(consoleAPI, pg.consoleAPI)
	mux.HandleFunc("/console/", func(w http.ResponseWriter, _ *http.Request) {
		apiError(w, http.StatusNotFound, "no such endpoint")
	})
}

// consoleAPI signs a request in and hands it to the control API.
func (pg *Page) consoleAPI(w http.ResponseWriter, r *http.Request) {
	a, csrf, expires, via, ok := pg.consoleCaller(w, r)
	if !ok {
		return
	}
	route := strings.TrimPrefix(r.URL.Path, consoleAPI)
	if route == "session" {
		if r.Method != http.MethodGet {
			apiError(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		writeJSON(w, http.StatusOK, consoleSession{Name: a.Name, Groups: a.Groups, Issuer: a.Issuer, CSRF: csrf, Expires: expires})
		return
	}
	ctx := r.Context()
	if !expires.IsZero() {
		// Event streams end with the sign-in.
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, expires)
		defer cancel()
	}
	r2 := r.Clone(control.WithCaller(ctx, a, via))
	r2.URL.Path = "/v1/" + route
	r2.URL.RawPath = ""
	r2.RequestURI = r2.URL.RequestURI()
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		pg.Control.ServeHTTP(w, r2)
		return
	}
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	pg.Control.ServeHTTP(rec, r2)
	pg.auditAction(a, via, r.Method, route, rec.status)
}

// consoleCaller signs r in, by bearer token or session cookie, and
// answers it when it is not: the approver, a cookie's CSRF token, until
// when the sign-in holds, and how its decisions are audited.
func (pg *Page) consoleCaller(w http.ResponseWriter, r *http.Request) (a broker.Approver, csrf string, expires time.Time, via string, ok bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		raw, isBearer := strings.CutPrefix(h, "Bearer ")
		if !isBearer || strings.TrimSpace(raw) == "" || pg.DeviceClientID == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-gateway console"`)
			apiError(w, http.StatusUnauthorized, "only the ID token of a sign-in of the command line counts here (mcp-gateway-admin approvals login --gateway URL)")
			return
		}
		p, err := pg.Tokens.ApproverToken(r.Context(), strings.TrimSpace(raw), pg.DeviceClientID)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-gateway console", error="invalid_token"`)
			apiError(w, http.StatusUnauthorized, "the sign-in is not accepted: "+err.Error())
			return
		}
		return approverOf(p), "", p.Expires, ViaRemote, true
	}
	s := pg.current(r)
	if s == nil {
		apiError(w, http.StatusUnauthorized, "not signed in: open "+pg.Origin+"/approvals/ to sign in")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		for _, o := range r.Header.Values("Origin") {
			if o != pg.Origin {
				apiError(w, http.StatusForbidden, "this request came from another site ("+o+")")
				return
			}
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			apiError(w, http.StatusForbidden, "this request came from another site")
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeader)), []byte(s.CSRF)) != 1 {
			apiError(w, http.StatusForbidden, "no valid CSRF token (X-CSRF-Token, from GET "+consoleAPI+"session)")
			return
		}
	}
	pg.mu.Lock()
	a, csrf, expires = s.Approver, s.CSRF, s.expires
	pg.mu.Unlock()
	return a, csrf, expires, ViaConsole, true
}

// auditAction records a request of the console that changes something.
func (pg *Page) auditAction(a broker.Approver, via, method, route string, status int) {
	if pg.Audit == nil {
		return
	}
	pg.Audit.Event("mcp-console-action", status < 400, map[string]string{
		"by": a.Name, "issuer": a.Issuer, "via": via, "method": method, "route": "/v1/" + route,
		"status": http.StatusText(status),
	})
}

// statusRecorder keeps the status of an answer.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

// Flush passes on flushes (the control API's event stream).
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
