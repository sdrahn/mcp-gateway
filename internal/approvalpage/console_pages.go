package approvalpage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/control"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/router"
	"github.com/sdrahn/mcp-gateway/internal/signin"
)

// The console's pages (docs/architecture.md, section 5.12.7, roadmap
// step 48): the gateway's management page at /console/, beside the
// approvals at /approvals/, signed in as there. The pages are rendered
// on the gateway, without scripts, as the approval page is; each reads
// and acts through the control API's routes, as the console's API
// (console.go) serves them, so that what a page shows and does is the
// approver rules' decision as on the control socket, audited the same.
// The configuration is shown, not edited: it is changed where it is
// kept (the ConfigMaps from Git, or the files on a host).
//
//	GET  /console/                       the gateway's status and policy
//	GET  /console/servers                the servers, their definitions' keys and instances
//	POST /console/instances/{id}/stop
//	GET  /console/sessions               the clients, and those of the last 24 hours
//	POST /console/sessions/{id}/end
//	GET  /console/tasks
//	POST /console/tasks/{id}/cancel
//	GET  /console/sign-ins               principals' sign-ins to servers
//	POST /console/sign-ins/{server}/sign-out
//	GET  /console/doctor                 the doctor's checks in the gateway, as last run
//	POST /console/doctor                 run them now
//	GET  /console/policy                 the policy's bundles and shipped roles, the what-if
//	POST /console/policy/whatif          the decisions proposed role data would change

// maxRoleData bounds the role data the what-if takes from the form.
const maxRoleData = 1 << 20

// consoleServer is an entry of GET /v1/servers, as the console shows it.
type consoleServer struct {
	Name         string                `json:"name"`
	Isolation    string                `json:"isolation"`
	Network      bool                  `json:"network"`
	NetworkView  string                `json:"network_view"`
	RunAs        string                `json:"run_as"`
	Privileged   bool                  `json:"privileged"`
	Capabilities []string              `json:"capabilities"`
	SignIn       bool                  `json:"sign_in"`
	Landlock     bool                  `json:"landlock"`
	Removed      bool                  `json:"removed"`
	Instances    []router.InstanceInfo `json:"instances"`
}

// consoleStatus is GET /v1/status.
type consoleStatus struct {
	Version        string   `json:"version"`
	RestartPending bool     `json:"restart_pending"`
	ServersError   string   `json:"servers_error"`
	ConfigError    string   `json:"config_error"`
	RestartNeeded  []string `json:"restart_needed"`
	ConfigReloads  int      `json:"config_reloads"`
}

// consolePolicy is GET /v1/policy.
type consolePolicy struct {
	Mode         string            `json:"mode"`
	Bundles      map[string]string `json:"bundles"`
	ShippedRoles map[string]struct {
		Setup       string `json:"setup"`
		Description string `json:"description"`
	} `json:"shipped_roles"`
}

// consoleHistory is an entry of GET /v1/sessions/history.
type consoleHistory struct {
	router.SessionInfo
	Ended   *time.Time `json:"ended"`
	End     string     `json:"end"`
	EndedBy string     `json:"ended_by"`
	Calls   int        `json:"calls"`
	// EndedAt is Ended, for the template.
	EndedAt time.Time `json:"-"`
}

// consoleWhatIf is POST /v1/policy/whatif's answer.
type consoleWhatIf struct {
	Changes    []pep.Change      `json:"changes"`
	Principals int               `json:"principals"`
	Resources  int               `json:"resources"`
	Unchecked  map[string]string `json:"unchecked"`
}

// consoleSignIns is GET /v1/sign-ins.
type consoleSignIns struct {
	SignIns []signin.Entry       `json:"sign_ins"`
	Pending []signin.PendingInfo `json:"pending"`
}

// consolePages serves the console's pages, if the page has the control
// API.
func (pg *Page) consolePages(mux *http.ServeMux) {
	if pg.Control == nil {
		return
	}
	mux.HandleFunc("GET /console/{$}", pg.consoleOverview)
	mux.HandleFunc("GET /console/servers", pg.consoleServers)
	mux.HandleFunc("POST /console/instances/{id}/stop", pg.consoleAction(func(r *http.Request) (string, string, string, string) {
		return http.MethodDelete, "instances/" + url.PathEscape(r.PathValue("id")), "", "stopped instance " + r.PathValue("id")
	}, "/console/servers"))
	mux.HandleFunc("GET /console/sessions", pg.consoleSessions)
	mux.HandleFunc("POST /console/sessions/{id}/end", pg.consoleAction(func(r *http.Request) (string, string, string, string) {
		return http.MethodDelete, "sessions/" + url.PathEscape(r.PathValue("id")), "", "ended " + r.PathValue("id")
	}, "/console/sessions"))
	mux.HandleFunc("GET /console/tasks", pg.consoleTasks)
	mux.HandleFunc("POST /console/tasks/{id}/cancel", pg.consoleAction(func(r *http.Request) (string, string, string, string) {
		return http.MethodPost, "tasks/" + url.PathEscape(r.PathValue("id")) + "/cancel", "", "cancelled task " + r.PathValue("id")
	}, "/console/tasks"))
	mux.HandleFunc("GET /console/sign-ins", pg.consoleSignIns)
	mux.HandleFunc("POST /console/sign-ins/{server}/sign-out", pg.consoleAction(func(r *http.Request) (string, string, string, string) {
		q := url.Values{}
		for _, k := range []string{"principal", "transport", "iss"} {
			if v := r.PostFormValue(k); v != "" {
				q.Set(k, v)
			}
		}
		route := "sign-ins/" + url.PathEscape(r.PathValue("server"))
		if len(q) > 0 {
			route += "?" + q.Encode()
		}
		return http.MethodDelete, route, "", "signed " + r.PostFormValue("principal") + " out of " + r.PathValue("server")
	}, "/console/sign-ins"))
	mux.HandleFunc("GET /console/doctor", pg.consoleDoctor)
	mux.HandleFunc("POST /console/doctor", pg.consoleDoctor)
	mux.HandleFunc("GET /console/policy", pg.consolePolicy)
	mux.HandleFunc("POST /console/policy/whatif", pg.consoleWhatIf)
}

// call serves a control API request as s's: route is below /v1/. It
// decodes a 2xx answer into out and returns the status and, for an
// error, its message.
func (pg *Page) call(ctx context.Context, s *session, method, route, body string, out any) (int, string) {
	pg.mu.Lock()
	a, expires := s.Approver, s.expires
	pg.mu.Unlock()
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	req := httptest.NewRequestWithContext(control.WithCaller(ctx, a, ViaConsole), method, "/v1/"+route, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	pg.Control.ServeHTTP(rec, req)
	if method != http.MethodGet {
		pg.auditAction(a, ViaConsole, method, strings.SplitN(route, "?", 2)[0], rec.Code)
	}
	if rec.Code >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		if e.Error == "" {
			e.Error = http.StatusText(rec.Code)
		}
		return rec.Code, e.Error
	}
	if out != nil && rec.Code != http.StatusNoContent {
		if err := json.NewDecoder(io.LimitReader(rec.Body, 32<<20)).Decode(out); err != nil {
			return http.StatusInternalServerError, "the control API's answer: " + err.Error()
		}
	}
	return rec.Code, ""
}

// consoleAction is a form's action: it calls the control API as the
// signed-in caller (method, route, body from what), keeps what it did
// (or why not) for the next page, and goes back to back.
func (pg *Page) consoleAction(what func(*http.Request) (method, route, body, done string), back string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := pg.checkPost(w, r)
		if s == nil {
			return
		}
		method, route, body, done := what(r)
		if code, msg := pg.call(r.Context(), s, method, route, body, nil); code >= 300 {
			done = "refused (" + msg + ")"
		}
		pg.flash(s, done)
		http.Redirect(w, r, back, http.StatusSeeOther)
	}
}

// consoleData starts a page's data: the session, what the last action
// did, and the errors of the reads.
func (pg *Page) consoleData(s *session, title, nav string) map[string]any {
	pg.mu.Lock()
	done := s.done
	s.done = ""
	pg.mu.Unlock()
	return map[string]any{"S": s, "Title": title, "Nav": nav, "Msg": done, "Console": true}
}

// read calls GET route into out and notes a failure in d's "Errors".
func (pg *Page) read(r *http.Request, s *session, d map[string]any, route string, out any) {
	if code, msg := pg.call(r.Context(), s, http.MethodGet, route, "", out); code >= 300 {
		errs, _ := d["Errors"].([]string)
		d["Errors"] = append(errs, fmt.Sprintf("/v1/%s: %s", route, msg))
	}
}

func (pg *Page) consoleOverview(w http.ResponseWriter, r *http.Request) {
	s := pg.signedIn(w, r)
	if s == nil {
		return
	}
	d := pg.consoleData(s, "Gateway", "overview")
	var st consoleStatus
	var pol consolePolicy
	var servers []consoleServer
	var sessions []router.SessionInfo
	var tasks []router.TaskInfo
	var pending []json.RawMessage
	pg.read(r, s, d, "status", &st)
	pg.read(r, s, d, "policy", &pol)
	pg.read(r, s, d, "servers", &servers)
	pg.read(r, s, d, "sessions", &sessions)
	pg.read(r, s, d, "tasks", &tasks)
	pg.read(r, s, d, "approvals", &pending)
	instances, running := 0, 0
	for _, sv := range servers {
		instances += len(sv.Instances)
	}
	for _, t := range tasks {
		if t.Ended == nil {
			running++
		}
	}
	d["Status"], d["Policy"], d["Bundles"] = st, pol, sortedKeys(pol.Bundles)
	d["Servers"], d["Instances"], d["Sessions"], d["Tasks"], d["Pending"] = len(servers), instances, len(sessions), running, len(pending)
	pg.render(w, http.StatusOK, consoleOverviewTmpl, d)
}

func (pg *Page) consoleServers(w http.ResponseWriter, r *http.Request) {
	s := pg.signedIn(w, r)
	if s == nil {
		return
	}
	d := pg.consoleData(s, "Servers", "servers")
	var servers []consoleServer
	pg.read(r, s, d, "servers", &servers)
	d["List"] = servers
	pg.render(w, http.StatusOK, consoleServersTmpl, d)
}

func (pg *Page) consoleSessions(w http.ResponseWriter, r *http.Request) {
	s := pg.signedIn(w, r)
	if s == nil {
		return
	}
	d := pg.consoleData(s, "Sessions", "sessions")
	var sessions []router.SessionInfo
	var history []consoleHistory
	pg.read(r, s, d, "sessions", &sessions)
	pg.read(r, s, d, "sessions/history", &history)
	ended := history[:0]
	for _, h := range history {
		if h.Ended != nil {
			h.EndedAt = *h.Ended
			ended = append(ended, h)
		}
	}
	d["List"], d["History"] = sessions, ended
	pg.render(w, http.StatusOK, consoleSessionsTmpl, d)
}

func (pg *Page) consoleTasks(w http.ResponseWriter, r *http.Request) {
	s := pg.signedIn(w, r)
	if s == nil {
		return
	}
	d := pg.consoleData(s, "Tasks", "tasks")
	var tasks []router.TaskInfo
	pg.read(r, s, d, "tasks", &tasks)
	d["List"] = tasks
	pg.render(w, http.StatusOK, consoleTasksTmpl, d)
}

func (pg *Page) consoleSignIns(w http.ResponseWriter, r *http.Request) {
	s := pg.signedIn(w, r)
	if s == nil {
		return
	}
	d := pg.consoleData(s, "Sign-ins to servers", "sign-ins")
	var si consoleSignIns
	pg.read(r, s, d, "sign-ins", &si)
	d["List"] = si.SignIns
	pg.render(w, http.StatusOK, consoleSignInsTmpl, d)
}

// consoleDoctor shows the doctor's checks in the gateway; POST runs them
// first.
func (pg *Page) consoleDoctor(w http.ResponseWriter, r *http.Request) {
	var s *session
	if r.Method == http.MethodPost {
		s = pg.checkPost(w, r)
	} else {
		s = pg.signedIn(w, r)
	}
	if s == nil {
		return
	}
	d := pg.consoleData(s, "Doctor", "doctor")
	var rep control.DoctorReport
	if code, msg := pg.call(r.Context(), s, r.Method, "doctor", "", &rep); code >= 300 {
		d["DoctorError"] = msg
	} else {
		d["Report"] = rep
	}
	pg.render(w, http.StatusOK, consoleDoctorTmpl, d)
}

func (pg *Page) consolePolicy(w http.ResponseWriter, r *http.Request) {
	s := pg.signedIn(w, r)
	if s == nil {
		return
	}
	pg.renderPolicy(w, r, s, pg.consoleData(s, "Policy", "policy"))
}

func (pg *Page) renderPolicy(w http.ResponseWriter, r *http.Request, s *session, d map[string]any) {
	var pol consolePolicy
	pg.read(r, s, d, "policy", &pol)
	roles := sortedKeys(pol.ShippedRoles)
	d["Policy"], d["Bundles"], d["Roles"] = pol, sortedKeys(pol.Bundles), roles
	pg.render(w, http.StatusOK, consolePolicyTmpl, d)
}

// consoleWhatIf shows the decisions pasted role data would change; it
// changes nothing (the role data is changed where it is kept).
func (pg *Page) consoleWhatIf(w http.ResponseWriter, r *http.Request) {
	s := pg.checkPostLimit(w, r, maxRoleData)
	if s == nil {
		return
	}
	d := pg.consoleData(s, "Policy", "policy")
	data := strings.TrimSpace(r.PostFormValue("data"))
	d["Data"] = data
	var res consoleWhatIf
	if !json.Valid([]byte(data)) {
		d["WhatIfError"] = "the role data is not JSON"
	} else if code, msg := pg.call(r.Context(), s, http.MethodPost, "policy/whatif", data, &res); code >= 300 {
		d["WhatIfError"] = msg
	} else {
		d["WhatIf"] = res
		d["Unchecked"] = sortedKeys(res.Unchecked)
	}
	pg.renderPolicy(w, r, s, d)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
