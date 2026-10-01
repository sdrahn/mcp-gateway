// Package control serves the gateway's control API to local users over a
// unix socket: pending approvals (decide on them), grants (list, revoke),
// backend servers and their instances (list, stop) and the policy status.
// Callers are identified by kernel peer credentials, so a Cockpit
// page talking to the socket through cockpit.http({unix: ...}) acts as
// the logged-in Cockpit user. What a caller may see and do is decided by
// policy (data.mcp.approvals: by default their own approvals and grants,
// and everyone's for the admin role).
//
// API (JSON):
//
//	GET    /v1/whoami
//	GET    /v1/status           {"restart_pending": true} after an update
//	GET    /v1/approvals
//	GET    /v1/approvals/{id}
//	POST   /v1/approvals/{id}   {"decision": "approve"|"deny", "scope": "session"}
//	GET    /v1/grants
//	DELETE /v1/grants/{id}
//	GET    /v1/servers          registry, with the instances the caller may see
//	DELETE /v1/instances/{id}   stop an instance
//	GET    /v1/policy           active policy bundles and their revisions, roles shipped by server setups
//	POST   /v1/policy/whatif    role data → the decisions it would change
//	GET    /v1/events           server-sent events: approvals the caller may decide on
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os/user"
	"sort"
	"strconv"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/router"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// Instances lists and stops backend instances (router.Router).
type Instances interface {
	Instances() []router.InstanceInfo
	StopInstance(id string) bool
}

// PolicyStatus reports the policy OPA has activated (pep.OPA).
type PolicyStatus interface {
	Bundles(ctx context.Context) (map[string]string, error)
}

// ShippedRoleSource also lists the roles of the server setup packages
// (pep.OPA: data.mcp.profiles).
type ShippedRoleSource interface {
	ShippedRoles(ctx context.Context) (json.RawMessage, error)
}

// shippedRole is a role a server setup package ships, as GET /v1/policy
// shows it.
type shippedRole struct {
	Setup       string          `json:"setup"`
	Description string          `json:"description,omitempty"`
	Permissions json.RawMessage `json:"permissions"`
}

// PolicyReview answers "what changes?" for proposed role data (pep.OPA).
type PolicyReview interface {
	RoleData(ctx context.Context) (json.RawMessage, error)
	WhatIf(ctx context.Context, in pep.WhatIfInput) ([]pep.Change, error)
}

// Catalog lists what the MCP servers offer (router.Router).
type Catalog interface {
	Catalog(ctx context.Context) router.Catalog
}

type peerKey struct{}

// Server is the control API.
type Server struct {
	Broker *broker.Broker
	// Backends is the server registry; Instances and Policy are optional.
	Backends  map[string]*config.Backend
	Instances Instances
	Policy    PolicyStatus
	// Review and Catalog serve POST /v1/policy/whatif; both optional.
	Review  PolicyReview
	Catalog Catalog
	Log     *slog.Logger
	// Identify maps peer credentials to an approver; defaults to NSS.
	Identify func(transport.PeerCred) (broker.Approver, error)
	// RestartPending, if set, tells whether the gateway's program was
	// replaced (the package does not restart it on update).
	RestartPending func() bool

	stopping <-chan struct{} // closed when Serve's context ends
}

// Serve serves the API on l until ctx ends.
func (s *Server) Serve(ctx context.Context, l *transport.UnixListener) error {
	s.stopping = ctx.Done() // ends event streams, which would delay Shutdown
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if uc, ok := c.(*transport.UnixConn); ok {
				return context.WithValue(ctx, peerKey{}, uc.Peer)
			}
			return ctx
		},
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	err := srv.Serve(listener{l})
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// listener adapts a transport.UnixListener to net.Listener.
type listener struct{ l *transport.UnixListener }

func (l listener) Accept() (net.Conn, error) { return l.l.Accept() }
func (l listener) Close() error              { return l.l.Close() }
func (l listener) Addr() net.Addr            { return &net.UnixAddr{Name: l.l.Addr(), Net: "unix"} }

// Handler returns the API handler. Requests must carry peer credentials
// in their context (see Serve); others are refused.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/whoami", s.with(func(w http.ResponseWriter, _ *http.Request, a broker.Approver) {
		writeJSON(w, http.StatusOK, a)
	}))
	mux.HandleFunc("GET /v1/status", s.with(func(w http.ResponseWriter, _ *http.Request, _ broker.Approver) {
		writeJSON(w, http.StatusOK, map[string]bool{"restart_pending": s.RestartPending != nil && s.RestartPending()})
	}))
	mux.HandleFunc("GET /v1/approvals", s.with(func(w http.ResponseWriter, r *http.Request, a broker.Approver) {
		writeJSON(w, http.StatusOK, s.Broker.ListPending(r.Context(), a))
	}))
	mux.HandleFunc("GET /v1/approvals/{id}", s.with(func(w http.ResponseWriter, r *http.Request, a broker.Approver) {
		p, err := s.Broker.GetPending(r.Context(), a, r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusNotFound, "no such approval")
			return
		}
		writeJSON(w, http.StatusOK, p)
	}))
	mux.HandleFunc("POST /v1/approvals/{id}", s.with(s.resolve))
	mux.HandleFunc("GET /v1/grants", s.with(func(w http.ResponseWriter, r *http.Request, a broker.Approver) {
		writeJSON(w, http.StatusOK, s.Broker.ListGrants(r.Context(), a))
	}))
	mux.HandleFunc("DELETE /v1/grants/{id}", s.with(func(w http.ResponseWriter, r *http.Request, a broker.Approver) {
		if err := s.Broker.RevokeGrant(r.Context(), a, r.PathValue("id")); err != nil {
			writeError(w, http.StatusNotFound, "no such grant")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("GET /v1/servers", s.with(s.servers))
	mux.HandleFunc("DELETE /v1/instances/{id}", s.with(s.stopInstance))
	mux.HandleFunc("GET /v1/policy", s.with(s.policy))
	mux.HandleFunc("POST /v1/policy/whatif", s.with(s.whatIf))
	mux.HandleFunc("GET /v1/events", s.with(s.events))
	return mux
}

// serverInfo is a registry entry as the API shows it (without command
// and environment, which may carry secrets).
type serverInfo struct {
	Name        string                `json:"name"`
	SELinuxType string                `json:"selinux_type"`
	Isolation   config.Isolation      `json:"isolation"`
	Network     bool                  `json:"network"`
	RunAs       string                `json:"run_as"`
	Privileged  bool                  `json:"privileged,omitempty"`
	Instances   []router.InstanceInfo `json:"instances"`
}

func (s *Server) servers(w http.ResponseWriter, r *http.Request, a broker.Approver) {
	byServer := map[string][]router.InstanceInfo{}
	if s.Instances != nil {
		for _, in := range s.Instances.Instances() {
			if s.Broker.MayManageInstance(r.Context(), a, in.Server, in.UID) {
				byServer[in.Server] = append(byServer[in.Server], in)
			}
		}
	}
	out := []serverInfo{}
	for name, b := range s.Backends {
		insts := byServer[name]
		if insts == nil {
			insts = []router.InstanceInfo{}
		}
		out = append(out, serverInfo{Name: name, SELinuxType: b.SELinuxType, Isolation: b.Isolation,
			Network: b.Network, RunAs: b.RunAs, Privileged: b.Privileged, Instances: insts})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) stopInstance(w http.ResponseWriter, r *http.Request, a broker.Approver) {
	id := r.PathValue("id")
	if s.Instances != nil {
		for _, in := range s.Instances.Instances() {
			if in.ID == id && s.Broker.MayManageInstance(r.Context(), a, in.Server, in.UID) {
				if in.Privileged && in.Busy {
					writeError(w, http.StatusConflict, "a call to this privileged server is running; it stops when the call ends")
					return
				}
				if s.Instances.StopInstance(id) {
					if s.Log != nil {
						s.Log.Info("instance stopped via control API", "instance", id, "server", in.Server, "by", a.Name)
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
	}
	writeError(w, http.StatusNotFound, "no such instance")
}

func (s *Server) policy(w http.ResponseWriter, r *http.Request, _ broker.Approver) {
	if s.Policy == nil {
		writeError(w, http.StatusNotFound, "no policy status")
		return
	}
	bundles, err := s.Policy.Bundles(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "policy engine unavailable")
		return
	}
	mode := "directories"
	if len(bundles) > 0 {
		mode = "bundle"
	}
	resp := map[string]any{"mode": mode, "bundles": bundles}
	if src, ok := s.Policy.(ShippedRoleSource); ok {
		raw, err := src.ShippedRoles(r.Context())
		if err != nil {
			writeError(w, http.StatusBadGateway, "policy engine unavailable")
			return
		}
		roles := map[string]shippedRole{}
		var setups map[string]struct {
			Roles map[string]shippedRole `json:"roles"`
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &setups); err != nil {
				writeError(w, http.StatusBadGateway, "invalid shipped roles")
				return
			}
		}
		for setup, d := range setups {
			for name, role := range d.Roles {
				role.Setup = setup
				roles[name] = role
			}
		}
		resp["shipped_roles"] = roles
	}
	writeJSON(w, http.StatusOK, resp)
}

// maxRoleData bounds the proposed role data of POST /v1/policy/whatif.
const maxRoleData = 4 << 20

// whatIf answers which decisions proposed role data (the request body, as
// in rbac/data.json) would change, for the users and groups the current
// and the proposed bindings name, over what the MCP servers offer.
func (s *Server) whatIf(w http.ResponseWriter, r *http.Request, a broker.Approver) {
	if s.Review == nil || s.Catalog == nil {
		writeError(w, http.StatusNotFound, "no policy review")
		return
	}
	if !s.Broker.MayReviewPolicy(r.Context(), a) {
		writeError(w, http.StatusForbidden, "not allowed to review policy changes")
		return
	}
	proposed, err := io.ReadAll(io.LimitReader(r.Body, maxRoleData+1))
	if err != nil || len(proposed) > maxRoleData {
		writeError(w, http.StatusBadRequest, "role data missing or too large")
		return
	}
	var next roleBindings
	if err := json.Unmarshal(proposed, &next); err != nil {
		writeError(w, http.StatusBadRequest, "role data is not a JSON object: "+err.Error())
		return
	}
	current, err := s.Review.RoleData(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "policy engine unavailable")
		return
	}
	var cur roleBindings
	if len(current) > 0 {
		_ = json.Unmarshal(current, &cur)
	}
	catalog := s.Catalog.Catalog(r.Context())
	in := pep.WhatIfInput{
		Principals: whatIfPrincipals(cur, next),
		Resources:  catalog.Resources,
		Proposed:   proposed,
	}
	changes, err := s.Review.WhatIf(r.Context(), in)
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("policy review failed", "err", err)
		}
		writeError(w, http.StatusBadGateway, "policy review failed")
		return
	}
	sort.Slice(changes, func(i, j int) bool {
		ci, cj := changes[i], changes[j]
		if ci.Principal != cj.Principal {
			return ci.Principal < cj.Principal
		}
		if ci.Server != cj.Server {
			return ci.Server < cj.Server
		}
		if ci.Kind != cj.Kind {
			return ci.Kind < cj.Kind
		}
		return ci.Name < cj.Name
	})
	if changes == nil {
		changes = []pep.Change{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"changes":    changes,
		"principals": len(in.Principals),
		"resources":  len(in.Resources),
		"unchecked":  catalog.Unchecked,
	})
}

// roleBindings is the part of the role data that names principals.
type roleBindings struct {
	Bindings struct {
		Users  map[string]json.RawMessage `json:"users"`
		Groups map[string]json.RawMessage `json:"groups"`
	} `json:"bindings"`
}

// whatIfPrincipals are the users and groups bound in either role data:
// users as the gateway would see them (local account: uid, groups and home
// from NSS; else a remote principal), groups as a member bound to nothing
// else.
func whatIfPrincipals(datas ...roleBindings) []pep.WhatIfPrincipal {
	users, groups := map[string]bool{}, map[string]bool{}
	for _, d := range datas {
		for u := range d.Bindings.Users {
			users[u] = true
		}
		for g := range d.Bindings.Groups {
			groups[g] = true
		}
	}
	var out []pep.WhatIfPrincipal
	for _, name := range sortedSet(users) {
		out = append(out, pep.WhatIfPrincipal{Label: "user:" + name, Principal: lookupPrincipal(name)})
	}
	for _, g := range sortedSet(groups) {
		out = append(out, pep.WhatIfPrincipal{Label: "group:" + g, Principal: principal.Principal{
			Groups: []string{g}, Transport: principal.TransportUnix,
		}})
	}
	return out
}

func lookupPrincipal(name string) principal.Principal {
	u, err := user.Lookup(name)
	if err != nil {
		return principal.Principal{Sub: name, Transport: principal.TransportHTTP}
	}
	p := principal.Principal{Sub: name, Home: u.HomeDir, Transport: principal.TransportUnix}
	if id, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
		uid := uint32(id)
		p.UID = &uid
	}
	if gids, err := u.GroupIds(); err == nil {
		for _, gid := range gids {
			if g, err := user.LookupGroupId(gid); err == nil {
				p.Groups = append(p.Groups, g.Name)
			}
		}
	}
	return p
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// eventKeepAlive is the interval of SSE comments that keep idle event
// streams (and proxies) alive.
var eventKeepAlive = 25 * time.Second

// approvalEvent is one event of GET /v1/events.
type approvalEvent struct {
	Type    string          `json:"type"` // "pending" or "resolved"
	ID      string          `json:"id"`
	New     bool            `json:"new,omitempty"`
	Pending *broker.Pending `json:"pending,omitempty"`
	URL     string          `json:"url,omitempty"` // the approval page
}

// events streams the approvals the caller may decide on as server-sent
// events: first the pending ones, then changes. Desktop notification
// agents (mcp-gateway-notify) use it.
func (s *Server) events(w http.ResponseWriter, r *http.Request, a broker.Approver) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	ch, stop := s.Broker.Subscribe() // before listing: nothing is missed
	defer stop()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	sent := map[string]bool{}
	write := func(ev approvalEvent) bool {
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
	for _, p := range s.Broker.ListPending(r.Context(), a) {
		sent[p.ID] = true
		if !write(approvalEvent{Type: "pending", ID: p.ID, Pending: &p, URL: s.Broker.ApprovalURL(p.ID)}) {
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
			case ev.Type == "pending" && s.Broker.MayApprove(r.Context(), a, *ev.Pending):
				sent[ev.ID] = true
				if !write(approvalEvent{Type: ev.Type, ID: ev.ID, New: ev.New, Pending: ev.Pending, URL: s.Broker.ApprovalURL(ev.ID)}) {
					return
				}
			case ev.Type == "resolved" && sent[ev.ID]:
				delete(sent, ev.ID)
				if !write(approvalEvent{Type: ev.Type, ID: ev.ID}) {
					return
				}
			}
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		case <-s.stopping:
			return
		}
	}
}

func (s *Server) resolve(w http.ResponseWriter, r *http.Request, a broker.Approver) {
	var body struct {
		Decision string `json:"decision"`
		Scope    string `json:"scope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.Decision != "approve" && body.Decision != "deny" {
		writeError(w, http.StatusBadRequest, `decision must be "approve" or "deny"`)
		return
	}
	g, err := s.Broker.Resolve(r.Context(), a, r.PathValue("id"), body.Decision == "approve", body.Scope)
	switch {
	case errors.Is(err, broker.ErrNotFound), errors.Is(err, broker.ErrForbidden):
		writeError(w, http.StatusNotFound, "no such approval")
	case errors.Is(err, broker.ErrBadScope):
		writeError(w, http.StatusBadRequest, "scope not offered")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal error")
	case g == nil:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusOK, g)
	}
}

// with identifies the caller and passes them to h.
func (s *Server) with(h func(http.ResponseWriter, *http.Request, broker.Approver)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peer, ok := r.Context().Value(peerKey{}).(transport.PeerCred)
		if !ok {
			writeError(w, http.StatusForbidden, "no peer credentials")
			return
		}
		identify := s.Identify
		if identify == nil {
			identify = Identify
		}
		a, err := identify(peer)
		if err != nil {
			writeError(w, http.StatusForbidden, "unknown user")
			return
		}
		h(w, r, a)
	}
}

// WithPeer returns ctx carrying peer credentials, for serving the Handler
// through other means (tests).
func WithPeer(ctx context.Context, p transport.PeerCred) context.Context {
	return context.WithValue(ctx, peerKey{}, p)
}

// Identify resolves peer credentials through NSS.
func Identify(p transport.PeerCred) (broker.Approver, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(p.UID), 10))
	if err != nil {
		return broker.Approver{}, err
	}
	a := broker.Approver{Name: u.Username, UID: p.UID}
	if gids, err := u.GroupIds(); err == nil {
		for _, gid := range gids {
			if g, err := user.LookupGroupId(gid); err == nil {
				a.Groups = append(a.Groups, g.Name)
			}
		}
	}
	return a, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
