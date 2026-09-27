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
//	GET    /v1/approvals
//	GET    /v1/approvals/{id}
//	POST   /v1/approvals/{id}   {"decision": "approve"|"deny", "scope": "session"}
//	GET    /v1/grants
//	DELETE /v1/grants/{id}
//	GET    /v1/servers          registry, with the instances the caller may see
//	DELETE /v1/instances/{id}   stop an instance
//	GET    /v1/policy           active policy bundles and their revisions
package control

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os/user"
	"sort"
	"strconv"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
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

type peerKey struct{}

// Server is the control API.
type Server struct {
	Broker *broker.Broker
	// Backends is the server registry; Instances and Policy are optional.
	Backends  map[string]*config.Backend
	Instances Instances
	Policy    PolicyStatus
	Log       *slog.Logger
	// Identify maps peer credentials to an approver; defaults to NSS.
	Identify func(transport.PeerCred) (broker.Approver, error)
}

// Serve serves the API on l until ctx ends.
func (s *Server) Serve(ctx context.Context, l *transport.UnixListener) error {
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
			Network: b.Network, RunAs: b.RunAs, Instances: insts})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) stopInstance(w http.ResponseWriter, r *http.Request, a broker.Approver) {
	id := r.PathValue("id")
	if s.Instances != nil {
		for _, in := range s.Instances.Instances() {
			if in.ID == id && s.Broker.MayManageInstance(r.Context(), a, in.Server, in.UID) {
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
	writeJSON(w, http.StatusOK, map[string]any{"mode": mode, "bundles": bundles})
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
