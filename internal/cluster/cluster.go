// Package cluster merges what the control API lists from several replicas
// (docs/architecture.md, section 5.12.5): the instances, tasks and
// clients of every live replica, each row naming its replica, and the
// doctor's reports of all. An action on another replica's row (stopping an
// instance, cancelling a task, ending a session) is carried out there.
//
// The rows of the other replicas come over the peer listener (mTLS, the
// replicas' certificate), unfiltered; the control API decides who sees and
// does what on the replica that serves the caller, as for its own rows
// (the approver rules), and the replica that holds the row carries the
// action out. A row of another replica has the id "<replica>~<id>", so
// that ids of several replicas do not collide and an action finds its
// replica; this replica's rows keep their ids.
package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/control"
	"github.com/sdrahn/mcp-gateway/internal/replicas"
	"github.com/sdrahn/mcp-gateway/internal/router"
)

// Prefix is the path below which the peer listener serves a replica's
// own rows to the others (Handler).
const Prefix = "/peer/v1/"

// DefaultTimeout bounds a peer's answer.
const DefaultTimeout = 3 * time.Second

// Local is what this replica runs (router.Router).
type Local interface {
	control.Instances
	control.Tasks
	control.Sessions
}

// View is the gateway's instances, tasks and clients across the live
// replicas, for the control API (control.Instances, control.Tasks,
// control.Sessions), and the doctor's reports of all (control.Doctor,
// with Doctor set).
type View struct {
	Local   Local
	Doctor  control.Doctor // optional
	Members *replicas.Members
	// Client reaches the peers' listener (mTLS).
	Client  *http.Client
	Timeout time.Duration // DefaultTimeout if 0
	Log     *slog.Logger
}

func (v *View) log() *slog.Logger {
	if v.Log != nil {
		return v.Log
	}
	return slog.Default()
}

// peers are the other live replicas, by name.
func (v *View) peers() []replicas.Member {
	live := v.Members.Live()
	delete(live, v.Members.Name)
	names := slices.Sorted(maps.Keys(live))
	out := make([]replicas.Member, 0, len(names))
	for _, n := range names {
		out = append(out, live[n])
	}
	return out
}

// qualify is the id of a row of replica in the merged views.
func qualify(replica, id string) string { return replica + replicas.StateSeparator + id }

// split returns the replica and its id of a merged view's id: "" for this
// replica's own (or one of a replica that is not live).
func (v *View) split(id string) (string, string) {
	replica, rest, ok := strings.Cut(id, replicas.StateSeparator)
	if !ok || replica == v.Members.Name || !v.Members.IsLive(replica) {
		return "", id
	}
	return replica, rest
}

// call asks m for path; out, if set, receives the JSON answer. It returns
// the status.
func (v *View) call(ctx context.Context, m replicas.Member, method, path string, body any, out any) (int, error) {
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(data)
	}
	u := url.URL{Scheme: "https", Host: m.Address, Path: path}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set(replicas.ForwardedByHeader, v.Members.Name)
	resp, err := v.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s: %w", path, err)
		}
	}
	return resp.StatusCode, nil
}

// gather asks every peer for path at once and returns their answers by
// replica; a peer that does not answer is logged and left out.
func gather[T any](v *View, path string) map[string]T {
	ps := v.peers()
	var mu sync.Mutex
	out := map[string]T{}
	var wg sync.WaitGroup
	for _, m := range ps {
		wg.Go(func() {
			var t T
			code, err := v.call(context.Background(), m, http.MethodGet, path, nil, &t)
			if err == nil && code != http.StatusOK {
				err = fmt.Errorf("status %d", code)
			}
			if err != nil {
				v.log().Warn("cluster: a replica's rows are missing", "replica", m.Name, "path", path, "err", err)
				return
			}
			mu.Lock()
			out[m.Name] = t
			mu.Unlock()
		})
	}
	wg.Wait()
	return out
}

// Instances implements control.Instances: oldest first.
func (v *View) Instances() []router.InstanceInfo {
	out := v.Local.Instances()
	for i := range out {
		out[i].Replica = v.Members.Name
	}
	for replica, rows := range gather[[]router.InstanceInfo](v, Prefix+"instances") {
		for _, in := range rows {
			in.Replica, in.ID = replica, qualify(replica, in.ID)
			out = append(out, in)
		}
	}
	slices.SortStableFunc(out, func(a, b router.InstanceInfo) int { return a.Started.Compare(b.Started) })
	return out
}

// StopInstance implements control.Instances.
func (v *View) StopInstance(id string) bool {
	replica, id := v.split(id)
	if replica == "" {
		return v.Local.StopInstance(id)
	}
	return v.act(replica, "instances/"+url.PathEscape(id)+"/stop", "") == nil
}

// Tasks implements control.Tasks: oldest first.
func (v *View) Tasks() []router.TaskInfo {
	out := v.Local.Tasks()
	for i := range out {
		out[i].Replica = v.Members.Name
	}
	for replica, rows := range gather[[]router.TaskInfo](v, Prefix+"tasks") {
		for _, t := range rows {
			t.Replica, t.ID = replica, qualify(replica, t.ID)
			out = append(out, t)
		}
	}
	slices.SortStableFunc(out, func(a, b router.TaskInfo) int { return a.Created.Compare(b.Created) })
	return out
}

// CancelTask implements control.Tasks.
func (v *View) CancelTask(id, by string) error {
	replica, id := v.split(id)
	if replica == "" {
		return v.Local.CancelTask(id, by)
	}
	return v.act(replica, "tasks/"+url.PathEscape(id)+"/cancel", by)
}

// Sessions implements control.Sessions: oldest first.
func (v *View) Sessions() []router.SessionInfo {
	out := v.Local.Sessions()
	for i := range out {
		out[i].Replica = v.Members.Name
	}
	for replica, rows := range gather[[]router.SessionInfo](v, Prefix+"sessions") {
		for _, c := range rows {
			c.Replica, c.ID = replica, qualify(replica, c.ID)
			for i, in := range c.Instances {
				c.Instances[i] = qualify(replica, in)
			}
			out = append(out, c)
		}
	}
	slices.SortStableFunc(out, func(a, b router.SessionInfo) int { return a.Started.Compare(b.Started) })
	return out
}

// EndSession implements control.Sessions.
func (v *View) EndSession(id, by string) error {
	replica, id := v.split(id)
	if replica == "" {
		return v.Local.EndSession(id, by)
	}
	return v.act(replica, "sessions/"+url.PathEscape(id)+"/end", by)
}

// History passes the clients' history through: the replicas keep it in
// the shared store, each list showing all (router.Router).
func (v *View) History(since, until time.Time) []router.ClientRecord {
	if h, ok := v.Local.(control.History); ok {
		return h.History(since, until)
	}
	return nil
}

// action is the body of an action on a peer.
type action struct {
	By string `json:"by,omitempty"`
}

// act has replica carry out the action at path: nil if it did,
// router.ErrNoTask (or the like) if it holds no such row.
func (v *View) act(replica, path, by string) error {
	m, ok := v.Members.Live()[replica]
	if !ok {
		return router.ErrNoTask
	}
	code, err := v.call(context.Background(), m, http.MethodPost, Prefix+path, action{By: by}, nil)
	switch {
	case err != nil:
		v.log().Warn("cluster: an action on another replica failed", "replica", replica, "path", path, "err", err)
		return err
	case code == http.StatusNoContent:
		return nil
	case code == http.StatusConflict:
		return router.ErrTaskEnded
	default:
		return router.ErrNoTask
	}
}

// Report implements control.Doctor: this replica's report, with the
// others' last ones.
func (v *View) Report(ctx context.Context) control.DoctorReport {
	rep := v.Doctor.Report(ctx)
	rep.Replicas = v.doctors(http.MethodGet)
	return rep
}

// Run implements control.Doctor: the checks of every replica, run now.
func (v *View) Run(ctx context.Context) control.DoctorReport {
	rep := v.Doctor.Run(ctx)
	rep.Replicas = v.doctors(http.MethodPost)
	return rep
}

// doctors returns the other replicas' reports, by replica; a replica that
// does not answer has one with that said.
func (v *View) doctors(method string) []control.DoctorReport {
	ps := v.peers()
	out := make([]control.DoctorReport, len(ps))
	var wg sync.WaitGroup
	for i, m := range ps {
		wg.Go(func() {
			var rep control.DoctorReport
			code, err := v.call(context.Background(), m, method, Prefix+"doctor", nil, &rep)
			if err == nil && code != http.StatusOK {
				err = fmt.Errorf("status %d", code)
			}
			if err != nil {
				rep = control.DoctorReport{Replica: m.Name, Unreachable: err.Error()}
			}
			rep.Replica = m.Name
			out[i] = rep
		})
	}
	wg.Wait()
	return out
}

// Handler serves this replica's own rows and actions to the other
// replicas, below Prefix (the peer listener, which admits replicas only).
func (v *View) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Prefix+"instances", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, v.Local.Instances())
	})
	mux.HandleFunc("GET "+Prefix+"tasks", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, v.Local.Tasks()) })
	mux.HandleFunc("GET "+Prefix+"sessions", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, v.Local.Sessions())
	})
	mux.HandleFunc("POST "+Prefix+"instances/{id}/stop", func(w http.ResponseWriter, r *http.Request) {
		if !v.Local.StopInstance(r.PathValue("id")) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		v.log().Info("instance stopped for another replica", "instance", r.PathValue("id"), "replica", r.Header.Get(replicas.ForwardedByHeader))
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST "+Prefix+"tasks/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		respond(w, v.Local.CancelTask(r.PathValue("id"), by(r)))
	})
	mux.HandleFunc("POST "+Prefix+"sessions/{id}/end", func(w http.ResponseWriter, r *http.Request) {
		respond(w, v.Local.EndSession(r.PathValue("id"), by(r)))
	})
	if v.Doctor != nil {
		mux.HandleFunc("GET "+Prefix+"doctor", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, v.Doctor.Report(r.Context())) })
		mux.HandleFunc("POST "+Prefix+"doctor", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, v.Doctor.Run(r.Context())) })
	}
	return mux
}

func by(r *http.Request) string {
	var a action
	_ = json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&a)
	return a.By
}

func respond(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, router.ErrTaskEnded):
		w.WriteHeader(http.StatusConflict)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
