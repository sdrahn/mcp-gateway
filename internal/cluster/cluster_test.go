package cluster

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/control"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
	"github.com/sdrahn/mcp-gateway/internal/kube/kubetest"
	"github.com/sdrahn/mcp-gateway/internal/replicas"
	"github.com/sdrahn/mcp-gateway/internal/router"
)

// local is a replica's router.
type local struct {
	mu        sync.Mutex
	instances []router.InstanceInfo
	tasks     []router.TaskInfo
	sessions  []router.SessionInfo
	done      []string // the actions carried out
}

func (l *local) Instances() []router.InstanceInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]router.InstanceInfo(nil), l.instances...)
}

func (l *local) StopInstance(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, in := range l.instances {
		if in.ID == id {
			l.done = append(l.done, "stop "+id)
			return true
		}
	}
	return false
}

func (l *local) Tasks() []router.TaskInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]router.TaskInfo(nil), l.tasks...)
}

func (l *local) CancelTask(id, by string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, t := range l.tasks {
		if t.ID == id {
			if t.Status == "completed" {
				return router.ErrTaskEnded
			}
			l.done = append(l.done, "cancel "+id+" by "+by)
			return nil
		}
	}
	return router.ErrNoTask
}

func (l *local) Sessions() []router.SessionInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]router.SessionInfo, len(l.sessions))
	for i, s := range l.sessions {
		s.Instances = append([]string(nil), s.Instances...)
		out[i] = s
	}
	return out
}

func (l *local) EndSession(id, by string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.sessions {
		if s.ID == id {
			l.done = append(l.done, "end "+id+" by "+by)
			return nil
		}
	}
	return errors.New("no such session")
}

func (l *local) actions() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.done...)
}

// checks is a replica's doctor.
type checks struct{ summary string }

func (c checks) Report(context.Context) control.DoctorReport {
	return control.DoctorReport{Trigger: "start", Results: []doctor.Result{{Check: "policy", Status: doctor.OK, Summary: c.summary}}}
}

func (c checks) Run(ctx context.Context) control.DoctorReport {
	r := c.Report(ctx)
	r.Trigger = "request"
	return r
}

var t0 = time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

// pair is replica gw-a's view, with gw-b behind its peer listener.
func pair(t *testing.T) (*View, *local, *local, *httptest.Server) {
	t.Helper()
	api := kubetest.NewSecrets(t)
	la := &local{
		instances: []router.InstanceInfo{{ID: "fs-ivy-1", Server: "fs", Started: t0.Add(2 * time.Minute)}},
		tasks:     []router.TaskInfo{{ID: "t-a", Server: "fs", Created: t0.Add(time.Minute)}},
		sessions:  []router.SessionInfo{{ID: "s-a", Started: t0.Add(3 * time.Minute), Instances: []string{"fs-ivy-1"}}},
	}
	lb := &local{
		// The same id as gw-a's: a shared instance runs on each.
		instances: []router.InstanceInfo{{ID: "fs-ivy-1", Server: "fs", Started: t0.Add(time.Minute)}},
		tasks: []router.TaskInfo{{ID: "t-b", Server: "fs", Created: t0}, {ID: "t-done", Server: "fs", Status: "completed",
			Created: t0.Add(4 * time.Minute)}},
		sessions: []router.SessionInfo{{ID: "s-b", Started: t0, Instances: []string{"fs-ivy-1"}}},
	}
	vb := &View{Local: lb, Doctor: checks{"gw-b's OPA decides"}}
	srv := httptest.NewTLSServer(vb.Handler())
	t.Cleanup(srv.Close)
	mb := &replicas.Members{Client: api.Client(), Namespace: "gw", Name: "gw-b", Address: strings.TrimPrefix(srv.URL, "https://")}
	if err := mb.Join(context.Background()); err != nil {
		t.Fatal(err)
	}
	vb.Members = mb
	ma := &replicas.Members{Client: api.Client(), Namespace: "gw", Name: "gw-a", Address: "127.0.0.1:1"}
	if err := ma.Join(context.Background()); err != nil {
		t.Fatal(err)
	}
	va := &View{Local: la, Doctor: checks{"gw-a's OPA decides"}, Members: ma, Client: srv.Client(), Timeout: time.Second}
	return va, la, lb, srv
}

// The lists are every replica's rows, oldest first, each naming its
// replica; another replica's ids are qualified, so that they do not
// collide with this one's.
func TestMergedViews(t *testing.T) {
	v, _, _, _ := pair(t)
	ins := v.Instances()
	if len(ins) != 2 || ins[0].ID != "gw-b~fs-ivy-1" || ins[0].Replica != "gw-b" || ins[1].ID != "fs-ivy-1" || ins[1].Replica != "gw-a" {
		t.Fatalf("instances %+v", ins)
	}
	ts := v.Tasks()
	if len(ts) != 3 || ts[0].ID != "gw-b~t-b" || ts[1].ID != "t-a" || ts[1].Replica != "gw-a" || ts[2].ID != "gw-b~t-done" {
		t.Fatalf("tasks %+v", ts)
	}
	ss := v.Sessions()
	if len(ss) != 2 || ss[0].ID != "gw-b~s-b" || ss[0].Instances[0] != "gw-b~fs-ivy-1" || ss[1].ID != "s-a" || ss[1].Instances[0] != "fs-ivy-1" {
		t.Fatalf("sessions %+v", ss)
	}
}

// An action on another replica's row is carried out there, one on this
// replica's here; an unknown row is refused.
func TestActionsForwarded(t *testing.T) {
	v, la, lb, _ := pair(t)
	if !v.StopInstance("gw-b~fs-ivy-1") || !v.StopInstance("fs-ivy-1") || v.StopInstance("gw-b~fs-nobody-1") {
		t.Fatal("stop")
	}
	if err := v.CancelTask("gw-b~t-b", "ivy"); err != nil {
		t.Fatal(err)
	}
	if err := v.CancelTask("gw-b~t-done", "ivy"); !errors.Is(err, router.ErrTaskEnded) {
		t.Errorf("an ended task: %v", err)
	}
	if err := v.CancelTask("gw-b~t-x", "ivy"); err == nil {
		t.Error("an unknown task cancelled")
	}
	if err := v.EndSession("gw-b~s-b", "root"); err != nil {
		t.Fatal(err)
	}
	// A replica that is not live: the id is this replica's.
	if v.StopInstance("gw-gone~fs-ivy-1") {
		t.Error("stopped on a replica that is gone")
	}
	if got := strings.Join(lb.actions(), ", "); got != "stop fs-ivy-1, cancel t-b by ivy, end s-b by root" {
		t.Errorf("at gw-b: %s", got)
	}
	if got := strings.Join(la.actions(), ", "); got != "stop fs-ivy-1" {
		t.Errorf("at gw-a: %s", got)
	}
}

// A replica that does not answer leaves its rows out, and says so in the
// doctor's report.
func TestPeerDown(t *testing.T) {
	v, _, _, srv := pair(t)
	rep := v.Report(context.Background())
	if len(rep.Replicas) != 1 || rep.Replicas[0].Replica != "gw-b" || len(rep.Replicas[0].Results) != 1 ||
		rep.Replicas[0].Results[0].Summary != "gw-b's OPA decides" || rep.Results[0].Summary != "gw-a's OPA decides" {
		t.Fatalf("report %+v", rep)
	}
	if rep := v.Run(context.Background()); rep.Trigger != "request" || rep.Replicas[0].Trigger != "request" {
		t.Errorf("run %+v", rep)
	}
	srv.Close()
	if ins := v.Instances(); len(ins) != 1 || ins[0].Replica != "gw-a" {
		t.Errorf("instances without gw-b %+v", ins)
	}
	if v.StopInstance("gw-b~fs-ivy-1") {
		t.Error("stopped at a replica that does not answer")
	}
	rep = v.Report(context.Background())
	if len(rep.Replicas) != 1 || rep.Replicas[0].Unreachable == "" || rep.Replicas[0].Replica != "gw-b" {
		t.Errorf("report without gw-b %+v", rep)
	}
}
