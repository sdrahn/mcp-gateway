// Package kubetest is a fake of the Kubernetes API's Secrets, for tests
// of what the gateway keeps there (internal/store): create, get, update
// and delete with resource versions, lists by label, and watches, whose
// history can be compacted (a watch from an older version is 410 Gone)
// and whose streams can be broken.
package kubetest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/kube"
)

// Secrets is the fake API server.
type Secrets struct {
	URL string

	mu      sync.Mutex
	version int
	objects map[string]kube.Secret // by namespace/name
	events  []event
	// oldest is the first version a watch may start after.
	oldest int
	// changed is closed and replaced at each change, waking watches.
	changed chan struct{}
	// broken is closed and replaced by Break, ending watches.
	broken chan struct{}
	// Requests counts the requests by method.
	Requests map[string]int
}

type event struct {
	version int
	typ     string
	ns      string
	obj     kube.Secret
}

// NewSecrets starts a fake API server, stopped when t ends.
func NewSecrets(t testing.TB) *Secrets {
	f := &Secrets{objects: map[string]kube.Secret{}, changed: make(chan struct{}), broken: make(chan struct{}),
		Requests: map[string]int{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.URL = srv.URL
	return f
}

// Client returns a client of the fake.
func (f *Secrets) Client() *kube.Client {
	c, _ := kube.NewClient(f.URL, "", "")
	return c
}

// Compact forgets the history: a watch from a version before now is 410
// Gone, as after the API server's compaction.
func (f *Secrets) Compact() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.oldest = f.version
	f.events = nil
}

// Break ends the open watches, as a dropped connection does.
func (f *Secrets) Break() {
	f.mu.Lock()
	defer f.mu.Unlock()
	close(f.broken)
	f.broken = make(chan struct{})
}

// Len returns the number of Secrets in ns.
func (f *Secrets) Len(ns string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k := range f.objects {
		if strings.HasPrefix(k, ns+"/") {
			n++
		}
	}
	return n
}

// Put writes s as another writer would (another replica, kubectl).
func (f *Secrets) Put(ns string, s kube.Secret) {
	f.mu.Lock()
	defer f.mu.Unlock()
	typ := "ADDED"
	if _, ok := f.objects[ns+"/"+s.Metadata.Name]; ok {
		typ = "MODIFIED"
	}
	f.store(ns, s, typ)
}

// Remove deletes the Secret ns/name as another writer would.
func (f *Secrets) Remove(ns, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.objects[ns+"/"+name]; ok {
		f.drop(ns, s)
	}
}

// store saves s as a new version. Caller holds f.mu.
func (f *Secrets) store(ns string, s kube.Secret, typ string) kube.Secret {
	f.version++
	s.Metadata.Namespace = ns
	s.Metadata.ResourceVersion = strconv.Itoa(f.version)
	if s.Data == nil {
		s.Data = map[string][]byte{}
	}
	for k, v := range s.StringData {
		s.Data[k] = []byte(v)
	}
	s.StringData = nil
	f.objects[ns+"/"+s.Metadata.Name] = s
	f.events = append(f.events, event{f.version, typ, ns, s})
	f.wake()
	return s
}

// drop deletes s. Caller holds f.mu.
func (f *Secrets) drop(ns string, s kube.Secret) {
	f.version++
	delete(f.objects, ns+"/"+s.Metadata.Name)
	s.Metadata.ResourceVersion = strconv.Itoa(f.version)
	f.events = append(f.events, event{f.version, "DELETED", ns, s})
	f.wake()
}

func (f *Secrets) wake() {
	close(f.changed)
	f.changed = make(chan struct{})
}

func (f *Secrets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.Requests[r.Method]++
	f.mu.Unlock()
	// /api/v1/namespaces/{ns}/secrets[/{name}]
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/"), "/")
	if len(parts) < 2 || parts[1] != "secrets" || len(parts) > 3 {
		status(w, http.StatusNotFound, "NotFound", "no such path")
		return
	}
	ns, name := parts[0], ""
	if len(parts) == 3 {
		name = parts[2]
	}
	switch {
	case r.Method == http.MethodPost && name == "":
		f.create(w, r, ns)
	case r.Method == http.MethodGet && name != "":
		f.get(w, ns, name)
	case r.Method == http.MethodGet && r.URL.Query().Get("watch") != "":
		f.watch(w, r, ns)
	case r.Method == http.MethodGet:
		f.list(w, r, ns)
	case r.Method == http.MethodPut && name != "":
		f.update(w, r, ns, name)
	case r.Method == http.MethodDelete && name != "":
		f.delete(w, r, ns, name)
	default:
		status(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method)
	}
}

func (f *Secrets) create(w http.ResponseWriter, r *http.Request, ns string) {
	var s kube.Secret
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil || s.Metadata.Name == "" {
		status(w, http.StatusBadRequest, "BadRequest", "no secret")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[ns+"/"+s.Metadata.Name]; ok {
		status(w, http.StatusConflict, "AlreadyExists", "secrets "+s.Metadata.Name+" already exists")
		return
	}
	s.Metadata.ResourceVersion = ""
	reply(w, http.StatusCreated, f.store(ns, s, "ADDED"))
}

func (f *Secrets) get(w http.ResponseWriter, ns, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.objects[ns+"/"+name]
	if !ok {
		status(w, http.StatusNotFound, "NotFound", "secrets "+name+" not found")
		return
	}
	reply(w, http.StatusOK, s)
}

func (f *Secrets) update(w http.ResponseWriter, r *http.Request, ns, name string) {
	var s kube.Secret
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil || s.Metadata.Name != name {
		status(w, http.StatusBadRequest, "BadRequest", "bad secret")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.objects[ns+"/"+name]
	if !ok {
		status(w, http.StatusNotFound, "NotFound", "secrets "+name+" not found")
		return
	}
	if v := s.Metadata.ResourceVersion; v != "" && v != cur.Metadata.ResourceVersion {
		status(w, http.StatusConflict, "Conflict", "the object has been modified")
		return
	}
	reply(w, http.StatusOK, f.store(ns, s, "MODIFIED"))
}

func (f *Secrets) delete(w http.ResponseWriter, r *http.Request, ns, name string) {
	var opts struct {
		Preconditions struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"preconditions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&opts)
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.objects[ns+"/"+name]
	if !ok {
		status(w, http.StatusNotFound, "NotFound", "secrets "+name+" not found")
		return
	}
	if v := opts.Preconditions.ResourceVersion; v != "" && v != cur.Metadata.ResourceVersion {
		status(w, http.StatusConflict, "Conflict", "precondition failed")
		return
	}
	f.drop(ns, cur)
	status(w, http.StatusOK, "", "deleted")
}

func (f *Secrets) list(w http.ResponseWriter, r *http.Request, ns string) {
	sel := selector(r.URL.Query().Get("labelSelector"))
	f.mu.Lock()
	defer f.mu.Unlock()
	out := kube.SecretList{Metadata: kube.ListMeta{ResourceVersion: strconv.Itoa(f.version)}, Items: []kube.Secret{}}
	for k, s := range f.objects {
		if strings.HasPrefix(k, ns+"/") && sel.matches(s.Metadata.Labels) {
			out.Items = append(out.Items, s)
		}
	}
	reply(w, http.StatusOK, out)
}

func (f *Secrets) watch(w http.ResponseWriter, r *http.Request, ns string) {
	q := r.URL.Query()
	sel := selector(q.Get("labelSelector"))
	from, _ := strconv.Atoi(q.Get("resourceVersion"))
	timeout := 5 * time.Minute
	if s, err := strconv.Atoi(q.Get("timeoutSeconds")); err == nil && s > 0 {
		timeout = time.Duration(s) * time.Second
	}
	deadline := time.After(timeout)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	flush := func() {
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
	}
	flush()
	for {
		f.mu.Lock()
		if from < f.oldest {
			f.mu.Unlock()
			_ = enc.Encode(map[string]any{"type": "ERROR", "object": map[string]any{
				"kind": "Status", "code": http.StatusGone, "reason": "Expired", "message": "too old resource version"}})
			flush()
			return
		}
		var send []event
		for _, e := range f.events {
			if e.version > from && e.ns == ns && sel.matches(e.obj.Metadata.Labels) {
				send = append(send, e)
			}
		}
		if n := len(f.events); n > 0 && f.events[n-1].version > from {
			from = f.events[n-1].version
		}
		changed, broken := f.changed, f.broken
		f.mu.Unlock()
		for _, e := range send {
			_ = enc.Encode(map[string]any{"type": e.typ, "object": e.obj})
		}
		flush()
		select {
		case <-changed:
		case <-broken:
			return
		case <-deadline:
			return
		case <-r.Context().Done():
			return
		}
	}
}

// selector is a label selector of equalities ("k=v,k2=v2").
type selector string

func (s selector) matches(labels map[string]string) bool {
	if s == "" {
		return true
	}
	for _, term := range strings.Split(string(s), ",") {
		k, v, _ := strings.Cut(term, "=")
		if labels[k] != v {
			return false
		}
	}
	return true
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func status(w http.ResponseWriter, code int, reason, msg string) {
	reply(w, code, map[string]any{"kind": "Status", "code": code, "reason": reason, "message": msg})
}
