// Package kubetest is a fake of the Kubernetes API for tests of what the
// gateway keeps there (internal/store, internal/replicas): namespaced
// objects of any resource (Secrets, Leases, pods) created, read, updated
// and deleted with resource versions, listed and deleted by label, and
// watched, with a history that can be compacted (a watch from an older
// version is 410 Gone) and streams that can be broken.
package kubetest

import (
	"encoding/base64"
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

// Secrets is the fake API server (named after what it first served).
type Secrets struct {
	URL string

	mu      sync.Mutex
	version int
	objects map[string]object // by resource/namespace/name
	events  []event
	// oldest is the first version a watch may start after.
	oldest int
	// changed is closed and replaced at each change, waking watches.
	changed chan struct{}
	// broken is closed and replaced by Break, ending watches.
	broken   chan struct{}
	requests map[string]int
}

// object is an object as JSON fields, metadata among them.
type object map[string]any

func (o object) meta() map[string]any {
	m, _ := o["metadata"].(map[string]any)
	if m == nil {
		m = map[string]any{}
		o["metadata"] = m
	}
	return m
}

func (o object) name() string { s, _ := o.meta()["name"].(string); return s }

func (o object) labels() map[string]string {
	out := map[string]string{}
	if l, ok := o.meta()["labels"].(map[string]any); ok {
		for k, v := range l {
			out[k], _ = v.(string)
		}
	}
	return out
}

func (o object) version() string { s, _ := o.meta()["resourceVersion"].(string); return s }

type event struct {
	version  int
	typ      string
	resource string
	ns       string
	obj      object
}

// NewSecrets starts a fake API server, stopped when t ends.
func NewSecrets(t testing.TB) *Secrets {
	f := &Secrets{objects: map[string]object{}, changed: make(chan struct{}), broken: make(chan struct{}),
		requests: map[string]int{}}
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

// Requests returns the number of requests of method so far.
func (f *Secrets) Requests(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[method]
}

// Len returns the number of Secrets in ns.
func (f *Secrets) Len(ns string) int { return f.LenOf("secrets", ns) }

// LenOf returns the number of objects of resource in ns.
func (f *Secrets) LenOf(resource, ns string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k := range f.objects {
		if strings.HasPrefix(k, resource+"/"+ns+"/") {
			n++
		}
	}
	return n
}

// Names returns the names of the objects of resource in ns with the
// labels of selector.
func (f *Secrets) Names(resource, ns, selector string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k, o := range f.objects {
		if strings.HasPrefix(k, resource+"/"+ns+"/") && matches(selector, o.labels()) {
			out = append(out, o.name())
		}
	}
	return out
}

// Put writes the Secret s as another writer would (another replica,
// kubectl).
func (f *Secrets) Put(ns string, s kube.Secret) { f.PutObject("secrets", ns, s) }

// PutObject writes v (an API object) as another writer would.
func (f *Secrets) PutObject(resource, ns string, v any) {
	o := toObject(v)
	f.mu.Lock()
	defer f.mu.Unlock()
	typ := "ADDED"
	if _, ok := f.objects[key(resource, ns, o.name())]; ok {
		typ = "MODIFIED"
	}
	f.store(resource, ns, o, typ)
}

// Remove deletes the Secret ns/name as another writer would.
func (f *Secrets) Remove(ns, name string) { f.RemoveObject("secrets", ns, name) }

// RemoveObject deletes an object as another writer would.
func (f *Secrets) RemoveObject(resource, ns, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o, ok := f.objects[key(resource, ns, name)]; ok {
		f.drop(resource, ns, o)
	}
}

func toObject(v any) object {
	b, _ := json.Marshal(v)
	var o object
	_ = json.Unmarshal(b, &o)
	if o == nil {
		o = object{}
	}
	return o
}

func key(resource, ns, name string) string { return resource + "/" + ns + "/" + name }

// store saves o as a new version. Caller holds f.mu.
func (f *Secrets) store(resource, ns string, o object, typ string) object {
	f.version++
	m := o.meta()
	m["namespace"] = ns
	m["resourceVersion"] = strconv.Itoa(f.version)
	if resource == "secrets" {
		// stringData is written only: the API server keeps it as data.
		data, _ := o["data"].(map[string]any)
		if data == nil {
			data = map[string]any{}
		}
		if sd, ok := o["stringData"].(map[string]any); ok {
			for k, v := range sd {
				s, _ := v.(string)
				data[k] = base64.StdEncoding.EncodeToString([]byte(s))
			}
		}
		delete(o, "stringData")
		o["data"] = data
	}
	f.objects[key(resource, ns, o.name())] = o
	f.events = append(f.events, event{f.version, typ, resource, ns, o})
	f.wake()
	return o
}

// drop deletes o. Caller holds f.mu.
func (f *Secrets) drop(resource, ns string, o object) {
	f.version++
	delete(f.objects, key(resource, ns, o.name()))
	gone := toObject(o)
	gone.meta()["resourceVersion"] = strconv.Itoa(f.version)
	f.events = append(f.events, event{f.version, "DELETED", resource, ns, gone})
	f.wake()
}

func (f *Secrets) wake() {
	close(f.changed)
	f.changed = make(chan struct{})
}

// parse splits a path into the resource (its plural), namespace and name:
// /api/v1/namespaces/{ns}/{resource}[/{name}] or
// /apis/{group}/{version}/namespaces/{ns}/{resource}[/{name}].
func parse(path string) (resource, ns, name string, ok bool) {
	rest, found := strings.CutPrefix(path, "/api/v1/namespaces/")
	if !found {
		after, found := strings.CutPrefix(path, "/apis/")
		if !found {
			return "", "", "", false
		}
		parts := strings.SplitN(after, "/", 3)
		if len(parts) < 3 {
			return "", "", "", false
		}
		if rest, found = strings.CutPrefix(parts[2], "namespaces/"); !found {
			return "", "", "", false
		}
	}
	parts := strings.Split(rest, "/")
	switch len(parts) {
	case 2:
		return parts[1], parts[0], "", true
	case 3:
		return parts[1], parts[0], parts[2], true
	}
	return "", "", "", false
}

func (f *Secrets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests[r.Method]++
	f.mu.Unlock()
	resource, ns, name, ok := parse(r.URL.Path)
	if !ok {
		status(w, http.StatusNotFound, "NotFound", "no such path")
		return
	}
	switch {
	case r.Method == http.MethodPost && name == "":
		f.create(w, r, resource, ns)
	case r.Method == http.MethodGet && name != "":
		f.get(w, resource, ns, name)
	case r.Method == http.MethodGet && r.URL.Query().Get("watch") != "":
		f.watch(w, r, resource, ns)
	case r.Method == http.MethodGet:
		f.list(w, r, resource, ns)
	case r.Method == http.MethodPut && name != "":
		f.update(w, r, resource, ns, name)
	case r.Method == http.MethodDelete && name != "":
		f.delete(w, r, resource, ns, name)
	case r.Method == http.MethodDelete:
		f.deleteCollection(w, r, resource, ns)
	default:
		status(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method)
	}
}

func decode(r *http.Request) (object, bool) {
	var o object
	if err := json.NewDecoder(r.Body).Decode(&o); err != nil || o == nil {
		return nil, false
	}
	return o, o.name() != ""
}

func (f *Secrets) create(w http.ResponseWriter, r *http.Request, resource, ns string) {
	o, ok := decode(r)
	if !ok {
		status(w, http.StatusBadRequest, "BadRequest", "no object")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[key(resource, ns, o.name())]; ok {
		status(w, http.StatusConflict, "AlreadyExists", resource+" "+o.name()+" already exists")
		return
	}
	delete(o.meta(), "resourceVersion")
	reply(w, http.StatusCreated, f.store(resource, ns, o, "ADDED"))
}

func (f *Secrets) get(w http.ResponseWriter, resource, ns, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objects[key(resource, ns, name)]
	if !ok {
		status(w, http.StatusNotFound, "NotFound", resource+" "+name+" not found")
		return
	}
	reply(w, http.StatusOK, o)
}

func (f *Secrets) update(w http.ResponseWriter, r *http.Request, resource, ns, name string) {
	o, ok := decode(r)
	if !ok || o.name() != name {
		status(w, http.StatusBadRequest, "BadRequest", "bad object")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.objects[key(resource, ns, name)]
	if !ok {
		status(w, http.StatusNotFound, "NotFound", resource+" "+name+" not found")
		return
	}
	if v := o.version(); v != "" && v != cur.version() {
		status(w, http.StatusConflict, "Conflict", "the object has been modified")
		return
	}
	reply(w, http.StatusOK, f.store(resource, ns, o, "MODIFIED"))
}

func (f *Secrets) delete(w http.ResponseWriter, r *http.Request, resource, ns, name string) {
	var opts struct {
		Preconditions struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"preconditions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&opts)
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.objects[key(resource, ns, name)]
	if !ok {
		status(w, http.StatusNotFound, "NotFound", resource+" "+name+" not found")
		return
	}
	if v := opts.Preconditions.ResourceVersion; v != "" && v != cur.version() {
		status(w, http.StatusConflict, "Conflict", "precondition failed")
		return
	}
	f.drop(resource, ns, cur)
	status(w, http.StatusOK, "", "deleted")
}

func (f *Secrets) deleteCollection(w http.ResponseWriter, r *http.Request, resource, ns string) {
	sel := r.URL.Query().Get("labelSelector")
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, o := range f.objects {
		if strings.HasPrefix(k, resource+"/"+ns+"/") && matches(sel, o.labels()) {
			f.drop(resource, ns, o)
		}
	}
	status(w, http.StatusOK, "", "deleted")
}

func (f *Secrets) list(w http.ResponseWriter, r *http.Request, resource, ns string) {
	sel := r.URL.Query().Get("labelSelector")
	f.mu.Lock()
	defer f.mu.Unlock()
	items := []object{}
	for k, o := range f.objects {
		if strings.HasPrefix(k, resource+"/"+ns+"/") && matches(sel, o.labels()) {
			items = append(items, o)
		}
	}
	reply(w, http.StatusOK, map[string]any{"metadata": map[string]any{"resourceVersion": strconv.Itoa(f.version)}, "items": items})
}

func (f *Secrets) watch(w http.ResponseWriter, r *http.Request, resource, ns string) {
	q := r.URL.Query()
	sel := q.Get("labelSelector")
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
			if e.version > from && e.resource == resource && e.ns == ns && matches(sel, e.obj.labels()) {
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

// matches reports whether labels match a selector of equalities,
// inequalities and absences ("k=v,k2!=v2,!k3").
func matches(selector string, labels map[string]string) bool {
	if selector == "" {
		return true
	}
	for _, term := range strings.Split(selector, ",") {
		switch {
		case strings.HasPrefix(term, "!"):
			if _, ok := labels[term[1:]]; ok {
				return false
			}
		case strings.Contains(term, "!="):
			k, v, _ := strings.Cut(term, "!=")
			if labels[k] == v {
				return false
			}
		default:
			k, v, _ := strings.Cut(term, "=")
			if labels[k] != v {
				return false
			}
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
