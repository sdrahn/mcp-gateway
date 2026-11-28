// Package discovery turns the Services of a cluster into definitions of
// servers that speak HTTP (docs/architecture.md, section 5.12.8, D25):
// the Services that carry server_discovery's labels, in the namespaces it
// names and in no other, each becoming a server named with its
// namespace's prefix, at the Service's cluster address. The annotations
// set the name, the port and the path, and nothing else: what carries
// credentials or changes how the gateway trusts a server comes from the
// server files only, and a file of the same name wins (Merge).
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/kube"
)

// watchTimeout is how long a watch lasts before it is made again.
const watchTimeout = 5 * time.Minute

// Problem is a Service that gives no server, or a discovered server that
// a server file overrides or masks.
type Problem struct {
	Namespace, Service string
	// Server is the name the Service would give ("" when it has none).
	Server string
	Reason string
	// Overridden is set when a server file of the same name is in force
	// instead (or an empty file masks the name): by design, not a fault.
	Overridden bool
}

func (p Problem) String() string {
	s := "Service " + p.Namespace + "/" + p.Service
	if p.Server != "" {
		s += " (server " + p.Server + ")"
	}
	return s + ": " + p.Reason
}

// Watcher follows the Services of server_discovery's namespaces.
type Watcher struct {
	Client *kube.Client
	// Config is server_discovery, its defaults filled in.
	Config config.ServerDiscovery
	Log    *slog.Logger
	// OnChange, if set, is called after the Services changed (not with
	// the lock held): the definitions are to be loaded again.
	OnChange func()
	// MinBackoff and MaxBackoff bound the wait before listing again
	// after a failure (1 s and 30 s by default).
	MinBackoff, MaxBackoff time.Duration

	mu       sync.Mutex
	services map[string]map[string]kube.Service // by namespace, by name
	version  map[string]string                  // by namespace: to watch from
	errs     map[string]string                  // by namespace: why it is not followed
}

func (w *Watcher) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.Default()
}

// Load lists the Services of every namespace once. A namespace that does
// not list (no Role there, say) has no servers until Run lists it; the
// error says which.
func (w *Watcher) Load(ctx context.Context) error {
	var errs []error
	for _, n := range w.Config.Namespaces {
		if err := w.list(ctx, n.Namespace); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Run follows each namespace's Services until ctx ends: it watches from
// the last list, and lists again when the watch breaks.
func (w *Watcher) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, n := range w.Config.Namespaces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.follow(ctx, n.Namespace)
		}()
	}
	wg.Wait()
}

func (w *Watcher) follow(ctx context.Context, ns string) {
	minB, maxB := w.MinBackoff, w.MaxBackoff
	if minB <= 0 {
		minB = time.Second
	}
	if maxB < minB {
		maxB = max(30*time.Second, minB)
	}
	backoff := minB
	for ctx.Err() == nil {
		w.mu.Lock()
		version := w.version[ns]
		w.mu.Unlock()
		var err error
		if version == "" {
			if err = w.list(ctx, ns); err == nil {
				w.mu.Lock()
				version = w.version[ns]
				w.mu.Unlock()
			}
		}
		if err == nil {
			err = w.Client.Watch(ctx, kube.ServicesPath(ns), w.Config.Selector, version, watchTimeout,
				func(ev kube.WatchEvent) error { return w.apply(ns, ev) })
			if err == nil {
				backoff = minB
				continue // the API server ended the watch: watch again
			}
		}
		if ctx.Err() != nil {
			return
		}
		w.mu.Lock()
		delete(w.version, ns) // list again
		w.mu.Unlock()
		if kube.IsGone(err) {
			continue
		}
		w.setErr(ns, err)
		w.log().Warn("discovery: following the Services failed; listing again", "namespace", ns, "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxB)
	}
}

// list replaces what is known of ns's Services with a list of them.
func (w *Watcher) list(ctx context.Context, ns string) error {
	var list kube.ServiceList
	if err := w.Client.List(ctx, kube.ServicesPath(ns), w.Config.Selector, &list); err != nil {
		err = fmt.Errorf("discovery: listing the Services of %s: %w", ns, err)
		w.setErr(ns, err)
		return err
	}
	byName := make(map[string]kube.Service, len(list.Items))
	for _, s := range list.Items {
		s.Metadata.Namespace = ns
		byName[s.Metadata.Name] = s
	}
	w.mu.Lock()
	if w.services == nil {
		w.services, w.version, w.errs = map[string]map[string]kube.Service{}, map[string]string{}, map[string]string{}
	}
	changed := !sameServices(w.services[ns], byName)
	w.services[ns] = byName
	w.version[ns] = list.Metadata.ResourceVersion
	delete(w.errs, ns)
	w.mu.Unlock()
	if changed {
		w.changed()
	}
	return nil
}

func (w *Watcher) apply(ns string, ev kube.WatchEvent) error {
	var s kube.Service
	if err := json.Unmarshal(ev.Object, &s); err != nil {
		return fmt.Errorf("discovery: a watch event of %s: %w", ns, err)
	}
	if ev.Type == "BOOKMARK" {
		w.mu.Lock()
		if w.version != nil && s.Metadata.ResourceVersion != "" {
			w.version[ns] = s.Metadata.ResourceVersion
		}
		w.mu.Unlock()
		return nil
	}
	s.Metadata.Namespace = ns
	w.mu.Lock()
	if w.services == nil {
		w.services, w.version, w.errs = map[string]map[string]kube.Service{}, map[string]string{}, map[string]string{}
	}
	if s.Metadata.ResourceVersion != "" {
		w.version[ns] = s.Metadata.ResourceVersion
	}
	m := w.services[ns]
	if m == nil {
		m = map[string]kube.Service{}
		w.services[ns] = m
	}
	changed := false
	switch ev.Type {
	case "ADDED", "MODIFIED":
		old, had := m[s.Metadata.Name]
		changed = !had || !sameService(old, s)
		m[s.Metadata.Name] = s
	case "DELETED":
		_, changed = m[s.Metadata.Name]
		delete(m, s.Metadata.Name)
	}
	w.mu.Unlock()
	if changed {
		w.changed()
	}
	return nil
}

func (w *Watcher) setErr(ns string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.errs == nil {
		w.errs = map[string]string{}
	}
	w.errs[ns] = err.Error()
}

func (w *Watcher) changed() {
	if w.OnChange != nil {
		w.OnChange()
	}
}

// Errors returns, by namespace, why its Services are not followed now.
func (w *Watcher) Errors() map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return maps.Clone(w.errs)
}

// Definitions returns the servers the Services give, by name, and the
// Services that give none: two that would give one name give neither.
func (w *Watcher) Definitions() (map[string]*config.Backend, []Problem) {
	w.mu.Lock()
	type found struct {
		svc    kube.Service
		prefix string
	}
	var all []found
	for _, n := range w.Config.Namespaces {
		for _, s := range w.services[n.Namespace] {
			all = append(all, found{s, n.PrefixOf()})
		}
	}
	w.mu.Unlock()
	slices.SortFunc(all, func(a, b found) int {
		return strings.Compare(a.svc.Metadata.Namespace+"/"+a.svc.Metadata.Name, b.svc.Metadata.Namespace+"/"+b.svc.Metadata.Name)
	})
	defs := map[string]*config.Backend{}
	from := map[string][]kube.Service{}
	var problems []Problem
	for _, f := range all {
		b, err := Definition(f.svc, f.prefix)
		if err != nil {
			problems = append(problems, Problem{Namespace: f.svc.Metadata.Namespace, Service: f.svc.Metadata.Name,
				Server: serverName(f.svc, f.prefix), Reason: err.Error()})
			continue
		}
		from[b.Name] = append(from[b.Name], f.svc)
		defs[b.Name] = b
	}
	for _, name := range slices.Sorted(maps.Keys(from)) {
		svcs := from[name]
		if len(svcs) < 2 {
			continue
		}
		delete(defs, name)
		var others []string
		for _, s := range svcs {
			others = append(others, s.Metadata.Namespace+"/"+s.Metadata.Name)
		}
		for _, s := range svcs {
			problems = append(problems, Problem{Namespace: s.Metadata.Namespace, Service: s.Metadata.Name, Server: name,
				Reason: "the Services " + strings.Join(others, ", ") + " would give the same server: neither is served"})
		}
	}
	return defs, problems
}

// serverName is the name a Service gives: its prefix, and its name
// annotation or its own name.
func serverName(s kube.Service, prefix string) string {
	name := s.Metadata.Name
	if a := strings.TrimSpace(s.Metadata.Annotations[config.DiscoveryNameAnnotation]); a != "" {
		name = a
	}
	return prefix + name
}

// Definition turns a Service into the definition of a server that speaks
// HTTP: named with prefix, at http://<service>.<namespace>.svc:<port><path>,
// and with the defaults of every other key.
func Definition(s kube.Service, prefix string) (*config.Backend, error) {
	if t := s.Spec.Type; t != "" && t != "ClusterIP" {
		return nil, fmt.Errorf("a Service of type %s: only ClusterIP Services are discovered", t)
	}
	port, err := pickPort(s)
	if err != nil {
		return nil, err
	}
	path := config.DefaultDiscoveryPath
	if a, ok := s.Metadata.Annotations[config.DiscoveryPathAnnotation]; ok {
		path = strings.TrimSpace(a)
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?# \t") {
			return nil, fmt.Errorf("annotation %s: %q is not a path (/mcp)", config.DiscoveryPathAnnotation, a)
		}
	}
	b := &config.Backend{
		Version: 1,
		Name:    serverName(s, prefix),
		URL:     fmt.Sprintf("http://%s.%s.svc:%d%s", s.Metadata.Name, s.Metadata.Namespace, port, path),
		Discovered: &config.Discovered{
			Namespace: s.Metadata.Namespace,
			Service:   s.Metadata.Name,
		},
	}
	b.ApplyDefaults()
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// pickPort is the Service's port the server listens on: the annotation's
// (a port's name or number), else the port named mcp, else the only one.
func pickPort(s kube.Service) (int, error) {
	tcp := func(p kube.ServicePort) bool { return p.Protocol == "" || p.Protocol == "TCP" }
	if a := strings.TrimSpace(s.Metadata.Annotations[config.DiscoveryPortAnnotation]); a != "" {
		n, numErr := strconv.Atoi(a)
		for _, p := range s.Spec.Ports {
			if tcp(p) && (p.Name == a || numErr == nil && p.Port == n) {
				return p.Port, nil
			}
		}
		return 0, fmt.Errorf("annotation %s: the Service has no TCP port %s", config.DiscoveryPortAnnotation, a)
	}
	var ports []kube.ServicePort
	for _, p := range s.Spec.Ports {
		if !tcp(p) {
			continue
		}
		if p.Name == "mcp" {
			return p.Port, nil
		}
		ports = append(ports, p)
	}
	switch len(ports) {
	case 1:
		return ports[0].Port, nil
	case 0:
		return 0, errors.New("the Service has no TCP port")
	}
	return 0, fmt.Errorf("the Service has %d ports and none is named mcp: name it with the annotation %s", len(ports), config.DiscoveryPortAnnotation)
}

// Merge joins the definitions of the server files and the discovered
// ones: a file's definition of the same name wins, and a name an empty
// file masks (masked: file names without .yaml) is not served; both are
// reported as overridden.
func Merge(files map[string]*config.Backend, masked map[string]bool, found map[string]*config.Backend) (map[string]*config.Backend, []Problem) {
	out := maps.Clone(files)
	if out == nil {
		out = map[string]*config.Backend{}
	}
	var problems []Problem
	for _, name := range slices.Sorted(maps.Keys(found)) {
		b := found[name]
		switch {
		case files[name] != nil:
			problems = append(problems, Problem{Namespace: b.Discovered.Namespace, Service: b.Discovered.Service, Server: name,
				Reason: "a server file defines " + name + ", and is in force instead", Overridden: true})
		case masked[name]:
			problems = append(problems, Problem{Namespace: b.Discovered.Namespace, Service: b.Discovered.Service, Server: name,
				Reason: "an empty server file " + name + ".yaml masks it", Overridden: true})
		default:
			out[name] = b
		}
	}
	return out, problems
}

// sameService reports whether two versions of a Service give the same
// definition: what Definition reads did not change.
func sameService(a, b kube.Service) bool {
	return a.Metadata.Namespace == b.Metadata.Namespace && a.Metadata.Name == b.Metadata.Name &&
		a.Spec.Type == b.Spec.Type && slices.Equal(a.Spec.Ports, b.Spec.Ports) &&
		a.Metadata.Annotations[config.DiscoveryNameAnnotation] == b.Metadata.Annotations[config.DiscoveryNameAnnotation] &&
		a.Metadata.Annotations[config.DiscoveryPortAnnotation] == b.Metadata.Annotations[config.DiscoveryPortAnnotation] &&
		a.Metadata.Annotations[config.DiscoveryPathAnnotation] == b.Metadata.Annotations[config.DiscoveryPathAnnotation]
}

func sameServices(a, b map[string]kube.Service) bool {
	if len(a) != len(b) {
		return false
	}
	for k, s := range a {
		t, ok := b[k]
		if !ok || !sameService(s, t) {
			return false
		}
	}
	return true
}
