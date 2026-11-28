package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/discovery"
	"github.com/sdrahn/mcp-gateway/internal/kube"
)

// discoveryLoadTimeout bounds the first list of the Services at the
// start: a namespace not listed by then is listed in the background.
const discoveryLoadTimeout = 10 * time.Second

// discoverySource adds the servers discovered from the cluster's Services
// (server_discovery; docs/architecture.md, section 5.12.8) to the
// definitions of the server files, at the start and at every reload.
type discoverySource struct {
	log     *slog.Logger
	gw      *config.Gateway
	watcher *discovery.Watcher
	// changes has a value when the Services changed: the reloader loads
	// the definitions again.
	changes chan struct{}

	mu       sync.Mutex
	problems []discovery.Problem
	logged   string // the problems last logged
}

// newDiscovery makes the source, nil without server_discovery, and lists
// the Services once.
func newDiscovery(log *slog.Logger, gw *config.Gateway) (*discoverySource, error) {
	if !gw.ServerDiscovery.Enabled() {
		return nil, nil
	}
	d := gw.ServerDiscovery.WithDefaults()
	client, err := kube.NewClient(d.APIServer, d.TokenFile, d.CAFile)
	if err != nil {
		return nil, fmt.Errorf("server_discovery: %w", err)
	}
	s := &discoverySource{log: log, gw: gw, changes: make(chan struct{}, 1)}
	s.watcher = &discovery.Watcher{Client: client, Config: d, Log: log, OnChange: s.changed}
	ctx, cancel := context.WithTimeout(context.Background(), discoveryLoadTimeout)
	defer cancel()
	if err := s.watcher.Load(ctx); err != nil {
		log.Warn("server_discovery: not every namespace's Services were listed; their servers come once they are", "err", err)
	}
	var names []string
	for _, n := range d.Namespaces {
		names = append(names, n.Namespace)
	}
	log.Info("server_discovery: following the Services", "namespaces", strings.Join(names, ","), "selector", d.Selector)
	return s, nil
}

func (s *discoverySource) changed() {
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

// run follows the Services until ctx ends.
func (s *discoverySource) run(ctx context.Context) {
	if s != nil {
		s.watcher.Run(ctx)
	}
}

// merge returns files with the discovered servers (a file of the same
// name wins, an empty file masks the name) and logs the Services that
// give no server, when they changed. Without discovery: files.
func (s *discoverySource) merge(files map[string]*config.Backend, dirs []string) (map[string]*config.Backend, error) {
	if s == nil {
		return files, nil
	}
	masked, err := config.MaskedNames(dirs...)
	if err != nil {
		return nil, err
	}
	found, problems := s.watcher.Definitions()
	// What container mode refuses (nothing in a definition made from a
	// Service, as it stands): the Service gives no server, the others
	// stay.
	for name, b := range found {
		if err := config.CheckDeployment(s.gw, map[string]*config.Backend{name: b}); err != nil {
			delete(found, name)
			problems = append(problems, discovery.Problem{Namespace: b.Discovered.Namespace, Service: b.Discovered.Service,
				Server: name, Reason: err.Error()})
		}
	}
	out, overridden := discovery.Merge(files, masked, found)
	problems = append(problems, overridden...)
	s.report(problems)
	return out, nil
}

// report logs the problems when they differ from those last logged.
func (s *discoverySource) report(problems []discovery.Problem) {
	var b strings.Builder
	for _, p := range problems {
		b.WriteString(p.String())
		b.WriteByte('\n')
	}
	s.mu.Lock()
	s.problems = problems
	same := b.String() == s.logged
	s.logged = b.String()
	s.mu.Unlock()
	if same {
		return
	}
	for _, p := range problems {
		if p.Overridden {
			s.log.Info("server_discovery: "+p.Reason, "namespace", p.Namespace, "service", p.Service, "server", p.Server)
			continue
		}
		s.log.Warn("server_discovery: a Service gives no server: "+p.Reason, "namespace", p.Namespace, "service", p.Service, "server", p.Server)
	}
}

// Problems returns the Services that give no server, as of the last
// load, and the namespaces whose Services are not followed now.
func (s *discoverySource) Problems() ([]discovery.Problem, map[string]string) {
	if s == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]discovery.Problem(nil), s.problems...), s.watcher.Errors()
}

// Changes has a value when the Services changed; nil without discovery.
func (s *discoverySource) Changes() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.changes
}
