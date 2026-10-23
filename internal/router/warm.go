package router

import (
	"context"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// Warm-up (supervisor.warm_up): on a small host a server's first start
// can take longer than an agent waits for its first listing. With
// WarmUp, the gateway starts the shared discovery instances itself and
// fills their lists, in the background: when serving starts, and for the
// servers a reload added or changed. The instances then stop when idle
// as any do (supervisor.idle_timeout).

// warmState holds the context Serve runs with, for the warm-ups of
// later reloads (nil before Serve or without WarmUp), and the warm-ups
// running, which Serve waits for before it stops the instances.
type warmState struct {
	ctx     atomic.Pointer[context.Context]
	mu      sync.Mutex
	stopped bool
	running sync.WaitGroup
}

// start runs f as a warm-up unless the gateway stops.
func (w *warmState) start(f func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	w.running.Add(1)
	go func() {
		defer w.running.Done()
		f()
	}()
}

// stop lets no warm-up start, and waits for those running.
func (w *warmState) stop() {
	w.mu.Lock()
	w.stopped = true
	w.mu.Unlock()
	w.running.Wait()
}

// startWarmUp warms all servers up when serving starts, if WarmUp.
func (r *Router) startWarmUp(ctx context.Context) {
	if !r.WarmUp {
		return
	}
	r.warm.ctx.Store(&ctx)
	r.warm.start(func() { r.warmUp(ctx, nil) })
}

// warmUpChanged warms up the servers a reload added or changed, if
// serving has started with WarmUp.
func (r *Router) warmUpChanged(ch BackendChanges) {
	p := r.warm.ctx.Load()
	names := append(slices.Clone(ch.Added), ch.Changed...)
	if p == nil || len(names) == 0 || (*p).Err() != nil {
		return
	}
	r.warm.start(func() { r.warmUp(*p, names) })
}

// warmUp starts the shared discovery instances of the servers named (all
// when names is nil) and fills their tool, prompt and resource template
// lists, up to listParallel servers at a time. Servers listed per user
// (discovery: instance) have nothing to warm up. Failures are logged;
// the first listing then tries again.
func (r *Router) warmUp(ctx context.Context, names []string) {
	backends := r.backends()
	if names == nil {
		names = slices.Sorted(maps.Keys(backends))
	}
	var todo []*config.Backend
	for _, name := range names {
		if b := backends[name]; b != nil && b.Discovery == config.DiscoveryShared {
			todo = append(todo, b)
		}
	}
	if len(todo) == 0 {
		return
	}
	start := time.Now()
	var failed atomic.Int32
	sem := make(chan struct{}, max(1, listParallel))
	var wg sync.WaitGroup
	for _, b := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return // the gateway stops
			}
			if err := r.warmUpServer(ctx, b); err != nil && ctx.Err() == nil {
				failed.Add(1)
				r.Log.Warn("warm-up failed; the first listing starts the server", "server", b.Name, "err", err)
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	r.Log.Info("warm-up done", "servers", len(todo), "failed", failed.Load(), "took", time.Since(start).Round(time.Millisecond))
}

// warmUpServer starts b's discovery instance and fills its lists.
func (r *Router) warmUpServer(ctx context.Context, b *config.Backend) error {
	ir, err := r.sharedInit(ctx, b)
	if err != nil {
		return err
	}
	for _, method := range []string{"tools/list", "prompts/list", "resources/templates/list"} {
		spec := listSpecs[method]
		if !ir.has(spec.capability) {
			continue
		}
		if _, err := r.sharedList(ctx, b, method, spec); err != nil {
			return err
		}
	}
	return nil
}
