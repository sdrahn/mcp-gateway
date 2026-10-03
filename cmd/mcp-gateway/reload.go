package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/router"
)

// serverReloader puts changed server definitions (servers.d) in force
// while the gateway runs: when the files change and on SIGHUP (systemctl
// reload). A definition that does not load, for any reason, changes
// nothing: the gateway keeps serving the definitions it had, logs the
// error, audits it and reports it in GET /v1/status (and so in the
// doctor) until a reload succeeds.
type serverReloader struct {
	log   *slog.Logger
	audit interface {
		Event(op string, ok bool, fields map[string]string)
	}
	dirs []string
	// load reads and validates the definitions (config.LoadBackends).
	load func(dirs ...string) (map[string]*config.Backend, error)
	// set puts them in force (router.Router.SetBackends).
	set func(map[string]*config.Backend) router.BackendChanges
	// loaded, if set, sees definitions put in force, to warn about them.
	loaded func(map[string]*config.Backend)

	mu      sync.Mutex
	lastErr string
}

// Err returns why the last reload failed, "" if it did not.
func (l *serverReloader) Err() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastErr
}

// reload loads the definitions and puts them in force. It never panics:
// a panic while loading or applying them is an error like any other.
func (l *serverReloader) reload(trigger string) (err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var ch router.BackendChanges
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("internal error: %v", p)
			l.log.Error("reloading server definitions panicked", "panic", p, "stack", string(debug.Stack()))
		}
		fields := map[string]string{"trigger": trigger}
		if err != nil {
			l.lastErr = err.Error()
			fields["error"] = l.lastErr
			l.log.Error("server definitions not reloaded; serving the previous ones", "trigger", trigger, "err", err)
			l.audit.Event("mcp-config-reload", false, fields)
			return
		}
		l.lastErr = ""
		if ch.Empty() {
			l.log.Info("server definitions reloaded; nothing changed", "trigger", trigger)
			return
		}
		fields["added"] = strings.Join(ch.Added, ",")
		fields["changed"] = strings.Join(ch.Changed, ",")
		fields["removed"] = strings.Join(ch.Removed, ",")
		l.audit.Event("mcp-config-reload", true, fields)
	}()
	next, err := l.load(l.dirs...)
	if err != nil {
		return err
	}
	if len(next) == 0 {
		// Mostly a directory that was not readable for a moment.
		return fmt.Errorf("no server definitions in %s", strings.Join(l.dirs, ", "))
	}
	for _, name := range slices.Sorted(maps.Keys(next)) {
		for _, w := range next[name].Warnings {
			l.log.Warn(w, "server", name)
		}
	}
	ch = l.set(next)
	if !ch.Empty() && l.loaded != nil {
		l.loaded(next)
	}
	return nil
}

// watch reloads when the files change (checked every interval) and on
// SIGHUP, until ctx ends. start is the fingerprint the definitions in
// force were loaded with. A failed reload is retried when the files
// change again, not at every check.
func (l *serverReloader) watch(ctx context.Context, interval time.Duration, start string, hup <-chan os.Signal) {
	last := start
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			last = serversFingerprint(l.dirs)
			_ = l.reload("SIGHUP")
		case <-t.C:
			if fp := serversFingerprint(l.dirs); fp != last {
				last = fp
				_ = l.reload("file change")
			}
		}
	}
}

// notifyHUP routes SIGHUP to a channel; without it SIGHUP ends the
// gateway.
func notifyHUP() (<-chan os.Signal, func()) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	return c, func() { signal.Stop(c) }
}

// serversFingerprint digests the names and contents of the definition
// files in dirs; it changes when one is added, removed or edited. Errors
// are part of the digest, so that a file becoming readable again counts
// as a change.
func serversFingerprint(dirs []string) string {
	h := sha256.New()
	for _, dir := range dirs {
		paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			_, _ = fmt.Fprintf(h, "%s: %v\n", dir, err)
			continue
		}
		for _, p := range paths { // sorted by Glob
			_, _ = fmt.Fprintf(h, "%s\n", p)
			f, err := os.Open(p)
			if err != nil {
				_, _ = fmt.Fprintf(h, "%v\n", err)
				continue
			}
			if _, err := io.Copy(h, f); err != nil {
				_, _ = fmt.Fprintf(h, "%v\n", err)
			}
			_ = f.Close()
			h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
