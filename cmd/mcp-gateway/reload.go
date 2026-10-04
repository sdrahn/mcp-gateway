package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// serverReloader puts a changed configuration in force while the gateway
// runs: the server definitions (servers.d) and the keys of gateway.yaml
// that can change without a restart (config.Reloadable), when the files
// change and on SIGHUP (systemctl reload). A file that does not load,
// for any reason, changes nothing: the gateway keeps serving what it
// had, logs the error, audits it and reports it in GET /v1/status (and
// so in the doctor) until a reload succeeds. Keys that need a restart
// are reported as such.
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

	// loadConfig, if set, reads and validates gateway.yaml
	// (config.Resolve), and applyConfig puts its reloadable keys in
	// force; an error from it (a certificate that does not load) keeps
	// the configuration in force. running is the configuration the
	// gateway started with, for the keys that need a restart.
	loadConfig  func() (*config.Gateway, error)
	applyConfig func(*config.Gateway) error
	running     *config.Gateway
	// configFiles lists the files besides servers.d whose change
	// triggers a reload (gateway.yaml, the TLS certificate and key, the
	// SMTP password).
	configFiles func(*config.Gateway) []string

	mu        sync.Mutex
	lastErr   string
	current   *config.Gateway // the configuration in force
	configErr string
	restart   []string
}

// Err returns why the last reload of the server definitions failed, ""
// if it did not.
func (l *serverReloader) Err() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastErr
}

// ConfigErr returns why the last reload of gateway.yaml failed, "" if it
// did not.
func (l *serverReloader) ConfigErr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.configErr
}

// RestartNeeded returns the keys of gateway.yaml whose change takes
// effect at the next start only.
func (l *serverReloader) RestartNeeded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.restart)
}

// reload puts gateway.yaml and the server definitions in force. It never
// panics: a panic while loading or applying them is an error like any
// other.
func (l *serverReloader) reload(trigger string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return errors.Join(l.reloadConfig(trigger), l.reloadServers(trigger))
}

// reloadConfig puts the reloadable keys of gateway.yaml in force; l.mu is
// held.
func (l *serverReloader) reloadConfig(trigger string) (err error) {
	if l.loadConfig == nil {
		return nil
	}
	var changed []string
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("internal error: %v", p)
			l.log.Error("reloading gateway.yaml panicked", "panic", p, "stack", string(debug.Stack()))
		}
		fields := map[string]string{"trigger": trigger, "file": "gateway.yaml"}
		if err != nil {
			l.configErr = err.Error()
			fields["error"] = l.configErr
			l.log.Error("gateway.yaml not reloaded; the configuration in force stays", "trigger", trigger, "err", err)
			l.audit.Event("mcp-config-reload", false, fields)
			return
		}
		l.configErr = ""
		if len(l.restart) > 0 {
			l.log.Warn("gateway.yaml changes keys that take effect at the next start only: systemctl restart mcp-gateway.service",
				"keys", strings.Join(l.restart, ","))
		}
		if len(changed) == 0 {
			return
		}
		l.log.Info("gateway.yaml reloaded", "trigger", trigger, "changed", strings.Join(changed, ","))
		fields["changed"] = strings.Join(changed, ",")
		fields["restart_needed"] = strings.Join(l.restart, ",")
		l.audit.Event("mcp-config-reload", true, fields)
	}()
	next, err := l.loadConfig()
	if err != nil {
		return err
	}
	if err := l.applyConfig(next); err != nil {
		return err
	}
	for _, w := range next.Warnings {
		l.log.Warn(w, "config", "gateway.yaml")
	}
	if l.current != nil {
		changed = config.Changed(l.current, next)
	}
	l.current = next
	l.restart = config.RestartNeeded(l.running, next)
	return nil
}

// reloadServers puts the server definitions in force; l.mu is held.
func (l *serverReloader) reloadServers(trigger string) (err error) {
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

// watch reloads when the files change (checked every interval, which
// may change with the configuration) and on SIGHUP, until ctx ends.
// start is the fingerprint the configuration in force was loaded with.
// A failed reload is retried when the files change again, not at every
// check.
func (l *serverReloader) watch(ctx context.Context, interval func() time.Duration, start string, hup <-chan os.Signal) {
	last := start
	t := time.NewTimer(interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			last = l.fingerprint()
			_ = l.reload("SIGHUP")
		case <-t.C:
			if fp := l.fingerprint(); fp != last {
				last = fp
				_ = l.reload("file change")
			}
			t.Reset(interval())
		}
	}
}

// Interval returns the policy.watch_interval in force.
func (l *serverReloader) Interval() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.current == nil || l.current.Policy.WatchInterval <= 0 {
		return config.DefaultWatchInterval
	}
	return l.current.Policy.WatchInterval
}

// fingerprint digests the files whose change triggers a reload.
func (l *serverReloader) fingerprint() string {
	l.mu.Lock()
	var files []string
	if l.configFiles != nil {
		files = l.configFiles(l.current)
	}
	l.mu.Unlock()
	return reloadFingerprint(l.dirs, files)
}

// reloadFingerprint digests the definition files in dirs and the given
// files (missing ones included as such).
func reloadFingerprint(dirs, files []string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, serversFingerprint(dirs))
	for _, f := range files {
		_, _ = fmt.Fprintf(h, "\n%s\n", f)
		b, err := os.ReadFile(f)
		if err != nil {
			_, _ = fmt.Fprintf(h, "%v", err)
			continue
		}
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
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
