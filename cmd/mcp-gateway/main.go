// Command mcp-gateway is the policy-enforcing MCP gateway daemon.
//
// Current scope (docs/architecture.md, section 11): local clients on the
// unix socket and remote clients over MCP Streamable HTTP with OAuth
// bearer tokens, per-server and aggregated endpoints, OPA decisions,
// form-mode approvals, backends as systemd transient units shared by a
// principal's sessions.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/authn"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	controlapi "github.com/sdrahn/mcp-gateway/internal/control"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/router"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
	"github.com/sdrahn/mcp-gateway/internal/transport"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

// MCS categories handed out to backend instances. c0 is left alone, and
// the range stays below the one libvirt and container tools usually use
// for their own random pairs (docs/architecture.md, section 12).
const mcsLo, mcsHi = 1, 255

func main() {
	configPath := flag.String("config", "", "path to the gateway configuration (default: "+
		config.DefaultConfigPath+", else "+config.DefaultVendorConfigPath+", else built-in defaults)")
	checkOnly := flag.Bool("check", false, "validate the configuration and backend registry, then exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	debug := flag.Bool("debug", false, "log debug messages")
	flag.Parse()

	if *showVersion {
		fmt.Println("mcp-gateway", version.Version)
		return
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := run(log, *configPath, *checkOnly); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, configPath string, checkOnly bool) error {
	gw, used, err := config.Resolve(configPath)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	if used == "" {
		used = "built-in defaults"
	}
	backends, err := config.LoadBackends(gw.VendorServersDir, gw.ServersDir)
	if err != nil {
		return fmt.Errorf("loading backend registry: %w", err)
	}
	log.Info("configuration valid", "config", used, "socket", gw.Socket, "backends", len(backends))
	if checkOnly {
		return nil
	}

	launcher, err := newLauncher(log, gw.Supervisor)
	if err != nil {
		return err
	}

	l, err := transport.ListenUnix(gw.Socket, 0o660, gw.SocketGroup)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", gw.Socket, err)
	}
	log.Info("listening", "socket", gw.Socket, "version", version.Version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(gw.StateDir, 0o700); err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	auditLog, closeAudit, err := newAudit(log, gw)
	if err != nil {
		return err
	}
	defer closeAudit()

	control := gw.Approvals.ControlSocket != "-"
	opa := pep.NewOPA(gw.Policy.OPASocket, gw.Policy.Timeout)
	b, err := broker.New(broker.Options{
		Timeout:     gw.ApprovalTimeout,
		GrantsFile:  filepath.Join(gw.StateDir, "grants.json"),
		URLTemplate: gw.Approvals.URLTemplate,
		OOB:         control,
		Policy:      opa,
		Audit:       auditLog,
		Log:         log,
	})
	if err != nil {
		return err
	}
	if !control && gw.Approvals.URLTemplate != "" {
		log.Warn("approvals.url_template is set but the control socket is disabled; url approvals cannot be decided")
	}
	if control {
		cl, err := transport.ListenUnix(gw.Approvals.ControlSocket, 0o660, gw.SocketGroup)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", gw.Approvals.ControlSocket, err)
		}
		log.Info("listening", "control", gw.Approvals.ControlSocket)
		cs := &controlapi.Server{Broker: b, Log: log}
		go func() {
			if err := cs.Serve(ctx, cl); err != nil {
				log.Error("control API failed", "err", err)
			}
		}()
	}

	r := &router.Router{
		Backends: backends,
		Launcher: launcher,
		PDP:      opa,
		Broker:   b,
		Audit:    auditLog,
		Log:      log,

		IdleTimeout: gw.Supervisor.IdleTimeout,
	}

	// Clients learn about policy changes through list_changed.
	go r.WatchPolicy(ctx, gw.Policy.WatchInterval, opa.Fingerprint, func() {
		auditLog.Event("mcp-policy-change", true, nil)
	})

	// Serve returns after ctx ends and all backend instances are stopped;
	// always wait for it so no instance outlives the gateway.
	served := make(chan error, 1)
	go func() { served <- r.Serve(ctx, l) }()
	var httpErr error
	if gw.HTTP.Listen != "" {
		httpErrs := make(chan error, 1)
		stopHTTP, err := serveHTTP(log, gw.HTTP, r, httpErrs)
		if err != nil {
			stop()
			<-served
			return err
		}
		select {
		case httpErr = <-httpErrs:
		case <-ctx.Done():
		}
		stopHTTP()
		stop()
	}
	return errors.Join(httpErr, <-served)
}

// serveHTTP starts the remote transport (MCP Streamable HTTP, OAuth
// resource server). The returned function ends all HTTP sessions and
// shuts the server down.
func serveHTTP(log *slog.Logger, cfg config.HTTP, r *router.Router, errc chan<- error) (func(), error) {
	h, err := transport.NewHTTPHandler(transport.HTTPConfig{
		Resource:             cfg.Audience,
		AuthorizationServers: []string{cfg.Issuer},
		Scopes:               cfg.Scopes,
		AllowedOrigins:       cfg.AllowedOrigins,
		KnownServer:          func(name string) bool { return r.Backends[name] != nil },
		SessionIdle:          cfg.SessionIdleTimeout,
		Log:                  log,
	}, authn.NewOAuth(cfg, nil), r.ServeClient)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	go func() {
		err := srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
		if !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("http: %w", err)
		}
	}()
	log.Info("listening", "http", cfg.Listen, "resource", cfg.Audience)
	return func() {
		// Sessions first: open SSE streams only end with their session.
		h.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}, nil
}

// newAudit sets up the audit trail: JSON records on stderr (journald),
// argument digests keyed with the per-installation key in the state
// directory, and security-relevant events to the kernel audit subsystem.
func newAudit(log *slog.Logger, gw *config.Gateway) (*audit.Logger, func(), error) {
	key, err := audit.LoadKey(filepath.Join(gw.StateDir, "audit.key"))
	if err != nil {
		return nil, nil, fmt.Errorf("audit key: %w", err)
	}
	opts := audit.Options{Key: key}
	closeFn := func() {}
	if gw.Audit.Kernel != "off" {
		nl, err := audit.OpenNetlink()
		switch {
		case err == nil:
			opts.Kernel = nl
			closeFn = func() { _ = nl.Close() }
			log.Info("kernel audit enabled")
		case gw.Audit.Kernel == "on":
			return nil, nil, fmt.Errorf("kernel audit: %w", err)
		default:
			log.Warn("kernel audit not available", "err", err)
		}
	}
	return audit.New(os.Stderr, opts), closeFn, nil
}

func newLauncher(log *slog.Logger, s config.Supervisor) (supervisor.Launcher, error) {
	switch s.Mode {
	case "exec":
		log.Warn("supervisor mode exec: backends run unconfined as child processes (development only)")
		return &supervisor.Exec{Log: log}, nil
	case "systemd":
		useSELinux := s.SELinux == "on" || (s.SELinux == "auto" && supervisor.SELinuxEnabled())
		log.Info("supervisor mode systemd", "selinux", useSELinux)
		return &supervisor.Systemd{Log: log, SELinux: useSELinux, MCS: supervisor.NewMCSAllocator(mcsLo, mcsHi)}, nil
	}
	return nil, fmt.Errorf("unknown supervisor mode %q", s.Mode)
}
