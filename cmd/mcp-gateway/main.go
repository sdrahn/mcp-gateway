// Command mcp-gateway is the policy-enforcing MCP gateway daemon.
//
// Current scope (docs/architecture.md, section 11): local clients on the
// unix socket, per-server and aggregated endpoints, OPA decisions,
// form-mode approvals, backends as systemd transient units shared by a
// principal's sessions.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
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
	configPath := flag.String("config", config.DefaultConfigPath, "path to the gateway configuration")
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
	gw, err := config.LoadGateway(configPath)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	backends, err := config.LoadBackends(gw.ServersDir)
	if err != nil {
		return fmt.Errorf("loading backend registry: %w", err)
	}
	log.Info("configuration valid", "socket", gw.Socket, "backends", len(backends))
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

	r := &router.Router{
		Backends: backends,
		Launcher: launcher,
		PDP:      pep.NewOPA(gw.Policy.OPASocket, gw.Policy.Timeout),
		Broker:   broker.New(gw.ApprovalTimeout),
		Audit:    audit.New(os.Stderr),
		Log:      log,

		IdleTimeout: gw.Supervisor.IdleTimeout,
	}
	return r.Serve(ctx, l)
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
