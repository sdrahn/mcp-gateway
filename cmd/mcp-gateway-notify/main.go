// Command mcp-gateway-notify shows desktop notifications for mcp-gateway
// approvals the logged-in user may decide on. It is started with the
// desktop session (XDG autostart) and exits quietly for users without
// access to the gateway's control socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/sdrahn/mcp-gateway/internal/notifyagent"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

func main() {
	socket := flag.String("socket", "/run/mcp-gateway/control.sock", "the gateway's control socket")
	page := flag.String("url", "https://localhost:9090/mcp-gateway#/approvals/{id}",
		"approval page ({id}: approval id), used when the gateway has no approvals.url_template")
	debug := flag.Bool("debug", false, "log debug messages")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("mcp-gateway-notify", version.Version)
		return
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	notifier, err := notifyagent.NewDBusNotifier()
	if errors.Is(err, notifyagent.ErrRunning) {
		return
	}
	if err != nil {
		log.Error("desktop notifications unavailable", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	agent := &notifyagent.Agent{
		Socket:      *socket,
		URLTemplate: *page,
		Notifier:    notifier,
		Open:        func(u string) error { return exec.Command("xdg-open", u).Start() },
		Log:         log,
	}
	if err := agent.Run(ctx); errors.Is(err, notifyagent.ErrNoAccess) {
		log.Info("no access to the gateway's control socket; nothing to notify", "socket", *socket)
	} else if err != nil {
		log.Error("stopped", "err", err)
		os.Exit(1)
	}
}
