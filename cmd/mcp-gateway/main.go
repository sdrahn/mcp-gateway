// Command mcp-gateway is the policy-enforcing MCP gateway daemon.
//
// Skeleton: it loads and validates the configuration and the backend
// registry, then exits. Transports, routing and enforcement follow in the
// proof of concept (docs/architecture.md, section 11).
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

func main() {
	configPath := flag.String("config", config.DefaultConfigPath, "path to the gateway configuration")
	checkOnly := flag.Bool("check", false, "validate the configuration and backend registry, then exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("mcp-gateway", version.Version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	gw, err := config.LoadGateway(*configPath)
	if err != nil {
		log.Error("loading configuration", "err", err)
		os.Exit(1)
	}
	backends, err := config.LoadBackends(gw.ServersDir)
	if err != nil {
		log.Error("loading backend registry", "err", err)
		os.Exit(1)
	}
	log.Info("configuration valid", "socket", gw.Socket, "backends", len(backends))

	if *checkOnly {
		return
	}
	log.Error("serving is not implemented yet")
	os.Exit(1)
}
