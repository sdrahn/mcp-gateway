// Package version holds build information, set at link time:
//
//	go build -ldflags "-X github.com/sdrahn/mcp-gateway/internal/version.Version=v0.1.0"
package version

// Version is the release version of the gateway binaries.
var Version = "devel"
