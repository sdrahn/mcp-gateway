// Package transport implements the client-facing transports of the gateway:
// the local unix socket (used directly or through the mcp-connect stdio
// shim) and MCP Streamable HTTP for remote clients.
//
// Every transport yields a uniform connection: a JSON-RPC message stream
// plus the raw identity evidence (peer credentials, SELinux peer label, or
// bearer token) that package authn turns into a principal.
//
// See docs/architecture.md, section 5.1.
package transport
