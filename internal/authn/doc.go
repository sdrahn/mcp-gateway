// Package authn authenticates client connections and produces a
// principal.Principal.
//
// Local connections are identified by the kernel (SO_PEERCRED for uid/gid/pid,
// SO_PEERSEC for the SELinux label). Remote connections present an OAuth 2.1
// bearer token; the gateway acts as a resource server only and never issues
// or forwards tokens.
//
// See docs/architecture.md, section 5.2.
package authn
