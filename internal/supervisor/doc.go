// Package supervisor starts, tracks and stops backend MCP server instances.
// Each instance serves exactly one principal (or one session) and runs as a
// systemd transient unit in its own SELinux domain, with a per-instance MCS
// category pair and stdio wired to the gateway through a socketpair.
//
// See docs/architecture.md, sections 5.7 and 5.8.
package supervisor
