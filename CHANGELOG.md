# Changelog

All notable changes to mcp-gateway. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
change configuration, policy data or APIs.

## v0.1.1 — 2026-09-29

Makes 0.1.0 work on openSUSE with SELinux enforcing, where the gateway
could not serve requests. Upgrading from 0.1.0 needs no configuration
changes; the packages create `/run/mcp-gateway` anew (tmpfiles.d) and
restart the services.

### Fixed

Found by the new VM test, which installs the packages on openSUSE
Tumbleweed with SELinux enforcing:

- The gateway failed to start: it could not give its client socket to
  the `mcp-users` group because it was not a member of that group
  (`SupplementaryGroups=mcp-users` in `mcp-gateway.service`).
- OPA failed to start with `--watch`: the SELinux policy lacked the
  `watch` permission on the policy directories.
- The gateway did not detect SELinux from inside its domain and started
  backends without their SELinux domain and MCS categories; it now
  checks the mount table.
- Clients could not connect after OPA restarted, and OPA could fail to
  start: both services declared `/run/mcp-gateway` as their
  `RuntimeDirectory=`, so systemd handed the directory, sockets included,
  to whichever started last. It is now created by tmpfiles.d
  (mode 0771, group `mcp-gateway`).
- On openSUSE, the gateway could not start any MCP server instance:
  systemd denied StartTransientUnit because the policy rule for it came
  from a reference-policy-only interface.
- The filesystem MCP server could not create files directly in the
  user's home directory (SELinux).
- SELinux denials from the gateway and OPA in normal operation: the MCS
  scan's walk over /proc (now silenced), the Go runtime reading sysctls
  and cgroup limits, and OPA's user lookup.
- The demo MCP server was labelled `bin_t` instead of `mcpsrv_fs_exec_t`:
  its file context entry lost to the base policy's more specific
  `/usr/libexec` entries.

### Added

- CI job `vm`: the packages on an openSUSE Tumbleweed VM (QEMU/KVM) with
  SELinux enforcing: labels, domains, per-user instances with distinct
  MCS pairs, policy decisions, polkit, credentials, kernel audit, and no
  SELinux denials (`test/vm`).

## v0.1.0 — 2026-09-28

First release. mcp-gateway makes stdio MCP servers on a Linux host
available to local and remote AI agents under central control: every
request is authorized by OPA, sensitive calls can require a human's
approval, each server runs confined by systemd and SELinux, and
everything is audited. Target distributions are openSUSE Tumbleweed,
Leap 16 and SLES 16, packaged with the Open Build Service.

### Transports and clients

- Local agents over a unix socket, identified by the kernel (peer
  credentials and SELinux label); `mcp-connect` shim for agents that can
  only spawn a command.
- Remote agents over MCP Streamable HTTP: OAuth 2.1 resource server
  (JWT/JWKS, RFC 9728 metadata, RFC 8707 audience), mapping to local
  accounts, allowed origins, mTLS with certificate-bound tokens
  (RFC 8705), resumable event streams.
- Per-server and aggregated endpoints with namespaced tools, prompts and
  resources.

### Policy

- OPA sidecar (unix socket), fail-closed: roles, permissions, bindings
  and approver rules as data; decisions `allow`, `deny` and `ask`;
  filtered listings; `list_changed` notifications on policy changes.
- Obligations: output redaction, size and rate limits, argument
  constraints, full audit, and pseudonymization with policy-controlled
  re-identification.
- Signed policy bundles (`mcp-policy-bundle`), bundle-server mode.
- Requests from MCP servers (sampling, elicitation, roots) decided by
  policy; elicitations asking for secrets refused unless allowed.

### Approvals

- Form, URL and out-of-band approval channels; scopes once, session or a
  duration; persistent grants; pending approvals survive disconnects and
  restarts.
- Control API on a unix socket; Cockpit page for approvals, grants,
  servers and instances, role bindings and audit records.
- Push notifications: desktop agent (`mcp-gateway-notify`) and e-mail.

### MCP server supervision

- Instances as transient systemd units per principal or per session, in
  a hardened sandbox, in their own SELinux domain with a unique MCS
  category pair; coordination with libvirt and container workloads.
- Idle stop, restart backoff, shared discovery instances with a cache,
  credentials through systemd, dynamic users for remote principals.

### Audit

- JSON audit records in the journal with keyed argument digests and
  decision ids correlated with OPA's decision log; kernel audit records
  (`TRUSTED_APP`) for denials, approvals, revocations, policy changes and
  MCS collisions.

### Packaging and documentation

- OBS packaging for openSUSE and SLES: `mcp-gateway`,
  `mcp-gateway-selinux`, `mcp-gateway-cockpit`, `mcp-gateway-desktop`,
  `mcp-gateway-demo-server`.
- User guide (`docs/user-guide/`) and architecture document
  (`docs/architecture.md`).

### Known limitations

- The confined systemd/SELinux path is covered by CI builds and the
  package smoke test, but not yet by tests on a real SELinux-enforcing
  host.
- SLES 15 and Leap 15 use AppArmor; no AppArmor profiles are provided.
- Policy bundles claim the whole OPA data tree (`"roots": [""]`), so they
  cannot share an OPA with other teams' bundles yet.
- Do not combine signed bundles with OPA's `--watch`: OPA does not verify
  signatures on watch reloads (the shipped drop-in leaves it out).
- Path arguments: `..` segments are rejected, symlinks inside an allowed
  tree are left to file permissions and SELinux.
- Pseudonymization is rule-based and covers only data flowing through the
  gateway from MCP servers.
