# Changelog

All notable changes to mcp-gateway. Versions follow
[Semantic Versioning](https://semver.org/). From 0.4 on, configuration,
role data and APIs change compatibly: what goes away is deprecated in one
minor release (with a warning) and removed in the next.

## Unreleased

### Added

- Setup packages for system management servers:
  `mcp-gateway-profile-systemd`, `-firewalld`, `-zypp` and
  `-suseconnect` install the server definition, the roles to bind users
  to (`systemd-reader`, `systemd-operator`, `firewalld-reader`,
  `zypp-reader`, `zypp-installer`, `suseconnect-reader`,
  `suseconnect-admin`), and where needed the account `mcp-sysmgmt` and a
  polkit rule. `mcp-gateway-profile-zypp` includes a privileged
  definition to link into `/etc/mcp-gateway/servers.d`. The SELinux
  modules `mcp_systemd`, `mcp_firewalld`, `mcp_zypp` and
  `mcp_suseconnect` come with `mcp-gateway-selinux`; they replace modules
  of the same names built from the user guide's examples.
  `mcp-gateway-profile-systemd` recommends `man`, without which
  systemd-mcp does not offer `get_man_page`.

- `mcp-gateway inspect` starts an MCP server (a registered one as for
  shared discovery, or a command), lists its tools, prompts and resource
  templates, classifies the tools as reading or changing from their
  annotations and names, drafts a reader and an operator role (and a
  server definition for a command), and checks role data against the
  tools the server has. The VM test checks the shipped roles of the
  setup packages against the real servers this way. The SELinux module
  lets backend instances use a socket from an administrator's shell for
  this.

- `mcp-gateway review` scans a server's source (Go, Python,
  JavaScript/TypeScript, C/C++, Rust) for the programs it runs, D-Bus
  names and polkit actions, paths, network access, root checks and
  environment variables, with file and line and the SELinux type on the
  system, and with a profiling run's `denials.json` marks what that run
  did not reach. The CI job that builds the setup servers reviews their
  sources.

- `mcp-gateway profile` runs a registered server with its SELinux domain
  permissive (a new domain from the template for a server without one),
  calls its reading tools with arguments from their schemas (others from
  a calls file, or all with `--call-all`) and drafts from the denials a
  policy module, file contexts and the definition, with hints on what
  allow rules cannot express (helpers needing a transition,
  capabilities, refused polkit authorizations). dontaudit rules are off
  during the run, so silently denied accesses are recorded too.
  `--verify` repeats the
  calls enforcing and fails on a denial. The VM test profiles
  firewalld-mcp as an unknown server and verifies the draft.

- The gateway is a `Type=notify` service with a watchdog: systemd sees
  it ready once its sockets are up, `systemctl status` shows sessions,
  server instances and pending approvals, and a gateway whose sessions,
  instances or approvals stay locked for a minute is restarted
  (`WatchdogSec=60s`), after writing every goroutine's stack to the
  journal.

- Fuzz tests for the JSON-RPC parser, the HTTP transport (no request
  without a valid token reaches a session, none reaches another
  principal's), the policy input and the parameters policy decides on
  (a server must read what policy saw); CI runs each for a minute.

- `mcp-gateway doctor` checks an installation for what had to be
  debugged by hand: the configuration and role data, the services and
  whether OPA decides, servers that do not start, roles naming tools a
  server does not offer, SELinux denials involving the gateway, OPA and
  the servers, servers running as an account no polkit rule names, and
  members of `socket_group` without a role.

- Metrics in the Prometheus text format: decisions by action and
  effect, decisions that failed closed, OPA query latency and errors,
  server instance starts and failures, approvals decided and pending,
  sessions, instances, a pending restart. Root reads them on the control
  socket (`GET /v1/metrics`); `metrics.listen` also serves them over
  plain HTTP (`/metrics`, SELinux port type `mcp_metrics_port_t`).

- Format versions: `gateway.yaml`, server definitions and role data may
  name their format with `version: 1` (`"version": 1`); files without
  one are read as version 1, and other versions are refused with an
  error that names the version the gateway reads. Deprecated keys are
  logged as warnings at start and by `mcp-gateway --check`, and removed
  a minor release later. CI checks that the configuration of the
  previous minor release (0.3) is still read. The shipped files and the
  drafts of `mcp-gateway inspect` and `profile` carry `version: 1`.

- Policy documents and control API: every policy input (decisions, the
  filter, approver rules, "what changes?") has `"version": 1`, and a
  decision may name its version (`"version": 1`; another version
  denies). `GET /v1/status` also reports the gateway's `version`. The
  fields of the policy documents and of the control API's requests and
  responses are listed in contract files, and a test fails when one
  disappears.

- Roles shipped with server setups: files in
  `/usr/share/mcp-gateway/policy/mcp/profiles/<setup>/data.json`
  (`data.mcp.profiles`) add roles that bindings may name; a role of the
  same name in the role data replaces a shipped one. They are known to
  `--check-policy-data` (new option `--shipped-policy`), listed by
  `GET /v1/policy` and shown in Cockpit, and part of the policy
  fingerprint (installing a setup tells clients to list tools again).

### Changed

- The threat model in the architecture document was reviewed and now
  lists, for each threat, the mitigation and the risk that remains.
  Decisions on three open questions: rate-limit counters stay in memory
  and start afresh after a restart (D11); policy and grants are checked
  when a call starts, not while it runs (D12); paths are checked as
  strings, and servers confine themselves beneath their root (D13).
  The user guide describes all three (chapters 4, 6, 7 and 9).

- The rate limiter drops the counters of keys that have not been used
  for an hour, so its memory no longer grows with every principal,
  server and tool seen since the start.

### Fixed

- firewalld-mcp's `get_services_for_zone` and `get_service_info` read
  the permanent firewall configuration, which needs polkit's
  `org.fedoraproject.FirewallD1.config.info`: the polkit rule of
  `mcp-gateway-profile-firewalld` and the example in the user guide
  (chapter 13) granted only `FirewallD1.info`, so both tools were refused
  ("Not Authorized(polkit)"). Found by `mcp-gateway profile`.

- Updates of a subscribed resource (`notifications/resources/updated`)
  were passed on even after a policy change took away the agent's
  access to that resource, and for any URI the server named, even one
  the agent may not subscribe to. Each update is now decided again as
  it arrives and dropped if denied.

- The demo file server `mcp-fs-demo` followed symbolic links out of
  its root: a link inside the root to `/etc` let policy allow a path
  under the root while the server read outside it. It now opens every
  path beneath its root with `os.Root`.

## v0.3.3 — 2026-10-02

A security fix, and an SELinux fix. Update and restart the gateway
(`systemctl restart mcp-gateway.service`); the configuration and the
role data need no changes. A client that sends repeated keys, or keys
differing only in case, now gets `invalid params`; no MCP client does
that on purpose.

### Fixed

- Security: a client could make an MCP server act on other arguments
  than policy decided on. The gateway decided on parameters with exact
  keys and forwarded the arguments as sent, so `{"path": "/home/a",
  "Path": "/etc/shadow"}`, `{"Arguments": …}` or `{"Path": …}` alone
  was checked as one path (or none) and read as another by servers that
  decode case-insensitively, such as Go servers using structs, or that
  keep the first of repeated keys. Requests with repeated keys, keys
  differing only in case, or keys differing only in case from one the
  gateway reads or an argument the tool or prompt declares are now
  refused (`invalid params`). Found by fuzzing; the fuzz tests and a CI
  job running them come with the fix.

- SELinux: the gateway could not stop instances of servers that do not
  exit when their input closes (for example systemd-mcp, zypp,
  suseconnect-mcp): systemd checks stopping a transient unit on its
  file, which `mcpgw_t` could not stop. Such instances kept running
  after their idle timeout, a stop from the Cockpit page, or the
  gateway's own stop.

## v0.3.2 — 2026-10-02

A correction to the user guide; the programs, the policy and the SELinux
module are unchanged. Upgrading from 0.3.1 needs no changes and no
restart. If you set up firewalld-mcp from the user guide, add the action
below to your polkit rule.

### Fixed

- User guide, chapter 13: firewalld-mcp's `get_services_for_zone` and
  `get_service_info` read the permanent firewall configuration, which
  needs polkit's `org.fedoraproject.FirewallD1.config.info`; the example
  rule granted only `FirewallD1.info`, so both tools were refused ("Not
  Authorized(polkit)").

## v0.3.1 — 2026-10-01

The gateway starts confined on openSUSE Leap 16. Upgrading from 0.3.0
needs no configuration changes; restart the gateway after the update
(`systemctl restart mcp-gateway.service`), since the package no longer
does.

### Fixed

- SELinux: on policies that grant systemd the transition into a service
  domain only together with `init_systemd` (openSUSE Leap 16), the
  gateway, OPA and the server instances stayed in `init_t` and OPA failed
  to start; the module now allows the transition under
  `NoNewPrivileges=` itself.

## v0.3.0 — 2026-10-01

Agents can install and remove packages through the gateway: MCP servers
that change the system as a whole (mcp-server-zypp) run as privileged
servers, outside the sandbox but with every call decided by policy,
approved and audited. The supported distributions are now SLES 16 and
openSUSE Leap 16.

Upgrading from 0.2.x needs no configuration changes. From 0.3.0 on, the
package no longer restarts the gateway on updates; restart
`mcp-gateway.service` yourself after an update (the update from 0.2.x
still restarts it, through the old package's scripts). If you copied
the system management examples from the user guide, compare them with
chapter 13: the firewalld polkit rule is narrower and the systemd-mcp
role no longer allows every `get_*` tool.

### Added

- Privileged servers (`privileged: true`, `run_as: root`) for MCP
  servers that change the system as a whole, such as package
  installation with mcp-server-zypp: no sandbox, SELinux domain without
  an MCS pair and the installing worker in `rpm_t`
  (`mcp_gateway_backend_rpm`). Accepted only in
  `/etc/mcp-gateway/servers.d`. Calls are allowed without approval only
  by permissions naming server and tool exactly (`admin` asks), every
  decision goes to the kernel audit log, and the gateway never stops
  such an instance while a call runs, also on shutdown (it waits up to
  28 minutes; `TimeoutStopSec=30min`).
- `GET /v1/status` (control API) reports a pending restart; the Cockpit
  page shows it.

### Changed

- The package no longer restarts `mcp-gateway.service` on update (an
  update through a privileged server would wait for itself); restart it
  yourself. The gateway logs that it was updated.
- Supported distributions are SLES 16 and openSUSE Leap 16; Tumbleweed
  is the development platform. SLES 15 and Leap 15 (AppArmor) are out of
  scope.
- User guide, chapter 13, checked against the servers' upstream
  sources: systemd-mcp's `--allow-read`/`--allow-write` have no effect
  (dropped from the example), its account needs the `systemd-journal`
  group, and `get_file` is allowed freely only below the systemd
  configuration directories; the firewalld polkit rule grants only
  `FirewallD1.info` (firewalld-mcp only reads); new section on
  mcp-server-zypp.

## v0.2.8 — 2026-10-01

The gateway's records in the kernel audit log are no longer cut short.
Upgrading from 0.2.7 needs no configuration changes.

### Fixed

- Kernel audit records of the gateway lost their last character
  (`res=succes`, `res=faile`): the kernel replaces the last byte of a user
  record with a NUL, which the gateway did not send. Tools that filter
  on `res=` (`ausearch --success`, `aureport`) misread them.

## v0.2.7 — 2026-10-01

MCP servers' log output (stderr) reaches the journal again instead of
the gateway's connection to the server. Upgrading from 0.2.6 needs no
configuration changes.

### Fixed

- What MCP servers write to stderr went to the gateway's connection to
  the server instead of the journal: with stdout passed as a file
  descriptor, systemd duplicated it to stderr. The gateway skipped such
  lines ("invalid message from backend"), so calls worked, but the
  servers' logs were missing from the journal. Instances now get
  `StandardOutput=null` (stdout is still the gateway's socket).

## v0.2.6 — 2026-10-01

Permissions can offer approvals for a fixed time, for agents that open a
new MCP session for every prompt, where a "session" grant ends with the
prompt. Upgrading from 0.2.5 needs no configuration changes; existing
role data keeps offering "once" and "session".

### Added

- Permissions can offer approvals for a fixed time:
  `"approval_scopes": ["once", "1h", "8h"]` in the role data (durations
  up to 720h; "once" is always offered; default "once" and "session").
  Such a grant is not bound to the agent's session, so it also helps
  agents that open a new MCP session for every prompt (Kit), where a
  "session" grant ends with the prompt. Cockpit offers "For 1h" and so
  on; the JSON Schema and `mcp-gateway --check-policy-data` check the
  values.

## v0.2.5 — 2026-10-01

Stops the gateway from telling clients every 10 seconds that the policy
changed, logs what MCP servers write to stdout when it is not MCP, and
documents running suseconnect-mcp. Upgrading from 0.2.4 needs no
configuration changes.

### Fixed

- The gateway told clients every `policy.watch_interval` (10 seconds)
  that the policy had changed (`notifications/tools/list_changed` and
  friends, "policy changed; notifying sessions" in the log), although it
  had not: OPA, which `mcp-opa.service` runs with decision logging,
  returns a new decision id with every response, and the gateway's
  policy fingerprint included it. Clients re-listed their tools all the
  time.

### Changed

- A line an MCP server writes to stdout that is not MCP is logged with
  its first 200 bytes (`line` in "invalid message from backend"), which
  usually shows the cause: a usage message or a log line on stdout.

### Added

- User guide chapter 13: running suseconnect-mcp (root, network, its
  state directory and the writable credentials directory).

## v0.2.4 — 2026-10-01

Server definitions can make paths writable for their instances, for
servers that keep state outside their private /tmp (such as
suseconnect-mcp in /var/lib/suseconnect-mcp). Existing definitions
behave as before; upgrading from 0.2.3 needs no configuration changes.

### Added

- Server definitions can make paths writable for their instances, which
  `ProtectSystem=strict` otherwise keeps read-only:
  `sandbox.state_directory` (a directory below `/var/lib` that systemd
  creates for the instance, e.g. for a server that keeps state in
  `/var/lib/<name>`) and `sandbox.read_write_paths` (other existing
  paths). Paths of the gateway itself are refused.

## v0.2.3 — 2026-09-30

Builds for SLES 16.0, which failed with 0.2.2 in the build's file list
check. No functional changes; upgrading from 0.2.2 needs no
configuration changes.

### Fixed

- The package did not build for SLES 16.0: its build root has no package
  owning `/usr/share/polkit-1/rules.d`, and the file list check failed.
  The build now pulls in polkit, which owns it.

## v0.2.2 — 2026-09-30

SELinux fixes found running systemd, firewalld and snapper MCP servers
on SLES 16.1, and a user guide chapter on setting them up. Upgrading
from 0.2.1 needs no configuration changes; modules built for dedicated
backend domains can now use the gateway's template.

### Added

- User guide chapter 13: running system management MCP servers
  (systemd, firewalld, snapper) behind the gateway: a dedicated account,
  SELinux domains for D-Bus, polkit rules, and a role that reads freely
  and changes only with approval.

### Fixed

- SELinux: `mcp-gateway-selinux` installs `mcp_gateway.if`, so modules
  for dedicated backend domains can use `mcp_gateway_backend_template`
  as chapter 4 describes; before, building such a module failed.
- SELinux: backend domains may read their cgroup limits, which Go
  servers do at start (denials for `cgroup_t`).
- SELinux: the gateway's user lookups through nss-systemd no longer log
  denials where PID 1 runs as `kernel_t` (seen on SLES 16.1).

## v0.2.1 — 2026-09-30

Makes the SELinux package installable when it was built against a newer
release of the host's selinux-policy version. Upgrading from 0.2.0
needs no configuration changes.

### Fixed

- `mcp-gateway-selinux` could not be installed when it was built against
  a newer release of the host's selinux-policy version (seen on SLES
  16.1: "nothing provides 'selinux-policy >= VERSION-RELEASE'"). It now
  requires the selinux-policy version only, not also its release.

## v0.2.0 — 2026-09-29

The policy engine fits into an existing OPA estate (decision D8): the
gateway's policy lives entirely below `data.mcp`, so its bundles can
share an OPA with other teams' policies, and its decision logs can go to
the same collector. Role data edits are checked against a JSON Schema
and previewed ("what changes?") before they take effect, and the policy
is linted with Regal in CI. Includes the fixes of 0.1.1.

**Upgrading from 0.1:** custom policy that reads `data.rbac` or adds to
`system.log`, and drop-ins that replace `ExecStart=` of
`mcp-opa.service`, need changes (below). The role data file stays where
it is and needs none.

### Changed (incompatible)

- **Everything below `data.mcp`**, so the policy can share an OPA with
  other policies:
  - The role data is `data.mcp.rbac` (was `data.rbac`); the file stays at
    `/etc/mcp-gateway/policy/rbac/data.json`. `mcp-opa.service` loads
    `/etc/mcp-gateway/policy` with the prefix `mcp:`, so other data
    files there move below `data.mcp` as well.
  - The decision-log mask is `mcp.log.mask` (was `system.log.mask`,
    now `policy/mcp/log.rego`); the OPA units set
    `decision_logs.mask_decision` to `/mcp/log/mask`.
  - Bundles from `mcp-policy-bundle` declare the root `mcp` (was the
    whole data tree); Rego packages outside `mcp` fail the build.

  Custom policy that reads `data.rbac` or adds to `system.log` must be
  changed (`docs/user-guide/12-custom-policy.md`). A drop-in replacing
  `ExecStart=` of `mcp-opa.service` must add the prefix and the mask
  setting.

### Added

- **JSON Schema for the role data** (`rbac.schema.json`, draft-07,
  installed in `/usr/share/mcp-gateway/schema/`). `mcp-gateway --check`
  and the new `mcp-gateway --check-policy-data` report every problem with
  its location: unknown fields, wrong types and values, regular
  expressions that do not compile, and bindings or approver rules that
  name a role that does not exist. Cockpit runs the check before saving
  the role data, `mcp-policy-bundle` before signing. Roles and
  permissions may carry a `description`.
- **Shipping decision logs to a collector** through OPA's decision-log
  service: drop-in `decision-logs.conf` and `decision-logs.yaml.example`
  in `/usr/share/mcp-gateway/opa/` (chapter 9). All `mcp-opa.service`
  variants pass `$OPA_EXTRA_ARGS` to OPA, so the drop-in combines with
  every policy mode.
- **"What changes?" before saving role data.** `POST /v1/policy/whatif`
  on the control API evaluates the decision for every user and group the
  current or proposed bindings name, over every tool, prompt, resource
  template and client request the MCP servers offer, with the current
  and with the proposed role data (policy package `mcp.whatif`), and
  returns those that differ. Cockpit shows them and saves only after
  confirmation. Allowed to those the default approver rules name besides
  `self` (new rule `mcp.approvals.review_policy`) and to root.
- **Regal** (the Rego linter) in CI, pinned to v0.42.0, with the
  repository's configuration in `.regal/config.yaml`. The policy follows
  it: the rules the gateway and OPA query are annotated as entrypoints,
  `decision` has a `default`, and rules of the same name are kept
  together.

### Changed

- The gateway's policy fingerprint (which triggers `list_changed`
  notifications) covers only modules in packages below `mcp` and
  `data.mcp.rbac`, so other policies in a shared OPA do not affect it.

## v0.1.2 — 2026-09-30

Makes the SELinux package installable when it was built against a newer
release of the host's selinux-policy version. Upgrading from 0.1.1
needs no configuration changes.

### Fixed

- `mcp-gateway-selinux` could not be installed when it was built against
  a newer release of the host's selinux-policy version (seen on SLES
  16.1: "nothing provides 'selinux-policy >= VERSION-RELEASE'"). It now
  requires the selinux-policy version only, not also its release.

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
