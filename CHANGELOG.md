# Changelog

All notable changes to mcp-gateway. Versions follow
[Semantic Versioning](https://semver.org/). From 0.4 on, configuration,
role data and APIs change compatibly: what goes away is deprecated in one
minor release (with a warning) and removed in the next.

## Unreleased

### Added

- Landlock as a second wall around server instances (roadmap step 30,
  D19). A server definition's new `landlock` key (`read`, `write`,
  `exec` trees with `${HOME}` and `${USER}`; `tcp_connect`, `tcp_bind`
  ports; `required`) restricts each instance with the kernel's Landlock
  LSM: it starts through the new `/usr/libexec/mcp-gateway/mcp-landlock`,
  which restricts itself (and a base: the system's programs and
  configuration, a few devices, private temporary directories,
  credentials), scopes signals and abstract unix sockets to the
  instance, and executes the server. It binds root too and stacks with
  SELinux and the sandbox. The shipped `fs` reaches its user's home and
  nothing else of `/home`, so another user's world-readable files are
  out of reach; `gateway-docs` reads only the documentation; `exec`
  reads the system and its state. Without Landlock in the kernel,
  instances run as before and the doctor warns (new check `landlock`);
  `required: true` refuses to start instead.
- The gateway's own programs restrict themselves with Landlock at
  startup, whatever starts them (step 30, stage B): `mcp-server-fs` to
  its `--root` directories, `mcp-server-exec` to the trees its commands
  name (the system read, their programs executed, the paths in `dir`
  and `argv` written, or read for `read_only` commands), and
  `mcp-http-connector` and `mcp-oauth-helper` to their credentials, the
  CA certificates and the TCP ports of their server or proxy. A command
  file's new `landlock` key (`read`, `write`, `exec`) widens the trees
  for its commands. The journal line at start says what was applied.
- `mcp-gateway-admin inspect` runs a server started by command, or a
  registered one with `--exec`, under Landlock (step 30, stage C): the
  system read-only, a directory of its own (removed afterwards) as its
  home and `TMPDIR`, its program and the paths on its command line
  readable and executable, no TCP. `--home` gives it your home,
  `--network` TCP, `--allow DIR` another tree. It needs
  `/usr/libexec/mcp-gateway/mcp-landlock` (package mcp-gateway).
- Diagnosis of Landlock (step 30, stage D): the doctor's `landlock`
  check tells a kernel built without Landlock from one that has it but
  not in its `lsm=` list, and names per server what the kernel leaves
  out of its rules (`required` rules it cannot apply in full fail). A
  server that does not start, runs restricted and was denied nothing by
  SELinux gets `landlock NAME`: Landlock is the likely cause, since its
  refusals leave no audit record. Cockpit shows "Landlock" among a
  server's facts and adds the hint under an instance's log that says
  "permission denied"; `GET /v1/servers` has `landlock`.
- The setup packages' definitions restrict their instances with
  Landlock (step 30): `systemd` reads the system's configuration and
  programs, the logs and the journal, `/run/systemd` and man's cache
  (`get_file` reads within these trees only); `firewalld` the
  configuration and programs; the unprivileged `zypp` also the
  repositories' caches and zypp's state. snapper, the
  privileged zypp and suseconnect have none (see the notes in their
  definitions).

## v0.17.1 — 2026-10-08

The gateway's own file and command servers tell agents how to use them,
and `gateway_capabilities` shows each user the instructions of their own
`fs`: in 0.17.0 it showed those of the shared discovery instance,
"Files below /". Upgrading from 0.17.0 needs no changes. After the
update, restart the gateway (`systemctl restart mcp-gateway.service`);
running `fs` and `exec` instances get the new texts when they next
start. A copy of the `exec` definition in
`/etc/mcp-gateway/servers.d/exec.yaml` keeps working, without the new
`--instructions` text; copy the shipped one
(`/usr/share/mcp-gateway/servers.d/exec.yaml`) again to get it.

### Changed

- `mcp-server-fs` tells agents how to use it: its instructions say which
  tool to use for what (search before reading whole files, then read the
  lines with `read_text_file`), that nothing outside its roots can be
  reached, and the limits of one call (read, write, entries), which the
  tool descriptions repeat.
- `mcp-server-exec` says what each tool runs and within which limits:
  after the administrator's description, a line from the definition
  ("Runs: /usr/bin/rpm -q {package}. Ends after 1 min; output … up to
  1 MiB."); tools have a title, `idempotentHint` when read-only, and an
  `outputSchema` for their structured result. Its instructions list the
  commands and say there are no others. A new `--instructions` option
  adds what the definition knows; the shipped one says the commands run
  as the user, without network, confined by SELinux.

### Fixed

- `gateway_capabilities` showed, for a server whose command names the
  user (`fs`: `--root ${HOME}`), the instructions of the shared discovery
  instance, which runs with the home `/`: "Files below /". It now asks
  the user's own instance, as it does for servers without shared
  discovery, which before had no instructions there at all.

## v0.17.0 — 2026-10-08

Agents learn what the user may do instead of finding out by trying.
Tool descriptions say what the user's roles allow (argument limits,
approvals) and carry the administrator's notes (`tool_notes`); denials
say which argument is outside the roles and where to look instead; and
on the aggregated endpoint the gateway's own tool `gateway_capabilities`
lists, per server, its instructions and its tools with those limits.
The `systemd` setup package notes the time format `list_log` takes,
and `mcp-gateway-admin inspect` suggests notes for arguments a server's
schema leaves unclear.

Upgrading from 0.16.x needs no changes to `gateway.yaml`, server
definitions or role data. After the update, restart the gateway
(`systemctl restart mcp-gateway.service`); the package does not. Things
to know:

- **A new tool on the aggregated endpoint.** `gateway_capabilities` is
  listed for every principal holding a permission that is not a deny
  and needs no approval; agents that count or allow-list tools see one
  more. Policy decides on it as on any tool (`resource.builtin`).
- **A custom policy** (chapter 12, approaches B and C) gets none of
  this until it adds it: without `data.mcp.filter.hints` the
  descriptions have no "According to your roles" line, without a rule
  allowing `resource.builtin` the capabilities tool is hidden, and its
  own denial reasons stay as they are. The input contract stays at
  version 1; `resource.builtin` is a new field.
- **Denial texts changed.** Reasons that start with "no matching
  permission" keep that start; anything matching the whole text (log
  filters, scripts) needs a look.
- **A copied `systemd` definition** in
  `/etc/mcp-gateway/servers.d/systemd.yaml` replaces the package's and
  has no `tool_notes`; copy them from
  `/usr/share/mcp-gateway/servers.d/systemd.yaml`.
- **Going back to 0.16** refuses server definitions with `tool_notes`
  (an unknown key); remove them first.

### Changed

- The `systemd` setup package's definition has a tool note for
  `list_log`: `from` and `to` are RFC 3339 times with a time zone;
  relative times and other formats are refused. Agents no longer guess
  "-1h" or "2026-10-07 11:00:00". A definition of your own in
  `/etc/mcp-gateway/servers.d` replaces the package's: copy the note.
- Denials say why and what instead (roadmap step 29, part 2). A call a
  role allows, but not with these arguments, is denied with "no matching
  permission: the arguments are outside what your roles allow (path:
  ^/home/alice/)" (the patterns of each such permission; the values sent
  are not repeated). An `arg_constraints` obligation names the pattern
  too ("argument "path" violates a constraint: it must match ^/srv/").
  A denied call that names the gateway's own files through another
  server adds where to look instead: the `gateway-admin` server's
  `show_config`, or `gateway-docs` for the documentation. Reasons that
  start with "no matching permission" keep that start.

### Added

- `mcp-gateway-admin inspect` suggests tool notes: it lists string
  arguments that look like times but whose schema does not say the
  format (a Go `time.Time` has the schema `{"type": "string"}` and
  accepts RFC 3339 only), and string arguments without a description,
  with a draft note to complete; the draft definition of `--out` has
  them as comments. For a `--server`, it marks the tools that have a
  note already and lists notes for tools the server does not offer.
  Only the schemas are read; no tool is called.
- Agents on the aggregated endpoint are told what the user may do
  (roadmap step 29, part 3). The gateway's own tool
  `gateway_capabilities` returns, per server, its instructions and its
  tools with the limits of the user's roles, and where the gateway's
  configuration and documentation are; the instructions point to it.
  Policy decides on it as on any tool (`resource.builtin`, the shipped
  `mcp/builtin.rego`): everyone holding a role gets it. A custom policy without such a rule hides it.
- Tool descriptions tell the agent what the user's roles allow (roadmap
  step 29, part 1). In `tools/list`, a tool limited by the user's roles
  gets a line such as "[mcp-gateway] According to your roles, calls need
  path starting with /home/alice/. Each call needs a human approval, out
  of band …", from the shipped policy's new `data.mcp.filter.hints` and
  the same role data the decisions use. Agents pick a call their roles
  allow instead of finding out by trying; every call is still decided.
  A custom `mcp/filter.rego` without `hints` gives no such lines.
- `tool_notes` in a server definition: the administrator's notes on
  tools (up to 500 characters each), added to their descriptions, for
  what the server's own description does not say (an argument's format,
  for example). The doctor warns about a note for a tool the server does
  not offer.

## v0.16.2 — 2026-10-07

Agents find the gateway's configuration: `show_config` of the
`gateway-admin` server now also shows the exec servers' command files,
and the file server and the documentation tell agents to ask
`gateway-admin` for the gateway's configuration. Upgrading from 0.16.1
needs no changes. After the update, restart the gateway
(`systemctl restart mcp-gateway.service`). A copy of the `fs`
definition in `/etc/mcp-gateway/servers.d` keeps its old command line;
copy the shipped one again
(`/usr/share/mcp-gateway/servers.d/fs-demo.yaml`) for the new
instructions.

### Changed

- `show_config` of the `gateway-admin` server also lists and shows the
  exec servers' command files (`/etc/mcp-gateway/exec.d/*.yaml`, or
  what an exec definition names with `--commands`), with secrets masked
  as in the other files. Agents had no tool that read them.
- The file server's shipped definition (`fs`) tells agents that the
  gateway's configuration is not among its files and that the
  `gateway-admin` server shows it; the documentation index
  (`docs/README.md`) says which server answers which question about the
  gateway, and which do not reach its files.

## v0.16.1 — 2026-10-07

Fixes for the systemd server's program label, the doctor's hints and
its scope with `--server`, and the health check agents run through the
`gateway-admin` server. Upgrading from 0.16.0 needs no changes. After
the update, restart the gateway (`systemctl restart
mcp-gateway.service`); the SELinux module is updated with the package,
and `/usr/bin/mcp-server-systemd` gets its label at the next relabel
(`restorecon -v /usr/bin/mcp-server-systemd`, on a transactional system
`transactional-update run restorecon -v /usr/bin/mcp-server-systemd`
and a reboot). The README, the user guide and the package description
now say that the gateway serves servers that speak Streamable HTTP as
well as stdio.

### Fixed

- The SELinux policy labels `/usr/bin/mcp-server-systemd` as the
  systemd server's program (`mcpsrv_systemd_exec_t`), as it does
  `/usr/bin/systemd-mcp`: the package `mcp-server-systemd` installs the
  program under both names. As hard links they share one label, and a
  relabel of the second name (`restorecon`, a full relabel) set it to
  `bin_t`, after which the shipped `systemd` server could not start.
- The doctor's check of a server's program names the domain when the
  program is labeled as another server's: a definition with the systemd
  program and `selinux_type: mcpsrv_generic_t` (or none, a definition
  written by hand) now gets "set selinux_type: mcpsrv_systemd_t" instead
  of "relabel it: restorecon", which would have let the program start
  in the generic domain without the system bus.
- The doctor run through the `gateway-admin` server (an agent's health
  check) reads snapper's configs for its snapper check: the
  `mcpsrv_admin_t` domain was denied `/etc/snapper/configs`
  (`snapperd_conf_t`), so the check was skipped and each run left a
  denial ("SELinux mcpsrv_admin_t: … snapperd_conf_t:dir { read }").
- `mcp-gateway-admin doctor --server NAME` (and the `doctor` tool of the
  `gateway-admin` server with `server`) checks only that server: the
  gateway's own checks (services, state files, policy, TLS, firewall,
  principals, approver groups) are left out, the configuration and the
  role data are shown only when they fail, SELinux denials only of the
  server's domain, and program labels only of its program and helpers.

## v0.16.0 — 2026-10-07

Agents look things up in the gateway's documentation for a small part
of the tokens it cost before. The file server, and with it the
`gateway-docs` server, searches text (`search_text`), reads a range of
lines (`read_text_file` with `offset` and `limit`) and lists a Markdown
file's headings with their line numbers (`outline_file`). The
`gateway-docs` instructions tell agents to search first, or read the
outline for a broad question, and then read only the section they need:
a lookup costs a few thousand tokens instead of whole chapters, or
about 40,000 for `architecture.md`.

Upgrading from 0.15.x needs no changes to `gateway.yaml`, server
definitions or role data. After the update, restart the gateway
(`systemctl restart mcp-gateway.service`); the package does not. Things
to know:

- **New tools, so roles must allow them.** The shipped roles
  `gateway-docs-reader` and `viewer` allow every tool of `gateway-docs`.
  For `fs`, an installed `/etc/mcp-gateway/policy/rbac/data.json` is kept
  on update: add `{"server": "fs", "tool": "search_text"}` and
  `{"server": "fs", "tool": "outline_file"}` to the roles that should
  have them. Roles written as `read_*` do not gain them.
- **A copied `gateway-docs` definition** in
  `/etc/mcp-gateway/servers.d/gateway-docs.yaml` keeps its old
  instructions; copy the shipped one again
  (`/usr/share/mcp-gateway/servers.d/gateway-docs.yaml`) to get the new
  ones.

### Added

- The file server lists a Markdown file's headings: `outline_file`
  returns each heading with its line number and the lines and bytes of
  its section (`maxLevel` to leave out deeper ones; headings in fenced
  code are not headings). For a broad question without a precise term
  to search for, an agent reads the outline (under 1,000 tokens for
  `architecture.md`) and then the one section with `read_text_file`
  (`offset`, `limit`); the `gateway-docs` instructions say so (roadmap
  step 28). `outline_file` is a new tool: the shipped roles
  `gateway-docs-reader` and `viewer` allow it for `gateway-docs`, and the
  shipped role data's `developer` for `fs`. An installed
  `/etc/mcp-gateway/policy/rbac/data.json` is kept on update; to let
  users outline their files with `fs`, add
  `{"server": "fs", "tool": "outline_file"}` to their role.
- The file server (`mcp-server-fs`, and with it `gateway-docs`) finds
  text: `search_text` returns the matching lines below a path or in one
  file, with file, line number and context, capped (`maxResults`,
  `--max-read`). `read_text_file` reads a range of lines (`offset`,
  `limit`) and says which lines of how many it returned. The
  `gateway-docs` instructions tell agents to search first and read only
  around a match, so looking something up in the documentation costs a
  few thousand tokens instead of whole files (roadmap step 27).
  `search_text` is a new tool: the shipped roles `gateway-docs-reader`
  and `viewer` allow it for `gateway-docs`, and the shipped role data's
  `developer` for `fs`. An installed `/etc/mcp-gateway/policy/rbac/data.json`
  is kept on update; to let users search their files with `fs`, add
  `{"server": "fs", "tool": "search_text"}` to their role.

## v0.15.1 — 2026-10-07

A fix for the health check agents run through the `gateway-admin`
server. Upgrading from 0.15.0 needs no changes; restart the gateway
after the update (`systemctl restart mcp-gateway.service`), so that the
next `gateway-admin` instance runs the new program.

### Fixed

- The doctor run through the `gateway-admin` server (an agent's health
  check) now compares the programs' SELinux labels with the policy's:
  it looked for `matchpathcon` and `restorecon` only in the server's
  `PATH`, which has no `/usr/sbin`, and reported "install selinux-tools"
  although the package was installed. It now looks in `/usr/sbin` and
  `/sbin` too, likewise for `ausearch` (SELinux denials from the audit
  log instead of the journal) and `semanage`, and says why when the
  tools cannot be run. The SELinux package recommends `selinux-tools`.

## v0.15.0 — 2026-10-06

Token scopes can now narrow what a remote user's roles allow. An
optional `scopes` map in the role data gives each OAuth scope a ceiling
(roles, permissions, or unlimited); a request needs the user's roles
and the ceiling of one of the token's scopes. Outside it, the request is
denied, and over HTTPS answered with an `insufficient_scope` challenge
so that agents that support it ask the user for the wider scope.
Cockpit and `mcp-gateway-admin setup http --token` show the ceilings,
and the user guide shows how to set up scopes and roles in Keycloak.
Kit's approvals wait up to `approval_timeout` on every protocol version
(the cap of 0.14.1, and rounds that wait until decided).

Upgrading from 0.14.x needs no changes to `gateway.yaml`, server
definitions or role data: without a `scopes` map nothing is narrowed.
After the update, restart the gateway
(`systemctl restart mcp-gateway.service`); the package does not. Things
to know:

- **Ceilings apply to remote users only.** Local users (Unix socket)
  are never limited, and a token with none of the map's scopes is not
  limited unless the map has a `default`.
- **Streamed responses over HTTPS** (SSE) now send their headers with
  the first message, or after 2 s, instead of at once, so that a
  request outside the ceiling can still be answered with `403`.
- **New settings,** optional with defaults:
  - `agents.no_request_timeout` (`[kit]`);
  - `agents.max_version` (`{kit: "2025-11-25"}`), already in 0.14.1.
- **Policy input and decision:** `principal.scopes` (a remote
  principal's token scopes); a denial outside the ceiling carries
  `outside_scopes` and `required_scopes`. Custom policy can use them
  (chapter 12).

### Added

- `agents.no_request_timeout` names clients without a request timeout
  of their own (default `[kit]`): on MCP 2026-07-28 a round of an
  approval or a sign-in waits for them until it is decided, up to
  `approval_timeout`, instead of `approvals.retry_wait`. So Kit's
  approvals wait as long without the version cap as with it (roadmap
  step 26).

- Token scopes as a ceiling (D17): the optional `scopes` map in the role
  data limits what a token's scopes let remote principals do; the roles
  decide within it. A request outside it is denied (never asked) with
  `outside_scopes` and `required_scopes` in the decision, lists hide it,
  and the audit trail records the token's scopes. The policy input
  carries `principal.scopes`. Over HTTPS such a request is answered
  with `403` and an `insufficient_scope` challenge for the first of
  the scopes that would allow it, so that agents that support it step
  up; the denial's text names those scopes. Cockpit's Policy tab lists
  the ceilings next to the roles, and `mcp-gateway-admin setup http
  --token` shows a token's scopes and the ceiling they set (new flag
  `--policy-data`). The user guide shows Keycloak client scopes for the
  ceiling, and roles assigned in Keycloak through `http.groups_claim`.

## v0.14.1 — 2026-10-06

A fix for Kit's approvals. Upgrading from 0.14.0 needs no changes: the
cap for Kit is the default, also with a `gateway.yaml` kept from 0.14.0.
Restart the gateway after the update
(`systemctl restart mcp-gateway.service`).

### Fixed

- Kit's approvals wait up to `approval_timeout` again (a regression of
  0.14): mcp-go 1.1 gives up on a call after three answers in a row
  that ask for nothing, so on MCP 2026-07-28 an approval ended for Kit
  after about 75 s. The new setting `agents.max_version` caps the MCP
  version per client name (`clientInfo`); as shipped, Kit is capped at
  2025-11-25 and uses the handshake, with a session, as before 0.14.
  `{}` caps no client. The name chooses the protocol, never what is
  allowed.

## v0.14.0 — 2026-10-06

The gateway speaks MCP 2026-07-28 on both sides. Servers that dropped
the `initialize` handshake can be registered, started and reached with
`url`, and keep working with every agent. Agents of 2026-07-28 are
served without a session, beside the agents of earlier versions on the
same endpoints:
- approvals, sign-ins and what a server asks the user for become multi
  round-trip requests, so no call has to outlast an agent's timeout;
- list changes come on a subscription stream the agent opens;
- what a session held belongs to the user.

The Python SDK 2.3, mcp-go 1.1 (Kit) and the TypeScript SDK 2.3 are
tested on 2026-07-28 in CI; the TypeScript SDK 1.x (Claude Code) keeps
the handshake.

Upgrading from 0.13.x needs no changes to `gateway.yaml`, server
definitions or role data. After the update, restart the gateway
(`systemctl restart mcp-gateway.service`); the package does not. Things
to know:

- **Agents that use 2026-07-28 now:** the Python SDK 2.x and mcp-go 1.1,
  and with it Kit. They used to fall back to the handshake. Without a
  session:
  - "session" grants are not offered to them; offer a duration
    (`approval_scopes`) where they need one;
  - servers with `isolation: session` give them one instance per user;
  - list changes reach them only on a `subscriptions/listen` stream they
    open (Kit opens none, as it acted on no `list_changed` before);
  - log messages reach them only for requests that ask for them.
- **Kit approvals:** an approval out of band or on the approval page
  ends for Kit after about 75 s, since mcp-go gives up after three rounds
  without input. Raise `approvals.retry_wait` (25 s) if Kit users need
  longer, for example to 40 s for two minutes; keep it below 60 s.
- **New settings,** all optional with defaults:
  - `http.list_ttl` (1 min);
  - `approvals.retry_wait` (25 s);
  - `pseudonymize.vault_idle` (1 h);
  - `limits.requests_per_principal` (64);
  - `limits.streams_per_principal` (16).
- **Policy input:** for a 2026-07-28 request, `context.protocol_version`
  is `2026-07-28` and the principal has no `session_id`. Custom policy
  that keys on the session needs another key for those requests.
- **`client` permissions** match the request's method
  (`sampling/createMessage`, `elicitation/create`, `roots/list`), as the
  role data schema now says too. Permissions written with the action
  names the documentation showed before (`sampling.create`, …) matched
  nothing and need the method names.
- **Servers** that keep the handshake are initialized with MCP
  2025-11-25. A server that exits on the `server/discover` probe is
  started again and initialized.

### Added

- Agents of MCP 2026-07-28 are served, on the socket and over HTTPS,
  beside agents of earlier versions on the same endpoints. They need
  no `initialize` and no session: every request carries the protocol
  version and the client's capabilities, and the gateway checks the
  2026-07-28 headers against the body. `server/discover` tells what an
  endpoint offers, and lists and reads carry `ttlMs` (`http.list_ttl`,
  1 min; 0 for a while after a policy or definition change) and
  `cacheScope: private`. Errors follow the version.
  - Approvals, sign-ins and what a modern server asks the user for are
    multi round-trip requests. The call is answered at once with the
    form, the approval page or the sign-in link to show, and the
    agent's SDK calls again with the answer. Retries wait for a decision
    up to `approvals.retry_wait` (25 s, new), so no round trip outlasts
    the agents' timeouts. The gateway's `requestState` is sealed and
    bound to the user, the call and 30 minutes.
  - List changes and resource updates come on a `subscriptions/listen`
    stream the agent opens. Subscribed resources are decided by policy
    (`resources.subscribe`).
  - Log messages go only to requests that ask for them.
  - What a session held belongs to the user:
    - pseudonyms per user and endpoint, dropped after
      `pseudonymize.vault_idle` (1 h, new);
    - limits on requests in flight and subscription streams per user
      (`limits.requests_per_principal`, 64; `limits.streams_per_principal`,
      16);
    - no "session" grants;
    - one instance per user for servers marked `isolation: session`.
  - The Python SDK 2.3 and mcp-go 1.1 (Kit) use 2026-07-28 with the
    gateway from now on, as does the TypeScript SDK 2.3 when it is asked
    to negotiate. The client suite runs all three. mcp-go gives up on a
    call after three rounds without input (about 75 s); raise
    `approvals.retry_wait` for longer approvals by Kit users.
- Servers of MCP 2026-07-28, which have no `initialize` handshake, can
  be registered, started as programs or reached with `url`.
  The gateway probes a definition's first instance with
  `server/discover` and uses a modern server without the handshake, with
  the protocol version and its identity in every request, the log level
  per request and the server's subscription stream for list changes and
  subscribed resources; agents see no difference. Other servers are
  initialized as before, now with MCP 2025-11-25; one that exits on the
  probe is started again and initialized. `mcp-gateway-admin inspect`
  and the doctor probe the same way. To a modern server with `url` the
  connector posts each request without a session and with the headers
  of the 2026-07-28 transport (`MCP-Protocol-Version`, `Mcp-Method`,
  `Mcp-Name`, `Mcp-Param-…` for parameters a tool marks with
  `x-mcp-header`), leaves out tools whose marks are invalid, retries
  once after a header mismatch, relays the server's errors, and cancels
  a call by closing its stream. A server unavailable when probed is
  probed again at its next start instead of being taken for an earlier
  version.
- A modern server that asks the client for input (a form, sampling,
  roots) gets it: the gateway asks the agent over its session, each
  request decided by policy as a legacy server's request is, and calls
  the server again with the answers; the agent sees one call. A refused
  elicitation is declined, a refused sampling or roots request ends the
  call; at most 8 rounds per call. Modern servers are told the
  capabilities the agent declared and policy lets them use.
- Signing in to a server checks that the authorization response comes
  from the authorization server the user was sent to (`iss`, RFC 9207,
  as MCP 2026-07-28 asks) before its code is used, and the gateway
  registers itself with `application_type` (`web`, or `native` for a
  gateway URL on the local host); the client ID metadata document names
  it too.
- CI tests the gateway with servers of MCP 2026-07-28 built with the
  official Go, Python and TypeScript SDKs, over stdio and HTTP: calls,
  a form the server asks for with a multi round-trip result, and a
  parameter mirrored into a header (`test/servers`).

### Fixed

- The user guide (chapters 6 and 13) and the role data schema named
  `client` permission patterns by the policy action
  (`sampling.create`, `elicitation.create`, `roots.list`); they match
  the request's method (`sampling/createMessage`, `elicitation/create`,
  `roots/list`), so a permission written as documented matched nothing
  and the server's request was refused. Permissions written that way
  need the method names.

## v0.13.0 — 2026-10-05

Signing in to servers lasts and works with every client, and remote
access is set up in one command. An instance of a server with `sign_in`
now outlives its access token: the gateway hands the running connector a
renewed one when the server refuses it, so calls go on in the same
session instead of the instance ending every hour. Clients without URL
elicitation get a short sign-in link the agent can show, so remote users
without a local account can sign in too. `mcp-gateway-admin setup http`
writes the `http` block from the public URL and the issuer and checks
the whole chain, the identity provider and a token included; the doctor
checks the listener's certificate and firewall. Connecting no longer
starts every server, and a release holds nothing but sources.

Upgrading from 0.12.x needs no changes to `gateway.yaml`, server
definitions or role data. After the update, restart the gateway
(`systemctl restart mcp-gateway.service`); the package does not. Things
to know:

- Instances of servers with `sign_in` no longer get `RuntimeMaxSec=`
  from the token's expiry; they end when idle, like any other instance.
- The SELinux policy lets the gateway fetch the identity provider's
  keys on port 8080 (`http_cache_port_t`). A `semanage port -m -t
  http_port_t -p tcp 8080` made as a workaround can be undone with
  `semanage port -d -p tcp 8080` if nothing else needs it.
- `mcp-gateway-admin doctor` has two new checks, `tls` and `firewall`,
  and warns about a polkit `readlog` rule only for systemd-mcp before
  0.3.5.
- From 0.13.0 on, releases are published as full releases; only tags
  such as `v1.0.0-rc1` are pre-releases.

### Added

- `mcp-gateway-admin doctor` checks the HTTP listener's certificate and
  key (`tls`: they load, the gateway's account and SELinux domain can
  read them, the certificate names the host of `http.audience` and has
  not expired) and whether firewalld lets its port in (`firewall`). A
  key the gateway cannot read keeps it from starting although
  `mcp-gateway --check` passes; a closed port makes remote clients see
  "connection refused" while the gateway works on the host.
- An instance of a server with `sign_in` outlives its access token: when
  the server refuses it (401), the connector gets a renewed one from the
  gateway and the call goes on, in the same session with the server.
  Before, the instance ended at the token's expiry (typically hourly)
  and the next call started a new one, with a new session.
- Signing in to a server with `sign_in` works with clients without URL
  elicitation: the call ends at once with a short link to the gateway
  (`<origin>/oauth/start/…`) for the agent to show, instead of waiting
  up to `sign_in.timeout` while the user looked for the link in Cockpit.
  Remote users without a local account can now sign in with such
  clients. The page after signing in names the server and the user.
- `mcp-gateway-admin setup http` sets up remote access and checks it
  end to end: from the public URL and the identity provider's issuer it
  fills in the `http` block of `gateway.yaml` (with `-write`; it keeps
  the other keys and the comments), then checks the identity provider's
  metadata and keys as the gateway fetches them, the certificate, the
  SELinux labels of the listener's and the identity provider's ports,
  firewalld and the listener as a client reaches it. With `-token`, it
  shows whom a token makes the principal and with which groups, or why
  the gateway refuses it (for Keycloak: the Audience and Group
  Membership mappers).

### Changed

- `mcp-gateway-admin doctor` warns about a polkit rule without
  `com.suse.gatekeeper.readlog` only when the systemd server reports a
  version of systemd-mcp before 0.3.5 (or the doctor did not start it),
  and notes that the rule's `readlog` is no longer needed with 0.3.5 or
  later.
- CI and `tools/check-release` refuse a tree that holds a binary file
  (a program) or a file of more than 1 MiB, naming each
  (`tools/check-tree`): 0.12.0 and 0.12.1 shipped two programs built in
  the top directory, which are gone.

### Fixed

- The gateway's SELinux domain may fetch the identity provider's keys
  from a port labeled `http_cache_port_t` (8080, Keycloak's default):
  with an issuer on such a port, the gateway refused every token.
- Listing resources (`resources/list`, which clients such as Kit send
  when they connect) starts the principal's instance only of servers
  with `discovery: shared` that offer resources, as their discovery
  instance tells; before, connecting started the principal's instance of
  every server.

## v0.12.4 — 2026-10-05

A fix for clients that list resources when they connect. Upgrading from
0.12.x needs no changes.

### Fixed

- Listing resources (`resources/list`, which clients such as Kit send
  when they connect) starts the principal's instance only of servers
  with `discovery: shared` that offer resources, as their discovery
  instance tells; before, connecting started the principal's instance of
  every server.
- The source tarball no longer holds two programs (`mcp-gateway`,
  `mcp-http-connector`) built in the top directory and committed by
  mistake in 0.12.0; the package never used them.

## v0.12.3 — 2026-10-05

Two checks for the HTTPS listener in `mcp-gateway-admin doctor`.
Upgrading from 0.12.x needs no changes.

### Added

- `mcp-gateway-admin doctor` checks the HTTP listener's certificate and
  key (`tls`: they load, the gateway's account and SELinux domain can
  read them, the certificate names the host of `http.audience` and has
  not expired) and whether firewalld lets its port in (`firewall`). A
  key the gateway cannot read keeps it from starting although
  `mcp-gateway --check` passes; a closed port makes remote clients see
  "connection refused" while the gateway works on the host. The user
  guide's `semanage port` lines fall back to `-m` where the policy
  already labels the port.

## v0.12.2 — 2026-10-04

A fix for servers with `sign_in`. Upgrading from 0.12.x needs no
changes; restart the gateway after the update (`systemctl restart
mcp-gateway.service`). At that start it deletes the tokens kept for
servers that no longer have `sign_in` or a definition (tokens kept by
0.12.0 and 0.12.1 do not record the server's `url`, so a `url` changed
before the update is not noticed).

### Fixed

- Sign-ins no longer outlive their server's definition: removing it, its
  `sign_in`, or changing its `url` deletes the principals' tokens and
  revokes them at the authorization server, also for changes made while
  the gateway was not running. Before, they stayed in the token store,
  and discovered metadata was used for up to an hour after a change.
- `DELETE /v1/sign-ins/{server}` answers how many sign-ins the
  authorization server revoked (`revoked`), and Cockpit says when the
  tokens were only deleted; `GET /v1/sign-ins` names each sign-in's
  `resource`.

## v0.12.1 — 2026-10-04

A fix for the systemd setup with systemd-mcp 0.3.4. Upgrading from
0.12.0 needs no changes; the updated `mcp-gateway-profile-systemd`
brings the new polkit rule, which polkit reads at once, and running
`systemd` instances work from their next call.

### Fixed

- systemd-mcp 0.3.4 checks every read (`list_loaded_units`, `list_log`,
  `get_file`, …) with polkit as `com.suse.gatekeeper.readlog`, which the
  setup's rule did not allow: all reads failed with "calling method was
  canceled by user". The rule of `mcp-gateway-profile-systemd` now
  allows that action for `mcp-sysmgmt`, and `mcp-gateway-admin doctor`
  warns when polkit knows the action but no rule for the server's
  account allows it (user guide, chapter 13).

## v0.12.0 — 2026-10-04

Each user signs in to MCP servers with their own account, servers are
reached through a proxy, and policy changes reach agents at once. A
server defined with `url` may have each user sign in to it (OAuth 2.1
with PKCE): the gateway keeps their tokens, encrypted, and hands each
instance its user's access token, while every request to the
authorization server is made by a confined helper that reaches only
that host; the agent never sees a token. Such servers may also be
reached through an HTTP proxy. Local policy is watched, so agents see a
role change when it is saved. Releases check themselves before anything
is published.

Upgrading from 0.11.x needs no changes to `gateway.yaml`, server
definitions or role data. After the update, restart the gateway
(`systemctl restart mcp-gateway.service`); the package does not. Things
to know:

- Saving role data or custom policy reaches agents within a second
  (they are told to list their tools again), not after
  `policy.watch_interval`; policy from a bundle server is still polled.
  Where a directory cannot be watched, the journal says "policy changes
  in a directory are noticed by polling only".
- `sign_in` needs the HTTP listener (`http.listen`, `http.audience`),
  reachable from the users' browsers: authorization servers send users
  back to `<origin of http.audience>/oauth/callback`. Without it, the
  gateway refuses such a definition.
- Policy that replaces the shipped logic (chapter 12) decides the tool
  `sign_in`, which the input marks `"resource": {"sign_in": true}`, and
  answers `data.mcp.approvals.manage_sign_in` for who may see and end
  sign-ins; without that rule only root may. The shipped policy covers
  `sign_in` wherever a permission names any tool of the server.
- New state: `/var/lib/mcp-gateway/tokens` (users' tokens and their key,
  made on the first sign-in; back it up with the rest, and keep the key
  with the tokens) and `/run/mcp-gateway/credentials` (tmpfiles). The
  SELinux module adds `mcpsrv_oauth_t`, `mcpgw_token_t` and
  `mcpgw_cred_run_t`, and lets servers defined with `url` connect to
  proxy ports (3128, 8080); each instance still reaches only its
  server's, or its proxy's, addresses.

### Added

- Releases check themselves: `tools/check-release vX.Y.Z` tells whether
  a release branch is ready to be tagged (the spec's `Version`, the first
  CHANGELOG.md section, `_service`); the Release workflow refuses a tag
  that fails it before building anything, and verifies the published
  files against `SHA256SUMS` and `git archive` of the tag.

- A server defined with an `https://` `url` may name an HTTP proxy
  (`proxy`, with `proxy_headers` for its credentials from
  `credentials`): the connector tunnels through it (`CONNECT`), TLS
  still ends at the server, and the instance may reach the proxy's
  addresses only. SELinux lets `mcpsrv_http_t` connect to the usual
  proxy ports (3128, 8080). No proxy is taken from the environment
  (user guide, chapter 4, Through a proxy).

- Each user signs in to a server with their own account there: with
  `sign_in` in a definition with `url`, a user who has not signed in
  sees one tool, `sign_in`; calling it (or any of the server's tools)
  sends them to the server's authorization server (OAuth 2.1 with PKCE)
  through a URL elicitation, or the Cockpit page, and back to the
  gateway's callback on its HTTP listener. The gateway keeps the
  tokens, encrypted, in `/var/lib/mcp-gateway/tokens`, renews them, and
  hands each instance its user's access token as a systemd credential;
  the agent never sees a token. Every request to the authorization
  server is made by the new `mcp-oauth-helper` in its own domain
  (`mcpsrv_oauth_t`), which reaches only that host. Users sign out, and
  administrators revoke sign-ins, in Cockpit or through the control API
  (`GET /v1/sign-ins`, `DELETE /v1/sign-ins/{server}`); sign-ins,
  refreshes and sign-outs are audited (user guide, chapter 4, Signing in
  for each user; architecture, decision D16).

### Changed

- Policy changes reach agents at once: the gateway watches the local
  policy trees (role data, shipped and custom rules) with inotify and
  checks OPA right after a change, instead of within
  `policy.watch_interval`. Policy from a bundle server is still checked
  every `policy.watch_interval`.

## v0.11.0 — 2026-10-04

MCP servers that speak HTTP, and a gateway that reacts at once and says
what to do. A server definition may give `url` instead of `command`:
its calls go through the same policy, approvals and audit, each
principal's instance is a confined connector that reaches only the
server's addresses, and the gateway itself makes no outbound
connection. Changes to the configuration take effect when the files are
written. The doctor warns only about what an administrator can change,
names the change, has a stable output for monitoring, and shows its
summary in Cockpit. Approval mail finds primary-group members of
approver groups also where the user database does not enumerate users.
It also carries the fix of 0.10.1 (servers read their credentials).

Upgrading from 0.10.x needs no changes to `gateway.yaml`, server
definitions or role data. After the update, restart the gateway
(`systemctl restart mcp-gateway.service`); the package does not. Things
to know:

- Saving `gateway.yaml` or a server definition takes effect within a
  fraction of a second, not after `policy.watch_interval`. Check a file
  with `mcp-gateway --check` before putting it in place, or write it
  under another name and rename it; a file that does not load still
  changes nothing and is reported. Where a directory cannot be watched,
  the journal says "changes in a directory are noticed by polling only"
  and the old interval applies.
- `mcp-gateway-admin doctor` reports some former warnings as `OK` with
  a note: polkit for servers that do not act through polkit, a
  privileged server on a transactional system; missing role data
  (policy from a bundle) is skipped. Monitoring that counts `WARN`
  lines sees fewer. The exit status is unchanged; `--strict` adds 3 for
  warnings, and `--json` results get `id` and `subject` (user guide,
  chapter 11), which are the fields to match on from now on.
- The state directory has a new file, `principals.json` (the local users
  who used the gateway, for approval mail); back it up with the rest.
- A server defined with `url` needs `https://` (`http://` only to the
  local host), reaches its server on HTTP ports unless
  `setsebool -P mcpsrv_http_connect_any on`, and does not use a proxy.
  Secrets for its headers come from `credentials` (user guide, chapter
  4, "Servers that speak HTTP").


### Added

- MCP servers that speak Streamable HTTP: a definition gives `url`
  (`https://…`, `http://` only to the local host) instead of `command`,
  and `headers`, whose `${CREDENTIAL:name}` come from `credentials`. The
  calls go through the same policy, approvals, audit and limits. Each
  principal's instance is `mcp-http-connector` (in the main package),
  run by systemd as a dynamic user in the new SELinux domain
  `mcpsrv_http_t`, which may reach the server's addresses only
  (resolved by the gateway, `IPAddressAllow=`) on HTTP ports (any port
  with the boolean `mcpsrv_http_connect_any`). The gateway makes no
  outbound connection, and secrets reach only the connector (user
  guide, chapter 4, "Servers that speak HTTP").
- `mcp-gateway-admin doctor --strict` exits 3 when a check warned and
  none failed (the exit status stays 1 for a failure and 0 otherwise).
  With `--json`, each result has an `id` and a `subject` that stay the
  same across releases, for monitoring (user guide, chapter 11).
- Cockpit's Servers tab shows the self-check's counts and lists its
  warnings and failures with what to do (`mcp-gateway-admin doctor
  --no-start`, as root with administrative access), when the page opens
  and with **Run self-check**.

### Changed

- Approval mail to an approver group also reaches the users whose
  primary group it is where NSS does not enumerate users (SSSD, LDAP
  without `enumerate = true`): the gateway remembers the local users
  who connect or use Cockpit's pages (`principals.json` in `state_dir`)
  and looks them up by name. With mail on, the doctor warns about an
  approver group in which it finds nobody, or that does not exist.
- Changes to `gateway.yaml`, the server definitions, the TLS certificate
  and key and the SMTP password file take effect when the file is
  written (inotify), not within `policy.watch_interval`; a file replaced
  by rename (editors, certbot's symbolic links) counts, and several
  writes in a row are reloaded once. Directories that cannot be watched
  are logged ("changes in a directory are noticed by polling only") and
  checked every `policy.watch_interval` as before.
- The doctor warns only about what an administrator can change, and
  the warning names the change. A server running as an account no
  polkit rule names warns only if it acts through polkit (the systemd
  and firewalld setups); for other servers it is a note (`OK`). So is a
  privileged server on a transactional system ("read-only /usr"). Role
  data that does not exist (policy from a bundle) is skipped, not a
  warning. The warnings about servers without tools, users without a
  role and missing snapper configs say what to do.

## v0.10.4 — 2026-10-05

A fix for clients that list resources when they connect. Upgrading from
0.10.x needs no changes.

### Fixed

- Listing resources (`resources/list`, which clients such as Kit send
  when they connect) starts the principal's instance only of servers
  with `discovery: shared` that offer resources, as their discovery
  instance tells; before, connecting started the principal's instance of
  every server.

## v0.10.3 — 2026-10-05

Two checks for the HTTPS listener in `mcp-gateway-admin doctor`.
Upgrading from 0.10.x needs no changes.

### Added

- `mcp-gateway-admin doctor` checks the HTTP listener's certificate and
  key (`TLS`: they load, the gateway's account and SELinux domain can
  read them, the certificate names the host of `http.audience` and has
  not expired) and whether firewalld lets its port in (`firewall`). A
  key the gateway cannot read keeps it from starting although
  `mcp-gateway --check` passes; a closed port makes remote clients see
  "connection refused" while the gateway works on the host. The user
  guide's `semanage port` lines fall back to `-m` where the policy
  already labels the port.

## v0.10.2 — 2026-10-04

A fix for the systemd setup with systemd-mcp 0.3.4. Upgrading from
0.10.x needs no changes; the updated `mcp-gateway-profile-systemd`
brings the new polkit rule, which polkit reads at once, and running
`systemd` instances work from their next call. The package's version is
right again (0.10.1's spec said 0.10.0).

### Fixed

- systemd-mcp 0.3.4 checks every read (`list_loaded_units`, `list_log`,
  `get_file`, …) with polkit as `com.suse.gatekeeper.readlog`, which the
  setup's rule did not allow: all reads failed with "calling method was
  canceled by user". The rule of `mcp-gateway-profile-systemd` now
  allows that action for `mcp-sysmgmt`, and `mcp-gateway-admin doctor`
  warns when polkit knows the action but no rule for the server's
  account allows it (user guide, chapter 13).
- The spec file names the release's version (0.10.1 said 0.10.0).

## v0.10.1 — 2026-10-04

A fix for MCP servers given secrets. Upgrading from 0.10.0 needs no
changes; restart the gateway after the update (`systemctl restart
mcp-gateway.service`) so that new instances get the changed sandbox.

### Fixed

- MCP servers can read their secrets (`credentials:`) under SELinux: the
  files in `$CREDENTIALS_DIRECTORY` are labeled `init_var_run_t`, which
  no server domain could read, so a confined server given credentials
  failed to read them. Server domains may now read them; instances no
  longer see the transient unit files of other instances
  (`InaccessiblePaths=/run/systemd/transient`).

## v0.10.0 — 2026-10-04

The gateway's own configuration changes while it runs. `gateway.yaml`
is reloaded like the server definitions, when it changes and on
`systemctl reload`: approvals, mail notifications, limits and timeouts
apply without ending sessions, and a renewed TLS certificate or SMTP
password file is picked up without a restart. What a reload leaves
behind is visible: instances of a previous or removed definition, a
file that did not load, keys that wait for the next start, in
`GET /v1/status`, `GET /v1/servers`, the doctor and Cockpit, whose
Servers tab can now reload the configuration. Over HTTP, what belongs
to a request goes on that request's stream, and containers that take
an instance's MCS pair are noticed within 2 s.

Upgrading from 0.9.x needs no changes to `gateway.yaml`, server
definitions or role data. After the update, restart the gateway
(`systemctl restart mcp-gateway.service`); the package does not. Things
to know:

- Changes to `/etc/mcp-gateway/gateway.yaml` now take effect within
  `policy.watch_interval` (10 s) of saving the file, not at the next
  restart, for the keys that can change while the gateway runs
  (user guide, chapter 3). Check the file with `mcp-gateway --check`
  before putting it in place. A file that does not load changes
  nothing and is reported (log, audit record `mcp-config-reload` with
  `file=gateway.yaml`, `config_error` in `GET /v1/status`, the doctor).
- Other keys (sockets, listeners and the identity provider, the
  supervisor's mode and MCS range, …) still need
  `systemctl restart mcp-gateway.service`. Until then the gateway logs
  them, `GET /v1/status` lists them in `restart_needed` and
  `mcp-gateway-admin doctor` warns.
- Replacing the files at `http.cert_file` and `http.key_file` is picked
  up the same way; connections opened before keep the old certificate.
  Hooks that restart the gateway after a certificate renewal can run
  `systemctl reload mcp-gateway.service` instead, which keeps sessions.
- HTTP clients now get a request's progress, approval dialog, and the
  server's log messages, elicitations and sampling requests on that
  request's stream, as the MCP specification describes; before, they
  could arrive on the stream of another request. A client that relied
  on the old behavior should read every stream it opens.

### Added

- The gateway reloads `gateway.yaml` while it runs, like the server
  definitions: when the file changes and on `systemctl reload
  mcp-gateway.service`. Approvals (`approval_timeout`,
  `approvals.url_template`, `progress_interval`), mail notifications,
  limits, `supervisor.idle_timeout` and the policy timeouts apply at
  once, without ending sessions; the TLS certificate and key and the
  SMTP password file are read again, also when only those files change,
  so that a renewed certificate needs no restart. Keys that take effect
  at the next start only (sockets, listeners, the identity provider,
  the supervisor's mode and MCS range, …) are logged, listed in
  `GET /v1/status` (`restart_needed`) and reported by the doctor. A file
  that does not load, a certificate or password file that cannot be
  read, changes nothing: it is logged, audited (`mcp-config-reload`,
  `file=gateway.yaml`) and reported (`config_error`).
- Instances that run from a server's previous definition, or of a server
  removed from the configuration, are marked in `GET /v1/servers`
  (`definition`: `previous`, `removed`; a removed server is listed with
  `removed: true` while instances of it run) and in Cockpit's Servers
  tab. The tab also shows a failed reload (`config_error`,
  `servers_error`) and the keys that need a restart, and its **Reload
  configuration** button runs `systemctl reload mcp-gateway.service`.

### Changed

- HTTP: what the gateway sends that belongs to a request goes on that
  request's stream while it is open: progress, the approval dialog, and
  a server's log messages, elicitations and sampling requests made while
  the session has that one call in flight on it. Before, such messages
  went to the most recently opened request stream, which could belong to
  another request. What belongs to no request (list changes, resource
  updates) goes on the GET stream if the client opened one.
- With `supervisor.mcs_avoid: auto`, running containers and virtual
  machines are checked for instances' MCS pairs every 2 s instead of
  every 30 s, so a container that takes an instance's pair shares it for
  at most about 2 s before the instance is replaced.

### Fixed

- `mcp-gateway-admin doctor` no longer warns `polkit dynamic` about
  servers with `run_as: dynamic`, such as `gateway-docs`: a dynamic
  user gets a new name for each instance, so no polkit rule could name
  it, and servers that act through polkit run as a fixed account.

## v0.9.0 — 2026-10-03

Server definitions that change while the gateway runs. The gateway
reloads `servers.d` when a file changes and on `systemctl reload`, so
that setup packages installed or updated with the gateway running take
effect without a restart and without ending sessions; a definition that
does not load never stops the gateway. The doctor checks the labels of
every program the SELinux modules give a type, approval mail reaches the
members of an approver group by primary group, agents asked about the
gateway's configuration are pointed to `gateway-admin`, and the
documentation starts with an index for people and agents.

Upgrading from 0.8.x needs no changes to `gateway.yaml`, server
definitions or role data. After the update, restart the gateway
(`systemctl restart mcp-gateway.service`); the package does not. Things
to know:

- **Restart before the first `systemctl reload`.** The unit now has
  `ExecReload`, but a gateway still running 0.8 does not handle SIGHUP:
  `systemctl reload mcp-gateway.service` ends it, and systemd does not
  start it again (SIGHUP counts as a clean exit). Restart it once after
  the update; from then on, reload as often as needed.
- Changes to `/etc/mcp-gateway/servers.d` now take effect within
  `policy.watch_interval` (10 s) of saving the file, not at the next
  restart. Check a definition with `mcp-gateway --check` before putting
  it in place, or write it under another name (not ending in `.yaml`)
  and rename it. A definition that does not load is reported (log,
  audit record `mcp-config-reload`, `servers_error` in
  `GET /v1/status`, the doctor) and changes nothing.
- When a server's definition changes, each session moves to an instance
  of the new definition at its next call; the old instance runs until
  no session uses it and no call on it is running. Instances of a
  removed server stop once their calls are answered.
- `mcp-gateway-admin doctor` may report `FAIL program …` for helper
  programs it did not check before, such as
  `/usr/libexec/mcp-server-zypp/zypp-mcp-tool` labeled `bin_t`. The
  line names the fix (`restorecon`, on transactional systems through
  `transactional-update run` and a reboot).
- Approval mail for `group:` approvers also goes to users whose primary
  group it is. With SSSD or LDAP they are found only if the directory
  enumerates users (`enumerate = true`); otherwise name them as `user:`.

### Added

- The gateway reloads the server definitions while it runs: when a file
  in `servers.d` (either one) changes, and on `systemctl reload
  mcp-gateway.service`. Setup packages installed or updated with the
  gateway running take effect without a restart, and sessions stay open.
  A session's next call to a changed server starts an instance from the
  new definition; the old instance runs until no session uses it and no
  call on it is running. Instances of removed servers stop once their
  calls are answered. Clients are told that the lists changed. A
  definition that does not load changes nothing: the gateway serves the
  previous definitions, logs and audits the error
  (`mcp-config-reload`), and the doctor warns until a reload succeeds
  (`servers_error` in `GET /v1/status`). `systemctl reload` checks the
  definitions first and fails on a broken one.

### Changed

- The documentation starts with an index (`docs/README.md`, installed
  for the `gateway-docs` server): which chapter answers which question,
  and where each common error message is explained, so that agents,
  which can search file names but not text, read the right file first.
  Chapter 10 explains errors that come from the servers behind the
  gateway ("outside the allowed directories", "calling method was
  canceled by user"); the reference tables list the programs, files and
  SELinux types of all packages, and the shipped roles are complete.
- `mcp-gateway-admin doctor` checks the labels of every program the
  gateway's and the setups' SELinux modules give a type, where installed,
  not only the servers' commands: a helper a server starts, such as
  zypp's `zypp-mcp-tool` (`rpm_exec_t`), labeled `bin_t` runs in the
  wrong domain too.

### Fixed

- Agents asked about the gateway's configuration are pointed to the
  `gateway-admin` server (`show_config`, `check_config`, `doctor`) by
  its instructions, those of `gateway-docs` and those of the aggregated
  endpoint, instead of trying to read the files through the file or
  systemd server, which cannot read them.
- Approval mail reaches the users whose primary group an approver group
  is; NSS does not list them as members of the group. They are found by
  enumerating users (`getent passwd`), which SSSD and LDAP do only with
  `enumerate = true`.

## v0.8.0 — 2026-10-03

The cleanup 0.7 announced, and HTTP streams that end with their token.
What 0.7 deprecated is gone: the old administrator commands of
`mcp-gateway`, and the entry of a server domain on the gateway's program.
A streamed response or GET stream now ends when the token of the request
that opened it expires, as requests with it are refused; clients resume
with a fresh token. 0.8.0 also has the fixes of 0.7.1.

Upgrading from 0.7.x needs no changes to `gateway.yaml` or role data.
After the update, restart the gateway (`systemctl restart
mcp-gateway.service`); the package does not. Things to know:

- Update `mcp-gateway-selinux` in the same transaction as the gateway;
  on transactional systems, reboot before restarting the gateway (user
  guide, chapter 2, "Transactional systems").
- `mcp-gateway inspect`, `profile`, `review`, `doctor` and
  `admin-server` exit with status 2 and name the `mcp-gateway-admin`
  command to run (`admin-server` is `serve`); change scripts that still
  call them. A copy of `gateway-admin.yaml` in
  `/etc/mcp-gateway/servers.d` that starts `mcp-gateway admin-server`
  no longer starts the server: `mcp-gateway --check` warns about it;
  start `mcp-gateway-admin serve`, or remove the copy.
- HTTP clients holding a stream for longer than their token is valid see
  it end at the token's expiry (plus one minute of leeway), with a last
  comment `: token expired`. Clients that refresh their token and resume
  with `Last-Event-ID` lose nothing; the SDKs tested in CI do (user
  guide, chapter 5).
- `mcp-gateway-admin doctor` prints `OK`, `WARN`, `FAIL` and `SKIP` in
  capitals; scripts that read its text output should use `--json`,
  whose status values are unchanged.

### Changed

- `mcp-gateway-admin doctor` prints the statuses in capitals, colored on
  a terminal: `OK` and `SKIP` green, `WARN` orange, `FAIL` red
  (`NO_COLOR` turns the colors off). `--json` is unchanged.
- An HTTP stream (the session's `GET` stream, or a request's
  `text/event-stream` response) ends when the token of the request that
  opened it is no longer accepted, as requests with it are refused; until
  now it went on. The stream stays resumable: the client reconnects with
  a fresh token and `Last-Event-ID` and gets what it missed. Expiries are
  audited (`mcp-token-expired`) and counted
  (`mcp_gateway_token_expiries_total`).

### Removed

- What 0.7 deprecated (D10): `mcp-gateway inspect`, `profile`,
  `review`, `doctor` and `admin-server` are unknown commands (status 2)
  that name the `mcp-gateway-admin` command to run instead. A server
  definition starting `mcp-gateway admin-server` cannot start; the
  gateway says so at start, `mcp-gateway --check` and the doctor warn,
  naming `mcp-gateway-admin serve`. `mcpsrv_admin_t` is no longer
  entered on the gateway's program: no server domain is.

### Fixed

- The user guide (chapter 11) named `mcp-gateway-admin inspect` where it
  meant the old `mcp-gateway inspect`.

## v0.7.1 — 2026-10-03

Fixes from running 0.7.0 on transactional systems: the doctor counts
SELinux denials only since the current boot and explains roles naming
tools a server does not offer, suseconnect-mcp may keep its cache in
`/run`, and a metric that was never served is. Upgrading from 0.7.0
needs no configuration changes. Update `mcp-gateway-selinux` together
with the gateway (the suseconnect module changed), and restart the
gateway after the update (`systemctl restart mcp-gateway.service`); on
transactional systems, reboot first.

### Changed

- `mcp-gateway-admin doctor` (and the `gateway-admin` tools `doctor` and
  `selinux_denials`) count SELinux denials only since the current boot,
  within `--since`. Denials from before a reboot came from the policy and
  labels of then; on transactional systems, where a module installed
  with its packages takes effect at the next boot, they reported problems
  already gone. `--previous-boots` counts them too.

### Fixed

- `mcp-gateway-admin doctor` names the server's version and account
  when roles name tools a server does not offer, and the usual causes: a
  server not running as root hides the tools only root can use (zypp's
  `confirm_install` and `confirm_remove`, for the role `zypp-installer`),
  and another server version names its tools differently. The zypp setup
  recommends `mcp-server-zypp` 0.1.1 or later: its roles name the tools
  of those versions, and 0.1.0 had `install_package` and `remove_package`
  instead of `plan_*` and `confirm_*`.
- The SELinux module of the suseconnect setup (`mcp_suseconnect`) did
  not let suseconnect-mcp create `/run/suseconnect`, where connect-ng
  caches the ids of the system profiles it uploads: the directory has a
  type of its own now (`mcpsrv_suseconnect_runtime_t`). If SUSEConnect
  created it first, `restorecon -R /run/suseconnect` relabels it.
- The metric `mcp_gateway_limit_refusals_total` (0.4) was counted but
  never served on `/v1/metrics` or `metrics.listen`.

## v0.7.0 — 2026-10-03

A smaller gateway. The commands for administrators leave the gateway's
binary: `mcp-gateway-admin` has `doctor` and the server `gateway-admin`
(`serve`), and runs `inspect`, `profile` and `review` from the new
package `mcp-gateway-tools`, which brings what they need. The gateway
keeps running the gateway and its checks, and no server domain needs an
entry point on its binary any longer (from 0.8 on, when the old commands
go).

Upgrading from 0.6.x needs no configuration changes unless a definition
still names `mcp-fs-demo`. After the update, restart the gateway
(`systemctl restart mcp-gateway.service`); the package does not. Things
to know:

- Update `mcp-gateway-selinux` in the same transaction as the gateway:
  `mcp-gateway-admin` has the new program type `mcpsrv_admin_exec_t`.
  On transactional systems, reboot before using it; then
  `mcp-gateway-admin doctor` checks the labels (user guide, chapter 2,
  "Transactional systems").
- `inspect`, `profile` and `review` need `zypper install
  mcp-gateway-tools`; without it, they say so.
- `mcp-gateway inspect`, `profile`, `review`, `doctor` and
  `admin-server` still work, after a warning, until 0.8: change scripts
  to `mcp-gateway-admin COMMAND` (`admin-server` is `serve`).
- The program name `mcp-fs-demo` is gone: a definition naming it no
  longer starts. `mcp-gateway --check` warned about such definitions in
  0.6; name `mcp-server-fs` instead.

### Added

- `mcp-gateway-admin`, the program for administrators: `doctor`,
  `serve` (the server `gateway-admin`), and `inspect`, `profile` and
  `review`, which are in the new package `mcp-gateway-tools` with what
  they need (the SELinux policy development files). The gateway's binary
  and package keep only what runs the gateway.

### Changed

- The server `gateway-admin` runs `mcp-gateway-admin serve`, which has
  its own program type (`mcpsrv_admin_exec_t`); update
  `mcp-gateway-selinux` together with the gateway.

### Deprecated

- `mcp-gateway inspect`, `profile`, `review`, `doctor` and
  `admin-server` run `mcp-gateway-admin` (`admin-server` as `serve`)
  after a warning, and go away in 0.8. A server definition starting
  `mcp-gateway admin-server` (a copy of `gateway-admin.yaml` in
  `/etc/mcp-gateway/servers.d`) gets a warning from `mcp-gateway --check`,
  at start and from the doctor; start `mcp-gateway-admin serve` instead.

### Removed

- The program name `mcp-fs-demo`, a link to `mcp-server-fs` since 0.5
  and deprecated in 0.6. A definition still naming it no longer starts:
  name `mcp-server-fs` instead. The definition the package installs
  (`servers.d/fs-demo.yaml`, which keeps its name) already does.

## v0.6.1 — 2026-10-03

A documentation fix for transactional systems. Upgrading from 0.6.0
needs no changes. If you installed `mcp-gateway-exec-server` after
updating to 0.6 but before rebooting, its program may carry the wrong
SELinux label (`bin_t`): `mcp-gateway doctor` says so, and
`transactional-update run restorecon -v
/usr/libexec/mcp-servers/mcp-server-exec` and a reboot fix it.

### Documentation

- On transactional systems, an SELinux module installed or updated in a
  transaction takes effect at the next boot. A server program installed
  before that reboot keeps the label it would have without its module,
  also after the reboot. The user guide (chapter 2, "Transactional
  systems") now says to install a program in the same transaction as
  its module, or to reboot in between, and to run `mcp-gateway doctor`
  after the reboot. The installed copy of the guide is what the
  `gateway-docs` server serves to agents.

## v0.6.0 — 2026-10-03

Agents get a few commands instead of a shell. The new server `exec`
(package `mcp-gateway-exec-server`) offers each command an administrator
allows as a tool: a fixed program whose arguments are checked against
patterns and passed without a shell, run with a timeout and an output
limit, as the calling user without network, in its own SELinux domain,
under the gateway's policy, approvals and audit.

Upgrading from 0.5.x needs no configuration changes. After the update,
restart the gateway (`systemctl restart mcp-gateway.service`); the
package does not. Things to know:

- Update `mcp-gateway-selinux` together with the gateway: it has the new
  domain `mcpsrv_exec_t`.
- `mcp-gateway-exec-server` is a new package and runs nothing until you
  put commands into `/etc/mcp-gateway/exec.d` (examples in
  `/usr/share/mcp-gateway/exec/examples.yaml`; check them with
  `mcp-server-exec --check`) and bind a role for the server `exec`
  (the shipped `exec-operator` runs every command with approval). Roles
  that name every server, like the shipped `admin`, reach it as any
  other.
- A definition that still names the program `mcp-fs-demo` gets a
  deprecation warning: name `mcp-server-fs` instead, before 0.7 removes
  the link.

### Added

- `mcp-gateway-exec-server`: the server `exec` runs commands an
  administrator allows in `/etc/mcp-gateway/exec.d`, each one a tool. A
  command is a fixed program and argument vector; the caller's arguments
  fill placeholders after matching their patterns (and may not start
  with `-` unless allowed). Commands run without a shell, with a timeout
  that kills what they started and an output limit, as the calling user
  without network in the domain `mcpsrv_exec_t`. The shipped role
  `exec-operator` runs them with approval; examples are in
  `/usr/share/mcp-gateway/exec/examples.yaml`; `mcp-server-exec --check`
  checks the files (user guide, chapter 4, "Commands an administrator
  allows").

### Deprecated

- The program name `mcp-fs-demo` (a link to `mcp-server-fs` since 0.5)
  goes away in 0.7. A definition naming it gets a warning from
  `mcp-gateway --check`, at start and from `mcp-gateway doctor`; name
  `mcp-server-fs` instead. The definition the package installs already
  does.

## v0.5.0 — 2026-10-03

Agents can now help with the gateway itself. The gateway's documentation
is an MCP server (`gateway-docs`), readable without the network, and its
diagnostics are another (`gateway-admin`): the doctor's checks, the
configuration with secrets masked, what the policy decides for a user
and why, audit records and SELinux denials, all read-only. The demo
server has become a full file server, `mcp-server-fs`, which also knows
transactional systems. `mcp-gateway doctor` finds server programs with
the wrong SELinux label and privileged servers on a read-only `/usr`.

Upgrading from 0.4.x needs no configuration changes. After the update,
restart the gateway (`systemctl restart mcp-gateway.service`); the
package does not. Things to know:

- Update `mcp-gateway-selinux` together with the gateway: it has the new
  domains `mcpsrv_docs_t` and `mcpsrv_admin_t`.
- `mcp-gateway-fs-server` replaces `mcp-gateway-demo-server`; zypper
  does this on update. The server is still `fs`, defined in the same
  file; definitions naming the program `mcp-fs-demo` keep working until
  0.6.
- Two servers are new: `gateway-admin` (main package) and `gateway-docs`
  (`mcp-gateway-fs-server`). Roles that name every server reach them like
  any other: the shipped `admin` all of `gateway-admin`, `viewer` the
  reading tools of `gateway-docs` (none of `gateway-admin`'s tool names
  match its patterns). Role data in `/etc` is not replaced on update, so
  for everyone else bind the shipped roles `gateway-admin` and
  `gateway-docs-reader` (user guide, chapter 10, "Asking an agent"). An
  empty file of the same name in `/etc/mcp-gateway/servers.d` disables
  either.
- Roles that allow `read_*` and `list_*` on `fs` now also allow the file
  server's new reading tools (`read_text_file`, `list_directory`, ...).
- `examples/poc` is now `examples/dev`, the setup for running the gateway
  from a checkout.

### Added

- The server `gateway-admin` (`mcp-gateway admin-server`, in the main
  package): the gateway's diagnostics for an agent. `doctor` and
  `check_config`, and with approval `explain_decision` (what the policy
  decides for a user and why), `show_config` (secrets masked),
  `recent_audit` and `selinux_denials`. It changes nothing; it runs as
  root without capabilities in the domain `mcpsrv_admin_t`, and like every
  server cannot reach the gateway's sockets or OPA. The shipped role
  `gateway-admin` grants it (user guide, chapter 10, "Asking an agent").
- `mcp-gateway doctor` checks that each server's program carries the
  SELinux label the policy gives its path ("program *name*"). A program
  installed before its module keeps, e.g., `bin_t`, and cannot start in
  its domain, so its tools are missing; the check names the fix
  (`restorecon`, on a transactional system `transactional-update run
  restorecon` and a reboot).
- On a transactional system (read-only `/usr`), `mcp-gateway doctor`
  warns about privileged servers, which cannot change `/usr`. The user
  guide has a section on such systems (chapter 2).
- The gateway's documentation as an MCP server, `gateway-docs` (package
  `mcp-gateway-fs-server`): the user guide, the architecture and the
  changelog of the installed version, installed to
  `/usr/share/mcp-gateway/docs` (also where documentation is excluded),
  served read-only by `mcp-server-fs` as a throwaway user in the new
  domain `mcpsrv_docs_t`, so that agents can help with the gateway's
  configuration without the network. The shipped role
  `gateway-docs-reader` grants it; the shipped `viewer` and `developer`
  roles include it (role data in `/etc` is not replaced on update:
  bind `gateway-docs-reader`, chapter 10). `mcp-server-fs` has
  `--instructions` to say what its files are.

### Changed

- The demo server is now a full file server: `mcp-server-fs`, package
  `mcp-gateway-fs-server`, which replaces `mcp-gateway-demo-server` on
  update. It is still the server `fs` on the user's home directory, in
  the domain `mcpsrv_fs_t`, defined in
  `/usr/share/mcp-gateway/servers.d/fs-demo.yaml` (the same file name, so
  that copies in `/etc/mcp-gateway/servers.d` still replace it); the
  program `mcp-fs-demo` stays as a link to it until 0.6. It has the tools
  of the reference filesystem server (`read_text_file`, `read_media_file`,
  `read_multiple_files`, `list_directory`, `list_directory_with_sizes`,
  `directory_tree`, `search_files`, `get_file_info`,
  `list_allowed_directories`, `write_file`, `edit_file`,
  `create_directory`, `move_file`) and `delete_file`, `read_file` and
  `list_dir` as before; several `--root` directories, `--read-only`, and
  limits on what one call reads, writes and lists. Files are replaced
  atomically, long searches end when the client cancels them, and every
  operation stays inside the directories also through symbolic links.
  On transactional systems, directories on the read-only root file
  system are shown as read-only and changes there are refused with the
  reason, and searches and trees do not enter btrfs `.snapshots`.
- The shipped role data's `developer` role allows `search_files`,
  `directory_tree` and `get_file_info`, and asks for approval for
  `edit_file`, `create_directory` and `move_file` within the home, as for
  `write_file`. Role data in `/etc` is not replaced on update: to give
  existing roles these tools, add
  `{"server": "fs", "tool": "search_files"}` and the like (chapter 4).
  Roles allowing `read_*` and `list_*` now also allow
  `read_text_file`, `read_media_file`, `read_multiple_files`,
  `list_directory`, `list_directory_with_sizes` and
  `list_allowed_directories`.

### Fixed

- Two files defining the same server, typically a hand-made definition
  in `/etc/mcp-gateway/servers.d` next to the one a setup package
  installs under another file name, failed with "duplicate backend name"
  and one file name. The message now names both files and says to
  rename yours to the package's file name (a file there replaces a
  package's only under the same file name) or remove it.

## v0.4.3 — 2026-10-02

A setup for mcp-server-snapper, and an SELinux fix for definitions
linked into `/etc/mcp-gateway/servers.d`. Upgrading from 0.4.x needs no
changes; restart the gateway when convenient. If you copied the
privileged zypp definition there instead of linking it, you can link it
again (chapter 13).

### Added

- `mcp-gateway-profile-snapper` sets up
  [mcp-server-snapper](https://github.com/aschnell/mcp-server-snapper)
  (0.3.0): the definition, the account `mcp-snapper`, the roles
  `snapper-reader` (configs, settings, snapshots) and `snapper-operator`
  (also creates snapshots; deletes them, changes configs and rolls back
  with approval), and the SELinux module `mcp_snapper` in
  `mcp-gateway-selinux`. snapperd answers the account for the configs
  whose `ALLOW_USERS` name it; a privileged definition, to link into
  `/etc/mcp-gateway/servers.d`, also changes configs and rolls back.
- `mcp-gateway doctor` checks that snapperd allows a snapper server's
  account some config, and no longer warns about polkit for it.

### Fixed

- With SELinux enforcing, a definition linked into
  `/etc/mcp-gateway/servers.d`, as chapter 13 says to enable the
  privileged zypp server, kept the gateway from starting ("permission
  denied"): its domain could not read symlinks there. Masking a server
  with a link to `/dev/null` failed the same way. The SELinux module
  allows both.

## v0.4.2 — 2026-10-02

A fix for a gateway that was run by hand as root. Upgrading from 0.4.x
needs no changes; restart the gateway when convenient. If the service
fails at start, `mcp-gateway doctor` or the gateway's log names files to
give back to `mcp-gateway` (`chown -R mcp-gateway: /var/lib/mcp-gateway`).

### Fixed

- `mcp-gateway.service` failed at start, restarting until systemd gave
  up, after the gateway had been run by hand as root: the state files it
  wrote (`pending.json`) were root's, and the service, running as
  `mcp-gateway`, could not read them. The gateway now refuses to run as
  root when the `mcp-gateway` account exists (`--allow-root` overrides;
  `--check` is not affected), and names state files another user owns,
  with the `chown` that fixes it, instead of failing with a bare
  permission error. `mcp-gateway doctor` checks the ownership of
  `/var/lib/mcp-gateway`.

## v0.4.1 — 2026-10-02

A fix of the command line's help. Upgrading from 0.4.0 needs no changes;
restart the gateway when convenient.

### Fixed

- `mcp-gateway -h` listed only the gateway's options, not the commands
  `inspect`, `profile`, `review` and `doctor`. It now lists them with a
  line each, and `mcp-gateway help [COMMAND]` shows the overview or a
  command's options. An unknown command (a typo) is an error; it used to
  start the gateway.

## v0.4.0 — 2026-10-02

The first release with stable interfaces: from 0.4 on, configuration,
role data, policy input and the control API change compatibly, and
what goes away is deprecated for a minor release first. MCP servers for
system management (systemd, firewalld, zypp, SUSEConnect) come as
setup packages with their roles, accounts, polkit rules and SELinux
modules. New tools help with servers that are not packaged:
`mcp-gateway inspect` drafts a definition and roles, `profile` drafts an
SELinux domain from a test run, `review` reads a server's source, and
`doctor` checks an installation. The gateway runs under a systemd
watchdog, exports metrics, and was fuzzed, its threat model reviewed and
its behaviour with common MCP clients tested.

Upgrading from 0.3.x needs no configuration changes; the gateway reads
0.3 configuration and role data as they are (CI checks this). After the
update, restart the gateway (`systemctl restart mcp-gateway.service`);
the package does not. Things to know:

- If you built the SELinux modules `mcp_systemd`, `mcp_firewalld`,
  `mcp_zypp` or `mcp_suseconnect` from the user guide, the modules of
  the same names in `mcp-gateway-selinux` replace them; compare them if
  you added rules. The setup packages (`mcp-gateway-profile-*`) can
  replace your hand-made definitions, roles and polkit rules.
- New limits apply by default: 64 sessions and 32 instances per
  principal (`limits`, chapter 3). Idle HTTP sessions and idle
  instances make room before anything is refused.
- Agents no longer see servers' task and experimental capabilities, and
  calls that ask for a task run synchronously.
- Calls waiting for approval report progress to agents that asked for
  it (`approvals.progress_interval`).


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
  the servers, server SELinux types the loaded policy does not know
  (servers whose module is missing cannot start), servers running as
  an account no polkit rule names, and members of `socket_group`
  without a role.

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

- Client compatibility tests (roadmap step 15): CI runs the official
  TypeScript and Python MCP SDKs and mcp-go (the library Kit uses)
  against the gateway, over `mcp-connect` and HTTPS, on discovery, calls,
  approvals out of band and in the client's dialog, `list_changed` and
  cancellation (`test/clients`). The user guide (chapter 5) lists how
  they behave.

- The user guide (chapter 5) describes Claude Code and Kit with the
  gateway: configuration for local and remote use, sessions, approvals,
  timeouts and how each learns of policy changes, plus what to check
  for other agents. Kit replaces an idle MCP session after 5 minutes and
  cannot answer elicitations (its approvals go out of band); Claude Code
  shows the gateway's "waiting for approval" progress and lists tools
  again on `list_changed`.

- Calls waiting for approval report progress to agents that asked for
  it (a `progressToken`): at once and every `approvals.progress_interval`
  (new, default 15 s). Agents with a request timeout, such as those built
  on the TypeScript SDK (60 s by default), no longer give up on a call
  before the approval arrives (`approval_timeout`, 120 s), provided they
  let progress extend the timeout. The server's own progress afterwards
  continues from the gateway's.

- Limits on sessions and instances (decision D14, roadmap step 15):
  `limits.sessions_per_principal` (64) and
  `limits.instances_per_principal` (32), and optionally
  `limits.instances` for all principals together. At a limit, the
  principal's longest-idle HTTP session, or an idle instance no session
  uses, makes room; otherwise the new session's `initialize` or the
  request needing an instance fails. Refusals are audited (`mcp-limit`)
  and counted (`mcp_gateway_limit_refusals_total`).

### Changed

- A server's capabilities reach agents only for what the gateway
  implements (tools, prompts, resources, completions, logging). Tasks
  (MCP 2025-11-25) and experimental capabilities are no longer passed
  on: the gateway routes neither, and task results would bypass policy
  and obligations. A call that asks for a task (Kit does when a server
  offers them) runs synchronously.

- A `server/discover` probe, sent by clients of MCP 2026-07-28 (the
  Python SDK 2, mcp-go 1.1 and so Kit) before they fall back to
  initialize, is answered "method not found" and no longer recorded in
  the audit log as a denied request.

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

## v0.3.5 — 2026-10-02

A fix for a gateway that was run by hand as root. Update the packages
and restart the gateway (`systemctl restart mcp-gateway.service`); the
configuration and the role data need no changes. If the service fails at
start, the gateway's log names files to give back to `mcp-gateway`
(`chown -R mcp-gateway: /var/lib/mcp-gateway`).

### Fixed

- `mcp-gateway.service` failed at start, restarting until systemd gave
  up, after the gateway had been run by hand as root: the state files it
  wrote (`pending.json`) were root's, and the service, running as
  `mcp-gateway`, could not read them. The gateway now refuses to run as
  root when the `mcp-gateway` account exists (`--allow-root` overrides;
  `--check` is not affected), and names state files another user owns,
  with the `chown` that fixes it, instead of failing with a bare
  permission error.

## v0.3.4 — 2026-10-02

Two SELinux fixes. Update the packages and restart the gateway
(`systemctl restart mcp-gateway.service`); the configuration and the
role data need no changes.

### Fixed

- A server definition naming a `selinux_type` that is not in the loaded
  policy (for example one of the user guide's examples installed without
  building its module) failed only when an instance started, with
  systemd's "Failed to change SELinux context ...: Operation not
  permitted", also in permissive mode. The gateway now warns at start of
  each such type and the servers naming it ("selinux_type is not in the
  loaded SELinux policy"). The SELinux module lets the gateway ask the
  kernel whether a context is valid.

- In permissive mode, the gateway's scan of the processes' MCS pairs
  (`supervisor.mcs_avoid`) logged a `process getattr` denial for every
  process on every scan. The SELinux module no longer audits them; in
  enforcing mode nothing changes.

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
