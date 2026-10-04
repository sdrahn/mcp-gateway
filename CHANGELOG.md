# Changelog

All notable changes to mcp-gateway. Versions follow
[Semantic Versioning](https://semver.org/). From 0.4 on, configuration,
role data and APIs change compatibly: what goes away is deprecated in one
minor release (with a warning) and removed in the next.

## Unreleased

### Changed

- Changes to `gateway.yaml`, the server definitions, the TLS certificate
  and key and the SMTP password file take effect when the file is
  written (inotify), not within `policy.watch_interval`; a file replaced
  by rename (editors, certbot's symbolic links) counts, and several
  writes in a row are reloaded once. Directories that cannot be watched
  are logged ("changes in a directory are noticed by polling only") and
  checked every `policy.watch_interval` as before.

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
