# 11. Reference

Lookup tables: the commands and their options, the control API, audit
record fields, files and directories, SELinux types, booleans and
interfaces, and limits and timings. The chapters before explain them.

## Commands

### mcp-gateway

```
mcp-gateway [--config FILE] [--check] [--debug] [--allow-root] [--version]
mcp-gateway --check-policy-data [--policy-data FILE]
mcp-gateway help
```

It runs the gateway (as `mcp-gateway.service` does); `mcp-gateway -h`
or `help` lists the options. The commands for administrators are
`mcp-gateway-admin`'s (below); `mcp-gateway inspect`, `profile`,
`review`, `doctor` and `admin-server` were removed in 0.8 and name the
`mcp-gateway-admin` command to run instead (`admin-server` is `serve`).
Any argument is an error (status 2).

| Flag | Meaning |
|---|---|
| `--config FILE` | configuration file (default: `/etc/mcp-gateway/gateway.yaml`, else `/usr/etc/mcp-gateway/gateway.yaml`, else built-in defaults) |
| `--check` | validate the configuration, all MCP server definitions and the role data (if the file exists), print a summary, exit (status 1 on errors) |
| `--check-policy-data` | validate only the role data against its schema, print each problem, exit (status 1 on problems) |
| `--policy-data FILE` | role data for the two checks (default: `/etc/mcp-gateway/policy/rbac/data.json`; `-`: standard input; empty: none) |
| `--shipped-policy DIR` | shipped policy with the roles of the server setups, which bindings may name; its setup role files are checked too (default: `/usr/share/mcp-gateway/policy`; empty: none) |
| `--debug` | log debug messages |
| `--allow-root` | run the gateway as root although the `mcp-gateway` account exists; without it the gateway refuses, since the state files it would create as root are unreadable for the service (`--check` runs as root without it) |
| `--version` | print the version |

### mcp-gateway-admin

```
mcp-gateway-admin doctor|setup|inspect|profile|review|serve [options]
mcp-gateway-admin help [COMMAND]
mcp-gateway-admin --version
```

The commands for administrators: `doctor`, `setup` and `serve` come with the
package `mcp-gateway`; `inspect`, `profile` and `review`, which help to
add MCP servers, with `mcp-gateway-tools` (`zypper install
mcp-gateway-tools`, which brings the SELinux policy development files
`profile` needs). `mcp-gateway-admin COMMAND -h` or `help COMMAND` shows
a command's options. An unknown command is an error (status 2).

### mcp-gateway-admin inspect

```
mcp-gateway-admin inspect [options] --server NAME
mcp-gateway-admin inspect [options] --name NAME -- COMMAND [ARG...]
```

Starts an MCP server, reports its tools, prompts and resource templates
with a classification of the tools, drafts roles, suggests tool notes
for arguments the schema leaves unclear (times without a format,
arguments without a description) and checks the definition's notes,
and checks role data against the server (chapter 4, "Inspecting a server"). Exit status 1 if
the server cannot be inspected or a role check finds errors, 2 on usage
errors.

| Flag | Meaning |
|---|---|
| `--server NAME` | a server of the registry, started as for shared discovery (through the configured supervisor; with systemd as root) |
| `--name NAME -- COMMAND…` | a server started by command, as a child process of the caller, without systemd and SELinux, under Landlock (refused as root) |
| `--config FILE` | gateway configuration, for the registry and the supervisor |
| `--exec` | start a `--server` definition as a child process, without systemd and SELinux, under Landlock (refused as root) |
| `--home` | with a command or `--exec`: the server reads and writes your home (otherwise it gets a directory of its own, removed afterwards) |
| `--network` | with a command or `--exec`: the server may use TCP (otherwise none) |
| `--allow DIR` | with a command or `--exec`: a tree the server may read and execute, such as its package; repeatable |
| `--roles FILE` | role data or a setup's roles to check against the server; repeatable |
| `--out DIR` | write the drafts there: `roles.json`, and `NAME.yaml` for a command, with the suggested tool notes as comments (existing files are kept) |
| `--read-by-name` | also put tools that read by their name alone into the reader role |
| `--json` | print the result (server answers, classification, draft roles, findings, `note_hints`, `unknown_notes`) as JSON |
| `--timeout D` | how long to wait for the server (default 60s) |

### mcp-gateway-admin profile

```
mcp-gateway-admin profile [options] --server NAME --out DIR
mcp-gateway-admin profile [options] --server NAME --verify
```

Runs a registered server with its SELinux domain permissive, calls its
tools and drafts a policy module and definition from the denials
(chapter 4, "Profiling a server"). Needs root, the systemd supervisor,
SELinux and selinux-policy-devel. Exit status 1 if the run fails (or,
with `--verify`, on a denial), 2 on usage errors.

| Flag | Meaning |
|---|---|
| `--server NAME` | the server of the registry to profile |
| `--out DIR` | directory for the drafts, the report, the calls and the denials (`denials.json`, for `review`) |
| `--calls FILE` | JSON object mapping tool names to arguments, or to a list of them |
| `--call-all` | call every tool, also those that change things (throwaway systems only) |
| `--keep-dontaudit` | leave the policy's dontaudit rules on while profiling (faster; misses the denials they hide) |
| `--verify` | run the calls with SELinux enforcing, load and draft nothing, fail on a denial |
| `--config FILE` | gateway configuration, for the registry and the supervisor |
| `--timeout D` | how long the run may take (default 5m) |

### mcp-gateway-admin review

```
mcp-gateway-admin review [options] --source DIR
```

Scans a server's source for programs it runs, D-Bus names and polkit
actions, paths, network access, root checks and environment variables,
with file, line and SELinux type (chapter 4, "Reviewing a server's
source"). Needs no root. Exit status 1 on errors, 2 on usage errors.

| Flag | Meaning |
|---|---|
| `--source DIR` | the server's source tree |
| `--main PKG` | Go: the server's main package relative to the module root; only the packages it imports are scanned |
| `--profile DIR` | drafts directory of a profiling run, whose `denials.json` marks what the run reached |
| `--json` | print the findings as JSON |

### mcp-gateway-admin doctor

```
mcp-gateway-admin doctor [options]
```

Checks the installation (chapter 10, "Self-check"). Run it as root;
without root, the checks that need it are skipped. Exit status 1 if a
check failed, 3 with `--strict` if one warned (and none failed), 2 on
usage errors, 0 otherwise.

| Flag | Meaning |
|---|---|
| `--config FILE` | gateway configuration (as for `mcp-gateway`) |
| `--policy-data FILE` | role data (default: `/etc/mcp-gateway/policy/rbac/data.json`) |
| `--shipped-policy DIR` | shipped policy with the roles of the server setups (default: `/usr/share/mcp-gateway/policy`; empty: none) |
| `--server NAME` | check only this server: whether it starts and what its roles name, the SELinux denials of its domain, its type and program label (with its helpers), polkit and snapper for it; the configuration and the role data only when they fail, and none of the gateway's own checks (services, state files, policy, TLS, firewall, principals) |
| `--no-start` | do not start the servers |
| `--since DURATION` | how far back to look for SELinux denials (default `24h`), within the current boot |
| `--previous-boots` | with `--since`, also count denials from before the current boot |
| `--timeout DURATION` | how long to wait for each server (default `30s`) |
| `--json` | print the results as JSON (below) |
| `--strict` | exit 3 if a check warned and none failed |

With `--json`, the output is an array of results: `check` (the label of
the text output), `id`, `subject` (absent for checks about nothing in
particular), `status` (`ok`, `warn`, `fail`, `skip`), `summary` and
`details` (lines; absent when there are none). `id` and `subject` stay
the same across releases; the texts may change.

| `id` | `subject` | Text label |
|---|---|---|
| `configuration` | | configuration |
| `role-data` | | role data |
| `unit` | `mcp-gateway.service`, `mcp-opa.service` | the unit |
| `state-files` | | state files |
| `tls` | | TLS |
| `firewall` | | firewall |
| `gateway-status` | | gateway status |
| `policy` | | policy |
| `servers` | | servers |
| `server` | server name | server *name* |
| `roles` | server name | roles *name* |
| `tool-notes` | server name | tool notes *name* |
| `selinux-denials` | SELinux type (absent when there are none) | SELinux *type*, SELinux |
| `selinux-transitions` | | SELinux transitions |
| `selinux-types` | | SELinux types |
| `selinux-type` | SELinux type | SELinux type *type* |
| `program` | program path or name | program *path* |
| `program-labels` | | program labels |
| `read-only-usr` | | read-only /usr |
| `snapper` | server name | snapper *name* |
| `polkit` | account | polkit *account* |
| `principals` | | principals |
| `approver-group` | group name | approver group *group* |

### mcp-gateway-admin setup http

```
mcp-gateway-admin setup http [options]
```

Sets up the HTTP listener for remote agents and checks it end to end
(chapter 5, "Remote agents"). From `--url` and `--issuer` it fills in the
`http` block of `gateway.yaml` (with `--write`; without, it shows what it
would change), keeping the keys it does not ask about and the rest of the
file, comments included; the new file must load before it replaces the
old one. Options left out keep what the block has, so `setup http
--token FILE` alone checks a running setup. Run it as root. Exit status 1
if a check failed, 2 on usage errors, 0 otherwise.

| Flag | Meaning |
|---|---|
| `--config FILE` | the configuration to set up (default: `/etc/mcp-gateway/gateway.yaml`; a missing one starts from the package default) |
| `--url URL` | the gateway's public MCP URL, as clients use it (`http.audience`); `http.listen` takes its port (443 if none) |
| `--issuer URL` | the identity provider's issuer (`http.issuer`) |
| `--cert FILE`, `--key FILE` | certificate (PEM, with the chain) and private key (`http.cert_file`, `http.key_file`) |
| `--groups-claim NAME` | token claim with the groups (`http.groups_claim`, default `groups`) |
| `--local-user-claim NAME` | token claim naming a local account (`http.local_user_claim`) |
| `--scopes LIST` | comma-separated scopes every token must carry (`http.scopes`; `""` for none) |
| `--token FILE` | an access token to check as the gateway takes it (`-`: standard input); it is never printed |
| `--policy-data FILE` | role data, for the ceiling of the token's scopes (default: `/etc/mcp-gateway/policy/rbac/data.json`; empty: none; unreadable: left out) |
| `--write` | write the `http` block |
| `--timeout DURATION` | how long to wait for the identity provider and the listener (default `10s`) |
| `--json` | print the results as JSON, as the doctor does |

The checks, with their `id`s:

| `id` | What |
|---|---|
| `http-block` | what `--write` wrote, or would write |
| `identity-provider` | `<issuer>/.well-known/openid-configuration` answers (with the system's CA certificates, as the gateway fetches it), names the issuer exactly as configured, and its key set has signing keys; notes PKCE (`S256`) and dynamic client registration |
| `tls` | the certificate and key, as `doctor` checks them |
| `selinux-port` | the listener's port is labeled `mcp_port_t`, and the identity provider's port `http_port_t` or `http_cache_port_t` (the gateway's SELinux domain reaches no other) |
| `firewall` | firewalld lets the port in, as `doctor` checks it |
| `token` | with `--token`: accepted, and as which principal with which groups and scopes, and the ceiling those scopes set in the role data (chapter 6, "Token scopes"); or refused, and why (issuer, audience, expiry, scope), from the token's claims |
| `listener` | `https://<host of --url>/.well-known/oauth-protected-resource/mcp` answers with this issuer and audience, with the certificate verified as clients verify it; with `--token`, an `initialize` is accepted |

### mcp-gateway-admin serve

```
mcp-gateway-admin serve [options]
```

The MCP server `gateway-admin` on stdin/stdout, which the gateway starts
(chapter 10, "Asking an agent"); not for running by hand.

| Flag | Meaning |
|---|---|
| `--config FILE` | gateway configuration (as for `mcp-gateway`) |
| `--policy-data FILE` | role data (default: `/etc/mcp-gateway/policy/rbac/data.json`) |
| `--shipped-policy DIR` | shipped policy (default: `/usr/share/mcp-gateway/policy`) |
| `--etc-policy DIR` | the administrator's policy directory, loaded below `data.mcp` (default: `/etc/mcp-gateway/policy`) |
| `--opa PATH` | the opa program for `explain_decision` (default: `/usr/bin/opa`) |

### mcp-connect

```
mcp-connect [--server NAME|all] [--socket PATH] [--version]
```

stdio ↔ unix socket bridge for local agents; `--server` defaults to
`all` (aggregated endpoint), `--socket` to `/run/mcp-gateway/mcp.sock`.
Chapter 5.

### mcp-gateway-notify

```
mcp-gateway-notify [--socket PATH] [--url TEMPLATE] [--debug] [--version]
```

Desktop notifications for pending approvals; `--socket` defaults to
`/run/mcp-gateway/control.sock`, `--url` to
`https://localhost:9090/mcp-gateway#/approvals/{id}`. Chapter 7.

### mcp-policy-bundle

```
mcp-policy-bundle [-k KEY] [-o OUTPUT] [-r REVISION] [-n] [-a ALG] [-V DIR] [-L DIR]
mcp-policy-bundle -G [-k KEY] [-o OUTPUT]
```

Builds and signs a policy bundle, or (`-G`) creates a signing key pair.
Chapter 6 lists the options. The environment variable `OPA` selects the
`opa` binary. Before building, the role data is checked with
`mcp-gateway --check-policy-data` if `mcp-gateway` (or the program in
`MCP_GATEWAY`) is found; with problems, no bundle is built.

## Control API

HTTP/1.1 with JSON on the unix socket `/run/mcp-gateway/control.sock`
(group `mcp-users`). The caller is identified by kernel peer
credentials; what it sees and may do is decided by the approver rules
(chapter 6). `root` may do everything.

```bash
curl -s --unix-socket /run/mcp-gateway/control.sock http://localhost/v1/whoami
```

| Method and path | Body / result |
|---|---|
| `GET /v1/whoami` | the caller: `{"name", "uid", "groups"}` |
| `GET /v1/status` | `{"version", "restart_pending", "servers_error", "config_error", "restart_needed"}`: the running gateway's version; `true` when its program was updated and the gateway not yet restarted; why the last reload of the server definitions, or of `gateway.yaml`, failed (absent when it did not); the keys of `gateway.yaml` changed since the start that take effect at the next start (absent when none) |
| `GET /v1/approvals` | pending approvals the caller may decide on (list of approvals, below) |
| `GET /v1/approvals/{id}` | one approval; `404` if unknown or not the caller's to decide |
| `POST /v1/approvals/{id}` | `{"decision": "approve"\|"deny", "scope": "once"\|"session"\|<duration>}`; returns the grant (`200`) or nothing (`204`, denied); `400 scope not offered` |
| `GET /v1/grants` | grants the caller may manage (list of grants, below) |
| `DELETE /v1/grants/{id}` | revoke; `204` |
| `GET /v1/servers` | registered servers `{"name", "selinux_type", "isolation", "network", "run_as", "privileged", "sign_in", "instances"}` with the instances the caller may manage `{"id", "server", "unit", "sub", "iss", "uid", "transport", "session_id", "isolation", "started", "sessions", "privileged", "busy", "definition"}`; `definition` is `current`, `previous` (started from a definition changed since) or `removed`; a server removed from the configuration whose instances still run is listed with `"removed": true` |
| `DELETE /v1/instances/{id}` | stop an instance; `204`; `409` for a privileged instance with a call running |
| `GET /v1/sign-ins` | `{"sign_ins": [{"server", "resource", "principal": {"sub", "iss", "uid", "transport"}, "since", "expiry", "scope", "refreshable"}], "pending": [{"server", "url", "expires"}]}`: the sign-ins to servers with `sign_in` the caller may see and end (`data.mcp.approvals.manage_sign_in`), never tokens; and the caller's own sign-ins waiting for them to open `url` (chapter 4, "Signing in for each user") |
| `DELETE /v1/sign-ins/{server}` | sign the caller out of the server, or with `?principal=<sub>` (and `transport`, `iss`) another principal the approver rules allow; deletes the tokens, revokes them at the authorization server if it offers that, stops the principal's instances; `200 {"signed_out": n, "revoked": m}` (`m` of them revoked at the authorization server, the others' tokens only deleted); `404` if there is none |
| `GET /v1/policy` | `{"mode": "directories"\|"bundle", "bundles": {name: revision}, "shipped_roles": {role: {"setup", "description", "permissions"}}}`; `502` if OPA is unavailable |
| `POST /v1/policy/whatif` | body: proposed role data (as `data.json`); returns `{"changes": [{"principal", "server", "kind", "name", "before", "after"}], "principals", "resources", "unchecked": {server: reason}}`: the decisions that would change, for the users (`user:<name>`) and groups (`group:<name>`) either role data binds; `403` unless `data.mcp.approvals.review_policy` allows the caller |
| `GET /v1/metrics` | metrics in the Prometheus text format (chapter 10); `403` unless the caller is root |
| `GET /v1/events` | server-sent events (`event: approval`) for the approvals the caller may decide on: first all pending, then changes; `data` is `{"type": "pending"\|"resolved", "id", "new", "pending", "url"}` |

Errors are `{"error": "…"}` with a matching status.

The API is versioned by its path. Within `/v1`, new releases only add
endpoints and fields; clients must ignore fields they do not know. A
field is never renamed or dropped within `/v1`: that would be `/v2`,
with `/v1` kept for one more minor release.

**Approval** fields: `id`, `channel`, `principal` (as policy sees it:
`sub`, `iss`, `uid`, `groups`, `home`, `transport`, `selinux`,
`client`, `session_id`, `cert`), `action`, `server`, `name`, `args`,
`prompt`, `scopes`, `created`, `expires`, `waiting`.

**Grant** fields: `id`, `sub`, `iss`, `uid`, `server`, `tool`, `scope`
(`once`, `session`, `duration`), `session_id`, `expires`, `approved_by`,
`channel`.

## Audit records

Decision records (journal of `mcp-gateway.service`, `"audit": true`):

| Field | Meaning |
|---|---|
| `session` | MCP session id |
| `sub` | principal |
| `action` | `tools.call`, `prompts.get`, `resources.read`, `resources.subscribe`, `resources.unsubscribe`, `completion.complete`, `sampling.create`, `elicitation.create`, `roots.list` |
| `server` | MCP server |
| `name` | tool, prompt, resource URI or method |
| `effect` | `allow` or `deny` |
| `reason` | why (for denials, and `approved`) |
| `grant` | the grant that allowed the call |
| `instance` | the instance involved |
| `decision_id` | correlates with OPA's decision log |
| `args_hmac` | HMAC-SHA256 of the arguments (key: `/var/lib/mcp-gateway/audit.key`) |
| `args` | the arguments, instead of `args_hmac`, with the obligation `audit: "full"` |
| `reidentified` | number of pseudonyms replaced by original values in the arguments (obligation `reidentify`); `args`/`args_hmac` then describe the arguments as forwarded |

Event records carry `event` (the operation below), `ok` and fields of
the event. The event `mcp-pseudonymize` is recorded in the journal only
(not in the kernel audit log): `session`, `sub`, `server`, `name`
(tool, prompt or `sampling/createMessage`), `decision_id` and `values`,
the classes and counts replaced (`"EMAIL:2 PERSON:1"`).

Kernel audit (`TRUSTED_APP`) operations:

| `op=` | When | Fields |
|---|---|---|
| `mcp-gateway-start` | the gateway started | |
| `mcp-decision` | a request was denied (`res=failed`), or any decision on a privileged server | `session`, `principal`, `action`, `server`, `target`, `reason`, `decision_id`; for privileged servers also `privileged=yes` and `grant` |
| `mcp-approval` | an approval was decided (`res=success` approved, `failed` denied) | `id`, `principal`, `server`, `target`, `by`, `scope`, `channel` |
| `mcp-grant-revoke` | a grant was revoked | `id`, `by`, `principal`, `server`, `target` |
| `mcp-policy-change` | OPA loaded a different policy | `revision` |
| `mcp-config-reload` | the server definitions, or `gateway.yaml` (`file=gateway.yaml`), were reloaded with changes (`res=success`), or could not be (`res=failed`; what was in force stays) | `trigger` (`file change`, `SIGHUP`), `file`, `added`, `changed`, `removed`, `restart_needed`, `error` |
| `mcp-mcs-collision` | an instance's MCS pair was taken by another workload | `instance`, `pair`, `foreign_pid`, `foreign_context` |
| `mcp-limit` | a session or instance was refused at a limit (`res=failed`) | `principal`, `transport`, `session`, `limit`, `max` |
| `mcp-token-expired` | an HTTP stream ended because the token that opened it expired | `principal`, `transport`, `session` |
| `mcp-sign-in` | a principal's sign-in to a server with `sign_in` started, completed (`res=success`) or failed (`res=failed`) | `server`, `principal`, `step` (`started`, `completed`, `failed`), `reason` |
| `mcp-sign-in-refresh` | a principal's token was refreshed (`res=success`), or could not be (`res=failed`; `tokens=deleted` when the authorization server refused it and the principal must sign in again) | `server`, `principal`, `reason`, `tokens` |
| `mcp-sign-out` | a principal was signed out of a server | `server`, `principal`, `by` (`mcp-gateway` when the server's definition was removed, lost `sign_in` or changed its `url`), `reason` (then), `revoked` (`yes`, `no`) |

## Files and directories

| Path | Contents |
|---|---|
| `/usr/bin/mcp-gateway`, `mcp-gateway-admin`, `mcp-connect`, `mcp-gateway-notify` | programs |
| `/usr/libexec/mcp-gateway/mcp-gateway-tools` | `inspect`, `profile` and `review` (package `mcp-gateway-tools`) |
| `/usr/sbin/mcp-policy-bundle` | bundle tool |
| `/usr/etc/mcp-gateway/gateway.yaml` | default configuration |
| `/etc/mcp-gateway/gateway.yaml` | your configuration |
| `/usr/share/mcp-gateway/servers.d/` | package server definitions |
| `/usr/share/mcp-gateway/profiles/` | definitions to link into `/etc/mcp-gateway/servers.d` by hand: `zypp-privileged.yaml`, `snapper-privileged.yaml` (chapter 13) |
| `/etc/mcp-gateway/servers.d/` | your server definitions |
| `/usr/share/mcp-gateway/policy/` | policy logic; `mcp/profiles/<setup>/data.json`: roles of setup packages |
| `/etc/mcp-gateway/policy/rbac/data.json` | role data |
| `/usr/share/mcp-gateway/schema/rbac.schema.json` | JSON Schema (draft-07) of the role data |
| `/etc/mcp-gateway/credentials/` | MCP server secrets (0700, `mcpgw_cred_t`) |
| `/etc/mcp-gateway/exec.d/` | commands of the server `exec`; examples in `/usr/share/mcp-gateway/exec/` |
| `/etc/mcp-gateway/bundle/` | `policy.tar.gz`, `verify.pem`, `signing.pem` |
| `/usr/share/mcp-gateway/opa/` | OPA drop-ins: `signed-bundle.conf`, `bundle-server.conf`, `decision-logs.conf`; examples `opa-config.yaml.example`, `decision-logs.yaml.example` |
| `/usr/share/mcp-gateway/mcs/` | libvirt drop-ins: `virtqemud.conf`, `libvirtd.conf` |
| `/var/lib/mcp-gateway/` | `grants.json`, `pending.json`, `audit.key`, `principals.json` |
| `/var/lib/mcp-gateway/tokens/` | principals' tokens for servers with `sign_in` (`tokens.json`, encrypted) and their key (`tokens.key`); 0700, `mcpgw_token_t` |
| `/run/mcp-gateway/mcp.sock` | MCP socket |
| `/run/mcp-gateway/control.sock` | control API |
| `/run/mcp-gateway/opa.sock` | OPA (gateway only) |
| `/run/mcp-gateway/credentials/` | an instance's access token (`sign_in`) until systemd has read it (0700, `mcpgw_cred_run_t`) |
| `/usr/libexec/mcp-gateway/mcp-http-connector`, `mcp-oauth-helper` | the instances of servers defined with `url`; the requests of sign-ins |
| `/usr/libexec/mcp-gateway/mcp-landlock` | starts the instances of definitions with `landlock`: restricts itself with Landlock, then executes the server; `-version` shows the kernel's Landlock ABI |
| `/usr/lib/systemd/system/mcp-gateway.service`, `mcp-opa.service` | units |
| `/usr/lib/sysusers.d/mcp-gateway.conf` | accounts |
| `/usr/share/polkit-1/rules.d/50-mcp-gateway.rules` | lets the gateway manage `mcp-*.service` |
| `/usr/share/cockpit/mcp-gateway/` | Cockpit page |
| `/etc/xdg/autostart/mcp-gateway-notify.desktop` | desktop agent autostart |
| `/usr/libexec/mcp-servers/` | conventional place for MCP server programs; `mcp-server-fs`, `mcp-server-exec` |
| `/usr/share/mcp-gateway/docs/` | this documentation (server `gateway-docs`) |

## SELinux

| Type | For |
|---|---|
| `mcpgw_t`, `mcpgw_exec_t` | gateway |
| `mcpopa_t`, `mcpopa_exec_t` | OPA |
| `mcpsrv_generic_t`, `mcpsrv_fs_t`, `mcpsrv_docs_t`, `mcpsrv_exec_t`, `mcpsrv_<name>_t` | MCP server instances (chapter 9, "SELinux") |
| `mcpsrv_http_t`, `mcpsrv_http_exec_t` | `mcp-http-connector`, the instances of servers defined with `url` |
| `mcpsrv_oauth_t`, `mcpsrv_oauth_exec_t` | `mcp-oauth-helper`, the requests of principals' sign-ins to servers with `sign_in` |
| `mcp_landlock_exec_t` | `mcp-landlock`, an entry point of every server domain |
| `mcpsrv_admin_t`, `mcpsrv_admin_exec_t` | `mcp-gateway-admin` and the server `gateway-admin` |
| `mcpsrv_systemd_t`, `mcpsrv_firewalld_t`, `mcpsrv_zypp_t`, `mcpsrv_suseconnect_t`, `mcpsrv_snapper_t` | the system management servers (chapter 13) |
| `mcpgw_etc_t` | `/etc/mcp-gateway`, `/usr/etc/mcp-gateway` |
| `mcpgw_cred_t` | `/etc/mcp-gateway/credentials` |
| `mcpgw_signing_key_t` | `/etc/mcp-gateway/bundle/signing.pem` |
| `mcpgw_var_lib_t` | `/var/lib/mcp-gateway` |
| `mcpgw_token_t` | `/var/lib/mcp-gateway/tokens` (the gateway only) |
| `mcpgw_cred_run_t` | `/run/mcp-gateway/credentials` (the gateway writes, systemd reads) |
| `mcpgw_runtime_t`, `mcpgw_sock_t`, `mcpgw_ctl_sock_t`, `mcpopa_sock_t` | `/run/mcp-gateway` and its sockets |
| `mcp_port_t` | the HTTPS port (`semanage port -a -t mcp_port_t -p tcp 8443`, or `-m` where the policy already labels it) |
| `mcp_metrics_port_t` | the metrics port (`semanage port -a -t mcp_metrics_port_t -p tcp 9464`) |

| Boolean | Default | Allows |
|---|---|---|
| `mcpopa_can_network` | off | OPA to fetch bundles over HTTPS |
| `mcpgw_can_send_mail` | off | the gateway to connect to SMTP ports |
| `mcpsrv_http_connect_any` | off | servers defined with `url`, and their sign-in helper, to connect to any port of their server, not only HTTP and proxy ports |

| Interface | For |
|---|---|
| `mcp_gateway_backend_template(name)` | defines `mcpsrv_<name>_t` and `mcpsrv_<name>_exec_t` |
| `mcp_gateway_backend_home_rw(domain)` | a server domain reading and writing user home content |
| `mcp_gateway_backend_rpm(name)` | the server's helpers run in `rpm_t`, as with zypper (chapter 4, "Privileged servers") |
| `mcp_gateway_client(domain)` | a user domain connecting to the MCP socket |
| `mcp_gateway_control_client(domain)` | a user domain using the control API |

## Limits and timings

| What | Value | Configurable |
|---|---|---|
| approval wait | 120 s | `approval_timeout` |
| policy decision | 250 ms | `policy.timeout` |
| policy change detection | when written (local policy); 10 s for policy from a bundle server | `policy.watch_interval` |
| configuration change detection | when written; 10 s where a directory cannot be watched | `policy.watch_interval` |
| instance idle stop | 15 min | `supervisor.idle_timeout` |
| HTTP session idle | 30 min | `http.session_idle_timeout` |
| instance memory / tasks / runtime | 512 MiB / 64 / 8 h | no |
| restart backoff | 1 s doubling to 2 min | no |
| MCS collision check | 2 s | no |
| "once" grant | 1 min (15 min if decided with no call waiting) | no |
| "session" grant | session end, at most 8 h | no |
| duration grant | at most 30 days | `approval_scopes` (role data) |
| SSE replay buffer | 256 events per stream, 5 min | no |
| sign-in, from the link to the callback | 10 min | `sign_in.timeout` |
| sign-in token refresh | when an instance starts and the access token expires within 5 min; the instance ends 1 min before it expires | no |
