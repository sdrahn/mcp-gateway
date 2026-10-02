# 11. Reference

## Commands

### mcp-gateway

```
mcp-gateway [--config FILE] [--check] [--debug] [--version]
mcp-gateway --check-policy-data [--policy-data FILE]
```

| Flag | Meaning |
|---|---|
| `--config FILE` | configuration file (default: `/etc/mcp-gateway/gateway.yaml`, else `/usr/etc/mcp-gateway/gateway.yaml`, else built-in defaults) |
| `--check` | validate the configuration, all MCP server definitions and the role data (if the file exists), print a summary, exit (status 1 on errors) |
| `--check-policy-data` | validate only the role data against its schema, print each problem, exit (status 1 on problems) |
| `--policy-data FILE` | role data for the two checks (default: `/etc/mcp-gateway/policy/rbac/data.json`; `-`: standard input; empty: none) |
| `--shipped-policy DIR` | shipped policy with the roles of the server setups, which bindings may name; its setup role files are checked too (default: `/usr/share/mcp-gateway/policy`; empty: none) |
| `--debug` | log debug messages |
| `--version` | print the version |

### mcp-gateway inspect

```
mcp-gateway inspect [options] --server NAME
mcp-gateway inspect [options] --name NAME -- COMMAND [ARG...]
```

Starts an MCP server, reports its tools, prompts and resource templates
with a classification of the tools, drafts roles, and checks role data
against the server (chapter 4, "Inspecting a server"). Exit status 1 if
the server cannot be inspected or a role check finds errors, 2 on usage
errors.

| Flag | Meaning |
|---|---|
| `--server NAME` | a server of the registry, started as for shared discovery (through the configured supervisor; with systemd as root) |
| `--name NAME -- COMMAND…` | a server started by command, as a plain child process of the caller, without sandbox (refused as root) |
| `--config FILE` | gateway configuration, for the registry and the supervisor |
| `--exec` | start a `--server` definition as a plain child process, without sandbox (refused as root) |
| `--roles FILE` | role data or a setup's roles to check against the server; repeatable |
| `--out DIR` | write the drafts there: `roles.json`, and `NAME.yaml` for a command (existing files are kept) |
| `--read-by-name` | also put tools that read by their name alone into the reader role |
| `--json` | print the result (server answers, classification, draft roles, findings) as JSON |
| `--timeout D` | how long to wait for the server (default 60s) |

### mcp-gateway profile

```
mcp-gateway profile [options] --server NAME --out DIR
mcp-gateway profile [options] --server NAME --verify
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

### mcp-gateway review

```
mcp-gateway review [options] --source DIR
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
| `GET /v1/status` | `{"version", "restart_pending"}`: the running gateway's version, and `true` when its program was updated and the gateway not yet restarted |
| `GET /v1/approvals` | pending approvals the caller may decide on (list of approvals, below) |
| `GET /v1/approvals/{id}` | one approval; `404` if unknown or not the caller's to decide |
| `POST /v1/approvals/{id}` | `{"decision": "approve"\|"deny", "scope": "once"\|"session"\|<duration>}`; returns the grant (`200`) or nothing (`204`, denied); `400 scope not offered` |
| `GET /v1/grants` | grants the caller may manage (list of grants, below) |
| `DELETE /v1/grants/{id}` | revoke; `204` |
| `GET /v1/servers` | registered servers `{"name", "selinux_type", "isolation", "network", "run_as", "privileged", "instances"}` with the instances the caller may manage `{"id", "server", "unit", "sub", "iss", "uid", "transport", "session_id", "isolation", "started", "sessions", "privileged", "busy"}` |
| `DELETE /v1/instances/{id}` | stop an instance; `204`; `409` for a privileged instance with a call running |
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
| `mcp-mcs-collision` | an instance's MCS pair was taken by another workload | `instance`, `pair`, `foreign_pid`, `foreign_context` |

## Files and directories

| Path | Contents |
|---|---|
| `/usr/bin/mcp-gateway`, `mcp-connect`, `mcp-gateway-notify` | programs |
| `/usr/sbin/mcp-policy-bundle` | bundle tool |
| `/usr/etc/mcp-gateway/gateway.yaml` | default configuration |
| `/etc/mcp-gateway/gateway.yaml` | your configuration |
| `/usr/share/mcp-gateway/servers.d/` | package server definitions |
| `/etc/mcp-gateway/servers.d/` | your server definitions |
| `/usr/share/mcp-gateway/policy/` | policy logic |
| `/etc/mcp-gateway/policy/rbac/data.json` | role data |
| `/usr/share/mcp-gateway/schema/rbac.schema.json` | JSON Schema (draft-07) of the role data |
| `/etc/mcp-gateway/credentials/` | MCP server secrets (0700, `mcpgw_cred_t`) |
| `/etc/mcp-gateway/bundle/` | `policy.tar.gz`, `verify.pem`, `signing.pem` |
| `/usr/share/mcp-gateway/opa/` | OPA drop-ins: `signed-bundle.conf`, `bundle-server.conf`, `decision-logs.conf`; examples `opa-config.yaml.example`, `decision-logs.yaml.example` |
| `/usr/share/mcp-gateway/mcs/` | libvirt drop-ins: `virtqemud.conf`, `libvirtd.conf` |
| `/var/lib/mcp-gateway/` | `grants.json`, `pending.json`, `audit.key` |
| `/run/mcp-gateway/mcp.sock` | MCP socket |
| `/run/mcp-gateway/control.sock` | control API |
| `/run/mcp-gateway/opa.sock` | OPA (gateway only) |
| `/usr/lib/systemd/system/mcp-gateway.service`, `mcp-opa.service` | units |
| `/usr/lib/sysusers.d/mcp-gateway.conf` | accounts |
| `/usr/share/polkit-1/rules.d/50-mcp-gateway.rules` | lets the gateway manage `mcp-*.service` |
| `/usr/share/cockpit/mcp-gateway/` | Cockpit page |
| `/etc/xdg/autostart/mcp-gateway-notify.desktop` | desktop agent autostart |
| `/usr/libexec/mcp-servers/` | conventional place for MCP server programs |

## SELinux

| Type | For |
|---|---|
| `mcpgw_t`, `mcpgw_exec_t` | gateway |
| `mcpopa_t`, `mcpopa_exec_t` | OPA |
| `mcpsrv_generic_t`, `mcpsrv_fs_t`, `mcpsrv_<name>_t` | MCP server instances |
| `mcpgw_etc_t` | `/etc/mcp-gateway`, `/usr/etc/mcp-gateway` |
| `mcpgw_cred_t` | `/etc/mcp-gateway/credentials` |
| `mcpgw_signing_key_t` | `/etc/mcp-gateway/bundle/signing.pem` |
| `mcpgw_var_lib_t` | `/var/lib/mcp-gateway` |
| `mcpgw_runtime_t`, `mcpgw_sock_t`, `mcpgw_ctl_sock_t`, `mcpopa_sock_t` | `/run/mcp-gateway` and its sockets |
| `mcp_port_t` | the HTTPS port (`semanage port -a -t mcp_port_t -p tcp 8443`) |
| `mcp_metrics_port_t` | the metrics port (`semanage port -a -t mcp_metrics_port_t -p tcp 9464`) |

| Boolean | Default | Allows |
|---|---|---|
| `mcpopa_can_network` | off | OPA to fetch bundles over HTTPS |
| `mcpgw_can_send_mail` | off | the gateway to connect to SMTP ports |

| Interface | For |
|---|---|
| `mcp_gateway_backend_template(name)` | defines `mcpsrv_<name>_t` and `mcpsrv_<name>_exec_t` |
| `mcp_gateway_backend_home_rw(domain)` | a server domain reading and writing user home content |
| `mcp_gateway_client(domain)` | a user domain connecting to the MCP socket |
| `mcp_gateway_control_client(domain)` | a user domain using the control API |

## Limits and timings

| What | Value | Configurable |
|---|---|---|
| approval wait | 120 s | `approval_timeout` |
| policy decision | 250 ms | `policy.timeout` |
| policy change detection | 10 s | `policy.watch_interval` |
| instance idle stop | 15 min | `supervisor.idle_timeout` |
| HTTP session idle | 30 min | `http.session_idle_timeout` |
| instance memory / tasks / runtime | 512 MiB / 64 / 8 h | no |
| restart backoff | 1 s doubling to 2 min | no |
| MCS collision check | 30 s | no |
| "once" grant | 1 min (15 min if decided with no call waiting) | no |
| "session" grant | session end, at most 8 h | no |
| duration grant | at most 30 days | `approval_scopes` (role data) |
| SSE replay buffer | 256 events per stream, 5 min | no |
