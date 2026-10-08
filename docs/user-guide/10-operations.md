# 10. Operations

Running the gateway: what to do after a change, logs, state and backup,
upgrades, monitoring, and troubleshooting, starting with the self-check
(`mcp-gateway-admin doctor`). [docs/README.md](../README.md) lists common
error messages and where each is explained.

## Services

| Unit | What | Notes |
|---|---|---|
| `mcp-gateway.service` | the gateway | runs `mcp-gateway --check` before starting; restarts on failure; wants `mcp-opa.service` |
| `mcp-opa.service` | OPA | loads policy changes by itself (directory mode) |
| `mcp-<server>-<id>.service` | one MCP server instance | transient; started and stopped by the gateway |

```bash
systemctl status mcp-gateway.service mcp-opa.service
systemctl list-units 'mcp-*'                 # includes running instances
```

Stopping the gateway stops all instances. Restarting it ends all
sessions: local agents reconnect (most clients restart `mcp-connect`),
remote agents initialize a new session. Pending approvals and grants
survive (chapter 7).

What needs what after a change:

| Change | Action |
|---|---|
| `gateway.yaml`: approvals, notifications, limits, idle and policy timeouts; TLS certificate, SMTP password | nothing; picked up when written (`systemctl reload mcp-gateway.service` at once) |
| `gateway.yaml`: other keys (sockets, listeners, supervisor, …; chapter 3) | `mcp-gateway --check && systemctl restart mcp-gateway.service`; until then `mcp-gateway-admin doctor` lists them |
| server definitions (`servers.d`), setup packages | nothing; picked up when written (`systemctl reload mcp-gateway.service` at once) |
| role data (directory mode) | nothing; picked up within seconds |
| role data (signed bundle) | `mcp-policy-bundle` (or "Sign and apply" in Cockpit) |
| OPA drop-in | `systemctl daemon-reload && systemctl restart mcp-opa.service` |
| a user added to `mcp-users` | the user logs in again |
| SELinux module of a server | `semodule -i …`; running instances keep their old rules until restarted |

## Logs

```bash
journalctl -u mcp-gateway.service -f                  # gateway: operation and audit records
journalctl -u mcp-opa.service -f                      # OPA: errors and decision log
journalctl -u 'mcp-fs-*' -f                           # the fs server's instances (their stderr)
journalctl -u mcp-gateway.service -o cat | grep '"audit":true' | jq -c 'select(.effect=="deny")'
```

For more detail, add `--debug` to the gateway's command line temporarily:

```bash
systemctl edit mcp-gateway.service
# [Service]
# ExecStart=
# ExecStart=/usr/bin/mcp-gateway --debug
```

## State and backup

`/var/lib/mcp-gateway/` (mode 0700, owned by `mcp-gateway`):

| File | Contents | If lost |
|---|---|---|
| `grants.json` | standing approvals | users are asked again |
| `pending.json` | pending approvals | pending approvals are gone; agents retry |
| `audit.key` | key of the argument digests | new key: old digests can no longer be compared with new ones |
| `principals.json` | local users who used the gateway or its control API (Cockpit) | approval mail finds primary-group members of approver groups only by enumeration until they come back (chapter 7) |

Back up `/etc/mcp-gateway/` (configuration, definitions, role data,
bundle keys, credentials) and `/var/lib/mcp-gateway/`. All files are
written atomically; copying them while the gateway runs is safe.

The files must stay owned by `mcp-gateway`; restore a backup with
`chown -R mcp-gateway: /var/lib/mcp-gateway`. To run the gateway by hand,
for example to watch its output, run it as that account:

```bash
systemctl stop mcp-gateway.service
runuser -u mcp-gateway -- /usr/bin/mcp-gateway --debug
```

As root it refuses (`refusing to run as root`) unless given
`--allow-root`: the state files it would write would be root's, and the
service would then fail to read them. If that happened, the gateway names
the files at start (`state files not owned by mcp-gateway`) and exits, and
`mcp-gateway-admin doctor` names them too; `chown -R mcp-gateway:
/var/lib/mcp-gateway` fixes it.

## Upgrades

```bash
zypper update 'mcp-gateway*'
systemctl try-restart mcp-gateway.service mcp-opa.service
```

The package does not restart `mcp-gateway.service` itself: an update
made through a privileged server (package installation by an agent)
would otherwise wait for itself. Until you restart it, the gateway runs
the previous version; it logs "mcp-gateway was updated", and the
Cockpit page shows a notice. A restart waits for calls to privileged
servers (up to 28 minutes) and ends all sessions.

Your files below `/etc` are left alone, and a new release reads the
files of the release before it. Before restarting, check them with the
new version:

```bash
mcp-gateway --check
```

It fails on what the new version cannot read, and warns about keys that
are deprecated: they still work, but go away with the next minor
release, so change them now. If the package's default configuration
changed, compare it with your copy:
`diff /usr/etc/mcp-gateway/gateway.yaml /etc/mcp-gateway/gateway.yaml`.
In signed bundle mode, rebuild the bundle after an update: the bundle
contains the policy logic of the version it was built with.

## Monitoring

### Metrics

Root reads the metrics, in the Prometheus text format, on the control
socket:

```bash
curl -s --unix-socket /run/mcp-gateway/control.sock http://localhost/v1/metrics
```

With `metrics.listen` (chapter 3) Prometheus can scrape them over HTTP
at `/metrics`.

| Metric | Type | Meaning |
|---|---|---|
| `mcp_gateway_decisions_total{action,effect}` | counter | decisions enforced; a call asked again after an approval counts twice |
| `mcp_gateway_policy_failures_total{reason}` | counter | decisions that failed closed: `error` (OPA did not answer), `invalid` (malformed decision) |
| `mcp_gateway_opa_query_duration_seconds{query}` | histogram | time of queries to OPA, e.g. `query="mcp/authz/decision"` |
| `mcp_gateway_opa_query_errors_total{query}` | counter | failed queries to OPA |
| `mcp_gateway_instance_starts_total{server}` | counter | server instances started |
| `mcp_gateway_instance_failures_total{server,stage}` | counter | instances that failed to start (`start`) or exited without being stopped (`exit`) |
| `mcp_gateway_token_expiries_total` | counter | HTTP streams ended because the token that opened them expired (chapter 5) |
| `mcp_gateway_limit_refusals_total{limit}` | counter | sessions and instances refused at a limit (`sessions`, `instances_per_principal`, `instances`; chapter 3) |
| `mcp_gateway_approvals_decided_total{decision}` | counter | approvals decided (`approve`, `deny`) |
| `mcp_gateway_approvals_pending` | gauge | approvals waiting for a decision |
| `mcp_gateway_sessions`, `mcp_gateway_instances` | gauge | client sessions, running server instances |
| `mcp_gateway_restart_pending` | gauge | `1` after an update until the gateway is restarted |
| `mcp_gateway_build_info{version}` | gauge | always `1`; the version as a label |

Worth an alert: a rising `mcp_gateway_policy_failures_total` (OPA is
down or the policy is broken: everything is denied), a rising
`mcp_gateway_instance_failures_total` (a server crashes; see its
journal), `mcp_gateway_approvals_pending` staying above zero (nobody
decides), and `mcp_gateway_restart_pending` staying at 1.

### Other signals

Useful signals:

- `systemctl is-active mcp-gateway.service mcp-opa.service`;
- `systemctl status mcp-gateway.service`: the status line counts
  sessions, server instances and pending approvals;
- the rate of `"effect":"deny"` records, especially with reason "policy
  evaluation failed" (OPA trouble);
- `backend unavailable` in the gateway log (servers crashing);
- kernel audit records `op=mcp-mcs-collision`;
- `GET /v1/policy` on the control socket (as root): the active bundle
  revision on every gateway.

The gateway tells systemd when it is ready (`Type=notify`) and pings
systemd's watchdog every 20 seconds (`WatchdogSec=60s`). It pings only
while its sessions, server instances and approvals can be reached: if
they stay locked for a minute, systemd kills the gateway with SIGABRT
and restarts it. Before it exits, the gateway writes the stack of every
goroutine to the journal (`journalctl -u mcp-gateway.service`); please
attach that to a bug report. Sessions end with the restart; calls to
privileged servers in progress are not waited for in that case. An
unreachable OPA does not count: the gateway then denies every request,
but keeps running.

## Troubleshooting

### Self-check

Start with the self-check, as root:

```bash
mcp-gateway-admin doctor
```

```
OK    configuration: /usr/etc/mcp-gateway/gateway.yaml, 3 servers (firewalld, fs, systemd)
OK    role data: /etc/mcp-gateway/policy/rbac/data.json valid (7 shipped roles known)
OK    mcp-gateway.service: active
OK    mcp-opa.service: active
OK    state files: /var/lib/mcp-gateway owned by mcp-gateway
OK    gateway status: running version 0.9.0
OK    policy: OPA decides (deny for an unknown principal)
OK    server firewalld: starts: firewalld-mcp 0.1.0, 5 tools, 0 prompts, 0 resource templates
FAIL  server fs: does not start: starting: …
        journalctl -u 'mcp-fs-*' shows its output; mcp-gateway-admin inspect --server fs for more
OK    server systemd: starts: systemd-mcp 0.3.0, 9 tools, 0 prompts, 0 resource templates
FAIL  SELinux mcpsrv_firewalld_t: 2 denials (1 distinct) since 2026-10-01 09:12:00
        2  mcpsrv_firewalld_t system_dbusd_var_run_t:dir { search } dbus (firewalld-mcp)
OK    polkit mcp-sysmgmt: a polkit rule names mcp-sysmgmt (servers firewalld, systemd)
WARN  principals: 1 of 4 members of mcp-users hold no role: they may connect but see no server
        carol
```

On a terminal the statuses are colored: `OK` and `SKIP` green, `WARN`
orange, `FAIL` red (not with `NO_COLOR` set or `--json`, where the status is
`ok`, `warn`, `fail` or `skip`).

- `FAIL`: something does not work; the lines below say what to do.
- `WARN`: something you can change, and the lines below name the change.
  The gateway works otherwise.
- `OK` with lines below: a note. The doctor cannot tell whether
  something is wrong (a server that may not need polkit), or it is how
  the system works (a transactional system's read-only `/usr`).

It exits 1 if a check failed and 0 otherwise; with `--strict`, 3 if a
check warned and none failed. For monitoring, `--json` gives each result
an `id` and, where it is about something, a `subject` (a server, an
account, a path) that stay the same across releases (chapter 11).

| Check | Looks at |
|---|---|
| configuration | `gateway.yaml` and the server definitions; deprecated keys warn |
| role data | the schema and references (as `--check-policy-data`); skipped when the file does not exist (policy from a bundle) |
| services, gateway status | `mcp-gateway.service` and `mcp-opa.service` active; the running version, and whether an update waits for a restart |
| state files | that `mcp-gateway` owns every file in `/var/lib/mcp-gateway`; a file root owns (the gateway was run as root) keeps the service from starting |
| TLS | with `http.listen`: that `cert_file` and `key_file` load as a pair, and that `mcp-gateway` (every directory on the way too) and the gateway's SELinux domain can read them (`mcpgw_etc_t` under `/etc/mcp-gateway`, `cert_t` under `/etc/pki`, or `usr_t`): without, the gateway does not start, and `mcp-gateway --check`, which runs as root, does not notice. Also that the certificate has not expired (a warning 14 days before) and names the host of `http.audience` (clients refuse it otherwise); notes a self-signed certificate, which clients must trust. Needs root |
| firewall | with `http.listen` on more than loopback and firewalld running: that an active zone lets the port in (its ports, one of its services, or target `ACCEPT`); without, remote clients get "connection refused" while everything works on the host itself, and the details give the `firewall-cmd` line. Needs root |
| policy | that OPA answers a decision (every request is denied otherwise) |
| server *name* | that each server starts, as for shared discovery, and answers MCP; then whether roles name tools it does not offer (`roles` *name*, with the server's version and account: a server not running as root may hide the tools only root can use, and another version may name its tools differently), and whether its `tool_notes` name tools it does not offer (`tool notes` *name*) |
| SELinux *type* | denials in the last day, but not from before the current boot, involving the gateway's, OPA's and the servers' types; denials in permissive mode (a profiling run) only warn. Denials from before a reboot came from the policy and labels of then: on a transactional system a module installed with its packages takes effect at the next boot (chapter 2). `--previous-boots` counts them too |
| SELinux types | that the loaded policy knows each server's `selinux_type`; a server whose module is missing cannot start, also in permissive mode |
| program *name* | that a server's program, and every other program the gateway's and the setups' modules give a type (the gateway's own, helpers a server starts like zypp's `zypp-mcp-tool`), where installed, carries the label the policy gives its path (`matchpathcon` from `selinux-tools`, else `restorecon -n` from `policycoreutils`, also from `/usr/sbin` where `PATH` lacks it, as for the `gateway-admin` server; if neither can tell, the check is skipped with the reason); a program installed before its module (e.g. still `bin_t`) cannot start in its domain, and its tools are missing. The fix it names is `restorecon`, on a transactional system `transactional-update run restorecon` and a reboot. A program labeled as another server's (`mcpsrv_systemd_exec_t` while the definition says `mcpsrv_generic_t`, or no `selinux_type`) is a definition with the wrong domain, most often written by hand: the check then names the `selinux_type` to set (compare with the shipped definitions in `/usr/share/mcp-gateway/servers.d`), not a relabel, which would start the program where it lacks what it needs |
| landlock | the kernel's Landlock ABI and which servers' instances start restricted (`landlock`), and per server what the kernel leaves out of its rules (TCP ports before ABI 4, scoping before ABI 6); warns when the kernel has no Landlock, telling a kernel built without it from one that has it but not in its `lsm=` list; fails for definitions with `required: true` whose rules the kernel cannot apply in full, or when `mcp-landlock` is missing |
| landlock *name* | a server that did not start (`server` *name*) and runs restricted (its definition's `landlock`, `mcp-server-fs` and `mcp-server-exec`, which restrict themselves, or the connector of a `url` server), while SELinux denied its domain nothing: Landlock is the likely cause. A Landlock refusal leaves no audit record on the 6.12 kernels; it is a "permission denied" in the server's own output (`journalctl -u 'mcp-NAME-*'`). Widen the definition's `landlock` with the tree it needs |
| read-only /usr | on a transactional system: notes privileged servers, which cannot change `/usr` (chapter 2, "Transactional systems") |
| snapper *server* | that a snapper config's `ALLOW_USERS` (or `ALLOW_GROUPS`) names the account mcp-server-snapper runs as; without, it can only list the configs. Warns when there is no config at all |
| polkit *account* | servers running as a system account (`run_as` naming one; not `principal`, `root` or `dynamic`) that no polkit rule names: warns for servers that act through polkit (the systemd and firewalld setups' domains), which are refused without one; for other servers a note. For a systemd server it also warns when the rule does not allow `com.suse.gatekeeper.readlog`, which systemd-mcp before 0.3.5 checks every read with (by the version the server reported when the doctor started it; without that, as if before 0.3.5) |
| principals | members of `socket_group` bound to no role, by name or group (users whose primary group it is, and remote principals, are not checked) |
| approver group *group* | with approval mail on: that mail finds members in each `group:` approver, as it does (chapter 7); warns about a group that does not exist or in which it finds nobody |

Starting the servers runs them like the gateway would, once each; use
`--no-start` to skip that, `--server` to check one. While someone
profiles a server (chapter 4), dontaudit rules are off and the audit log
has denials that do not matter otherwise; they show up here too.

### Asking an agent

With `mcp-gateway-fs-server` installed, the gateway's documentation is
itself a server, `gateway-docs`: the user guide, `architecture.md` and
`CHANGELOG.md` of the installed version, from
`/usr/share/mcp-gateway/docs`, read-only and without the network. An
agent connected to the gateway can look up how something is configured
or what an error means ("the snapper tools do not show up: what does the
gateway need for that?"). The server tells the agent where
troubleshooting and the reference are; it has the reading tools of the
file server (chapter 4). Its instructions tell the agent to search
first (`search_text`) and read only the lines around a match
(`read_text_file` with `offset` and `limit`): a lookup costs a few
thousand tokens instead of whole chapters (`architecture.md` alone is
about 40,000). For a broad question without a precise term, the agent
reads a file's outline (`outline_file`: its headings with line numbers
and sizes, under 1,000 tokens for `architecture.md`) and then the one
section.

For the configuration in force on the machine, the agent needs the
`gateway-admin` server (role `gateway-admin`): its `show_config` shows
`gateway.yaml`, the server definitions, the exec servers' command files
(`exec.d`) and the role data with secrets
masked (each call with an approval, out of band), `check_config` and
`doctor` check them without one. The other servers cannot
read these files, by design: the file server sees the user's home only,
and the systemd roles allow reading systemd's own files only (systemd-mcp
reports such a refusal as "calling method was canceled by user"). The
servers' instructions, and those of the aggregated endpoint, point
agents to `gateway-admin`. On the aggregated endpoint,
`gateway_capabilities` lists what the user may do on each server and
where the gateway's files are (chapter 5).

Users need a role for it: the shipped `viewer` and `developer` roles
include it, and the shipped role `gateway-docs-reader` grants only it:

```json
"bindings": {"groups": {"mcp-users": ["gateway-docs-reader"]}}
```

A role of your own (such as `sysops` in chapter 13) gets it with two
permissions, or by binding `gateway-docs-reader` next to it:

```json
{"server": "gateway-docs", "tool": "*"},
{"server": "gateway-docs", "resource": "*"}
```

It runs as a throwaway user in the domain `mcpsrv_docs_t`, which reads
`/usr` and nothing of the users'. An empty
`/etc/mcp-gateway/servers.d/gateway-docs.yaml` disables it.

The documentation tells an agent how things should be, not how they are
on this machine. For that there is the server `gateway-admin`, which the
main package installs: the gateway's diagnostics as tools.

| Tool | What it returns | With the role `gateway-admin` |
|---|---|---|
| `doctor` | the checks of `mcp-gateway-admin doctor` (above), without starting servers and without asking OPA | allowed |
| `check_config` | whether `gateway.yaml`, the server definitions and the role data are valid | allowed |
| `explain_decision` | what the policy decides when a user calls a tool, with the user's roles and the permissions that match | approval |
| `show_config` | the configuration files (also the exec servers' command files in `exec.d`), values of keys that look like secrets (`token`, `secret`, `password`, `private`, `api_key`) masked | approval |
| `recent_audit` | the gateway's audit records from its journal, filtered by user, server and effect | approval |
| `selinux_denials` | SELinux denials for the gateway and its servers | approval |

The shipped role `gateway-admin` grants these; the `admin` role, which
allows everything, includes them without approval. Bind it to the
administrators who debug the gateway with an agent:

```json
"bindings": {"users": {"alice": ["gateway-admin", "gateway-docs-reader"]}}
```

Nothing in it changes the system; the agent suggests the changes, you
make them. It runs as root, which the audit log and some of the doctor's
checks need, but in the sandbox without capabilities and in the domain
`mcpsrv_admin_t`, which only reads: the configuration, the state
directory, the journal, the audit log, file labels. Like every server it
cannot reach the gateway's sockets or OPA, so the `doctor` tool skips
what needs them (run `mcp-gateway-admin doctor` as root for those), and
`explain_decision` evaluates the policy files with `opa eval` as
`mcp-opa.service` loads them: with signed policy bundles, the active
policy is the bundle's. It does not see approvals already given.

An empty `/etc/mcp-gateway/servers.d/gateway-admin.yaml` disables it.

### The agent cannot connect

| Symptom | Cause and fix |
|---|---|
| `mcp-connect: … permission denied` | the user is not in `mcp-users`, or has not logged in again since: `id -nG` |
| `… no such file or directory` | the gateway is not running: `systemctl status mcp-gateway.service` |
| connection closes at once, AVC denial for the agent's domain | the agent runs in a confined domain not allowed to connect (chapter 9) |
| the agent lists no tools | the principal holds no role with permissions for the server; check the bindings and test a decision (chapter 6) |
| `unknown server "x"` | no server with that name; `mcp-gateway --check` lists how many are registered, the Servers tab in Cockpit their names |

### Calls fail

The error text the agent gets (a tool error starting with `mcp-gateway:`
for tool calls) says why; the audit record has the same reason.

| Reason | Meaning and fix |
|---|---|
| `no matching permission` | no role of the principal allows this; add a permission or binding |
| `no matching permission: the arguments are outside what your roles allow (path: ^/home/alice/)` | a role allows the tool, but not with these arguments: its `args` patterns follow (one per permission, joined with "; or "), so the agent can correct the call. The values sent are not repeated |
| `…; the gateway's configuration is shown by the gateway-admin server's show_config, not by other servers` | the call named the gateway's own files (`/etc/mcp-gateway`, `/usr/share/mcp-gateway`) through another server; added when `gateway-admin` (or `gateway-docs`, for the documentation) is defined |
| `denied by policy` | a permission with `effect: "deny"` matched |
| `policy evaluation failed` | OPA did not answer in time or is down: `systemctl status mcp-opa.service`, `journalctl -u mcp-opa.service`; with a signed bundle, check that it verifies |
| `invalid policy decision` / `invalid obligations` | custom policy produced something the gateway cannot use; see the gateway log |
| `approval via url required but not available` | neither the channel nor the fallback is usable: set `approvals.url_template`, keep the control socket enabled, or use a client with URL elicitation |
| `declined by user` | the approver denied, or the user declined to open the approval page |
| `approval failed` | the approval timed out (`approval_timeout`) or the agent's client failed the elicitation |
| `policy did not accept the approval` | a grant was created but policy still asks (custom policy) |
| `rate limit exceeded` | a `rate_limit` obligation; wait |
| `argument "x" violates a constraint: it must match …` | an `arg_constraints` obligation; the pattern the argument must match follows |
| `output withheld: result of N bytes exceeds the limit of M` | a `max_output_bytes` obligation |
| `backend unavailable; retry in 8s` | the instance crashed or could not start and is backing off; read its journal (`journalctl -u 'mcp-<server>-*'`) |
| `backend unavailable` | the instance died during the call |

### Errors from servers

An error without the `mcp-gateway:` prefix comes from the MCP server
behind the gateway: policy allowed the call, and the server, or the
system service it asked, refused it.

| Error | Server | Meaning and fix |
|---|---|---|
| `…: outside the allowed directories (…)` | `fs` | the file server works only below its `--root` directories, as shipped the user's home (`list_allowed_directories` names them). Files elsewhere are not meant to be reached through it; for the gateway's configuration, use `gateway-admin` ("Asking an agent" above) |
| `…: leads outside the allowed directories (through a symbolic link)` | `fs` | a link below the root points out of it; the server does not follow it (chapter 9, "Paths and symbolic links") |
| `read-only file system (on a transactional system, …)` | `fs` | the path is on the read-only root file system (chapter 2, "Transactional systems") |
| `calling method was canceled by user` | `systemd` | systemd-mcp's own authorization refused the call: its polkit check found no rule for the account it runs as (chapter 13, "Service permissions"; systemd-mcp 0.3.4 checks reads too, as `com.suse.gatekeeper.readlog`), or it cannot read the file `get_file` names. The gateway's own files are closed to it by SELinux (chapter 9) |
| `Interactive authentication required`, `NOT_AUTHORIZED` | `systemd`, `firewalld` | polkit refused the server's account: the setup's polkit rule is missing or names another account (chapter 13) |
| `D-Bus call failed: org.freedesktop.DBus.Error.Failed` | `snapper` | snapperd refused the account: it is not in the config's `ALLOW_USERS`, or the tool needs root (chapter 13) |
| `…: permission denied`, `Permission denied` with no SELinux denial (`ausearch -m AVC` shows none) | any server with `landlock`, and `fs`, `exec`, the connector | the kernel's Landlock refused a path outside the instance's trees; it leaves no audit record. The doctor names the ruleset (`landlock` *name*); widen the definition's `landlock` with the tree the server needs (chapter 4, "Landlock"), for `exec` the command file's `landlock` |

### Instances do not start

```bash
journalctl -u mcp-gateway.service -b | grep -i 'instance\|backend'
journalctl -u 'mcp-git-*' -b
ausearch -m AVC -ts recent | grep mcpsrv
```

| Cause | Fix |
|---|---|
| the program is not executable or not found | the first element of `command` must be an absolute path to an executable |
| SELinux denies the program as entry point | label it with the domain's `_exec_t` type or add `corecmd_bin_entry_type` (chapter 4) |
| SELinux denies what the server does | extend the server's module (permissive + `audit2allow`) |
| the server needs the network / a writable home | `network: true`, `sandbox.protect_home: read-write` |
| the server fails with "permission denied" and SELinux denied nothing | its `landlock` (or, for `fs`, `exec` and the connector, their own restriction) leaves out a tree it needs: the journal's first line says what was applied (`mcp-landlock: Landlock ABI 6, scoped`), the doctor names the ruleset (`landlock` *name*); widen the definition's `landlock` (chapter 4, "Landlock") |
| `landlock: required, but the kernel cannot apply every restriction` | the definition says `landlock: {required: true}` and the kernel lacks Landlock or a right the rules need (the doctor's `landlock` check names it): another kernel, or drop `required` |
| the server cannot create or write its state (`Read-only file system`, e.g. below `/var/lib`) | `sandbox.state_directory`, or `sandbox.read_write_paths` for other existing paths (chapter 4) |
| "Interactive authentication required" / polkit denial | the polkit rule `50-mcp-gateway.rules` is missing, or the unit name does not start with `mcp-` |
| out of memory, killed after 8 hours | the fixed limits (512 MiB, 8 h); split the work or restart |
| the gateway logs `invalid message from backend … parse error` | the server wrote something other than MCP to stdout; the `line` field shows its first 200 bytes (often a usage message, so the server's arguments are wrong, or a log line, so it needs its option to log to stderr). Such lines are discarded. They may contain whatever the server printed, so treat the gateway's journal accordingly. |

### Remote clients

See the status table in chapter 5. The gateway logs the reason for every
rejected token (`token rejected`, with the error) at the default log
level. Common causes: the token's `aud` is not exactly `http.audience`,
the clock is off, or the IdP's keys cannot be fetched (check that the
gateway may reach the issuer).

### Warnings at start

| Warning | Meaning |
|---|---|
| `libvirt picks MCS categories from the gateway's range; …` | install the libvirt drop-in (chapter 9) |
| `kernel audit not available` | events go only to the journal; set `audit.kernel: off` to silence, `on` to require |
| `approvals.url_template is set but the control socket is disabled; …` | URL approvals cannot be decided; enable the control socket |
| `supervisor mode exec: backends run as child processes without systemd's sandbox and SELinux …` | development mode is on |
