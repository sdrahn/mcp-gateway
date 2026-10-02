# 10. Operations

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
| `gateway.yaml`, server definitions, TLS certificate, SMTP password | `mcp-gateway --check && systemctl restart mcp-gateway.service` |
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
`mcp-gateway doctor` names them too; `chown -R mcp-gateway:
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
mcp-gateway doctor
```

```
ok    configuration: /usr/etc/mcp-gateway/gateway.yaml, 3 servers (firewalld, fs, systemd)
ok    role data: /etc/mcp-gateway/policy/rbac/data.json valid (7 shipped roles known)
ok    mcp-gateway.service: active
ok    mcp-opa.service: active
ok    state files: /var/lib/mcp-gateway owned by mcp-gateway
ok    gateway status: running version 0.4.0
ok    policy: OPA decides (deny for an unknown principal)
ok    server firewalld: starts: firewalld-mcp 0.1.0, 5 tools, 0 prompts, 0 resource templates
fail  server fs: does not start: starting: …
        journalctl -u 'mcp-fs-*' shows its output; mcp-gateway inspect -server fs for more
ok    server systemd: starts: systemd-mcp 0.3.0, 9 tools, 0 prompts, 0 resource templates
fail  SELinux mcpsrv_firewalld_t: 2 denials (1 distinct) since 2026-10-01 09:12:00
        2  mcpsrv_firewalld_t system_dbusd_var_run_t:dir { search } dbus (firewalld-mcp)
ok    polkit mcp-sysmgmt: a polkit rule names mcp-sysmgmt (servers firewalld, systemd)
warn  principals: 1 of 4 members of mcp-users hold no role: they may connect but see no server
        carol
```

| Check | Looks at |
|---|---|
| configuration | `gateway.yaml` and the server definitions; deprecated keys warn |
| role data | the schema and references (as `--check-policy-data`) |
| services, gateway status | `mcp-gateway.service` and `mcp-opa.service` active; the running version, and whether an update waits for a restart |
| state files | that `mcp-gateway` owns every file in `/var/lib/mcp-gateway`; a file root owns (the gateway was run as root) keeps the service from starting |
| policy | that OPA answers a decision (every request is denied otherwise) |
| server *name* | that each server starts, as for shared discovery, and answers MCP; then whether roles name tools it does not offer (`roles` *name*; as the account it runs as, a server may hide tools) |
| SELinux *type* | denials in the last day involving the gateway's, OPA's and the servers' types; denials in permissive mode (a profiling run) only warn |
| SELinux types | that the loaded policy knows each server's `selinux_type`; a server whose module is missing cannot start, also in permissive mode |
| snapper *server* | that a snapper config's `ALLOW_USERS` (or `ALLOW_GROUPS`) names the account mcp-server-snapper runs as; without, it can only list the configs |
| polkit *account* | servers running as a system account that no polkit rule names: servers that act through polkit (systemd, firewalld) are refused without one |
| principals | members of `socket_group` bound to no role, by name or group (users whose primary group it is, and remote principals, are not checked) |

Starting the servers runs them like the gateway would, once each; use
`--no-start` to skip that, `--server` to check one. While someone
profiles a server (chapter 4), dontaudit rules are off and the audit log
has denials that do not matter otherwise; they show up here too.

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
| `denied by policy` | a permission with `effect: "deny"` matched |
| `policy evaluation failed` | OPA did not answer in time or is down: `systemctl status mcp-opa.service`, `journalctl -u mcp-opa.service`; with a signed bundle, check that it verifies |
| `invalid policy decision` / `invalid obligations` | custom policy produced something the gateway cannot use; see the gateway log |
| `approval via url required but not available` | neither the channel nor the fallback is usable: set `approvals.url_template`, keep the control socket enabled, or use a client with URL elicitation |
| `declined by user` | the approver denied, or the user declined to open the approval page |
| `approval failed` | the approval timed out (`approval_timeout`) or the agent's client failed the elicitation |
| `policy did not accept the approval` | a grant was created but policy still asks (custom policy) |
| `rate limit exceeded` | a `rate_limit` obligation; wait |
| `argument "x" violates a constraint` | an `arg_constraints` obligation |
| `output withheld: result of N bytes exceeds the limit of M` | a `max_output_bytes` obligation |
| `backend unavailable; retry in 8s` | the instance crashed or could not start and is backing off; read its journal (`journalctl -u 'mcp-<server>-*'`) |
| `backend unavailable` | the instance died during the call |

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
| `supervisor mode exec: backends run unconfined …` | development mode is on |
