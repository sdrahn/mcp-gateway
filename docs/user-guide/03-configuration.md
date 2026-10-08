# 3. Configuration

Which files the gateway reads, and every key of `gateway.yaml`. MCP
server definitions are chapter 4, the role data chapter 6.

## Files

The gateway separates what packages install (below `/usr`) from what you
change (below `/etc`):

| Path | Contents | Owner |
|---|---|---|
| `/usr/etc/mcp-gateway/gateway.yaml` | default configuration | package |
| `/etc/mcp-gateway/gateway.yaml` | your configuration; used **instead of** the default if it exists | you |
| `/usr/share/mcp-gateway/servers.d/*.yaml` | MCP server definitions installed by packages | packages |
| `/etc/mcp-gateway/servers.d/*.yaml` | your MCP server definitions; a file overrides the package file of the same name, an empty file or a symlink to `/dev/null` disables it | you |
| `/usr/share/mcp-gateway/policy/` | policy logic (Rego), and the roles of setup packages (`mcp/profiles/<setup>/data.json`) | packages |
| `/etc/mcp-gateway/policy/rbac/data.json` | roles, bindings, approver rules | you |
| `/etc/mcp-gateway/credentials/` | secrets for MCP servers (root only) | you |
| `/etc/mcp-gateway/exec.d/*.yaml` | the commands of the command server `exec` (chapter 4) | you |
| `/etc/mcp-gateway/bundle/` | signed policy bundle and keys (optional) | you |
| `/var/lib/mcp-gateway/` | grants, pending approvals, audit key | gateway |
| `/run/mcp-gateway/` | sockets | gateway, OPA |
| `/usr/share/mcp-gateway/docs/` | this documentation, for the server `gateway-docs` | package |

On distributions without `/usr/etc`, the default configuration is
`/etc/mcp-gateway/gateway.yaml` itself (marked as a configuration file).

To change the configuration, copy the default and edit the copy:

```bash
cp /usr/etc/mcp-gateway/gateway.yaml /etc/mcp-gateway/gateway.yaml
$EDITOR /etc/mcp-gateway/gateway.yaml
mcp-gateway --check && systemctl reload mcp-gateway.service
```

The copy replaces the default as a whole; settings you leave out take
their built-in defaults (listed below), not the values of the default
file.

### Changing the configuration while the gateway runs

The gateway reloads `gateway.yaml` when it changes and on `systemctl
reload mcp-gateway.service`, together with the MCP server definitions
(chapter 4, "Changing definitions while the gateway runs"). Sessions
stay open. A change is noticed when the file is written (inotify, also
for a file replaced by renaming another onto it), and several writes in
a row are reloaded once. Where a directory cannot be watched (another
file system, SELinux, inotify's limit; the journal says "changes in a
directory are noticed by polling only"), changes there are noticed
within `policy.watch_interval` (10 s).

| Keys | After a change |
|---|---|
| `approval_timeout`, `approvals.url_template`, `approvals.progress_interval`, `approvals.retry_wait` | apply to approvals asked from then on (`retry_wait`: to the next retry) |
| `notifications.email` (all keys) | apply to the next mail; the password file is read again |
| `limits` | apply to the next session, instance or request |
| `pseudonymize.vault_idle` | applies to the next request |
| `agents.max_version`, `agents.no_request_timeout` | apply to the next request or session (`no_request_timeout`: to the next round) |
| `supervisor.idle_timeout` | applies to instances that become idle from then on |
| `policy.timeout`, `policy.watch_interval` | apply to the next decision and check |
| `http.cert_file`, `http.key_file` | the certificate and key are read again; new connections get them. Renewing the files is a change too, so a renewed certificate needs no restart |
| `http.list_ttl` | applies to the next list |
| all others (sockets, `socket_group`, `http.listen` and the identity provider, `metrics`, `audit`, `state_dir`, the other `supervisor` keys, `policy.opa_socket`, the servers directories) | take effect at the next start (`systemctl restart mcp-gateway.service`, which ends all sessions). Until then the gateway logs them, `GET /v1/status` lists them (`restart_needed`) and `mcp-gateway-admin doctor` warns |

A reload reads and validates the whole file before it changes anything.
If the file does not parse or validate, or the certificate or the
password file cannot be read, nothing changes: the gateway keeps the
configuration in force, logs the error, audits it (`mcp-config-reload`
with `file=gateway.yaml`), reports it (`config_error` in `GET
/v1/status`, the doctor) and retries when the file changes again.
`systemctl reload` runs `mcp-gateway --check` first and fails on such a
file.

## Reference

All keys, with their defaults. Durations are written like `250ms`, `10s`,
`15m`, `8h`.

### Format version

```yaml
version: 1
```

| Key | Default | Meaning |
|---|---|---|
| `version` | `1` | the version of the file's format. The gateway refuses a version it does not read (a file written for a newer gateway) instead of misreading it. |

Within a version, new gateway releases only add keys. A key that is going
away keeps working for one minor release: the gateway logs "… is
deprecated since …" at start and with `mcp-gateway --check`, with what
to write instead, and the release notes list it under "Deprecated".
Server definitions and role data have a `version` of their own and
follow the same rules.

### Local socket

```yaml
socket: /run/mcp-gateway/mcp.sock
socket_group: mcp-users     # default: empty (the gateway's own group)
```

| Key | Default | Meaning |
|---|---|---|
| `socket` | `/run/mcp-gateway/mcp.sock` | unix socket for local agents (mode 0660) |
| `socket_group` | empty | group owning the socket and the control socket; its members may connect. The shipped file sets `mcp-users`. |

### MCP server definitions and state

| Key | Default | Meaning |
|---|---|---|
| `vendor_servers_dir` | `/usr/share/mcp-gateway/servers.d` | definitions installed by packages |
| `servers_dir` | `/etc/mcp-gateway/servers.d` | your definitions (override and mask vendor files by name) |
| `state_dir` | `/var/lib/mcp-gateway` | `grants.json`, `pending.json`, `audit.key`, `principals.json` |

### Policy engine

```yaml
policy:
  opa_socket: /run/mcp-gateway/opa.sock
  timeout: 250ms
  watch_interval: 10s
```

| Key | Default | Meaning |
|---|---|---|
| `policy.opa_socket` | `/run/mcp-gateway/opa.sock` | OPA's socket (`mcp-opa.service`) |
| `policy.timeout` | `250ms` | a decision not received in time is a denial |
| `policy.watch_interval` | `10s` (minimum `1s`) | how often the gateway checks whether OPA loaded changed policy (local policy files are also watched, and checked right after a change); agents are then told to list tools, prompts and resources again. Also how often it checks configuration files in directories it cannot watch |

### Approvals

```yaml
approval_timeout: 120s
approvals:
  control_socket: /run/mcp-gateway/control.sock
  url_template: ""
  progress_interval: 15s
  retry_wait: 25s
```

| Key | Default | Meaning |
|---|---|---|
| `approval_timeout` | `120s` | how long a call waits for a human decision before it is denied |
| `approvals.control_socket` | `/run/mcp-gateway/control.sock` | control API for the Cockpit page, the desktop agent and scripts; `"-"` disables it, and with it the `url` and `oob` channels |
| `approvals.url_template` | empty | the approval page sent to agents in URL-mode approvals, with `{id}` for the approval id, e.g. `https://gw.example.com:9090/mcp-gateway#/approvals/{id}`; empty disables the `url` channel (policy falls back to `oob`) |
| `approvals.progress_interval` | `15s` | how often a call waiting for approval reports progress (`notifications/progress`) to an agent that asked for progress; at least `1s` (chapter 7) |
| `approvals.retry_wait` | `25s` | how long a retry of an agent of MCP 2026-07-28 waits for an approval or a sign-in before it is answered to retry again; keep it below the agents' request timeouts; at least `1s` (chapter 7) |

Who may decide on approvals is policy (chapter 6), not configuration.

### Push notifications

```yaml
notifications:
  email:
    smtp: localhost:25
    from: mcp-gateway@gw.example.com
    to: "{user}"
    starttls: auto
    username: ""
    password_file: ""
    include_args: false
```

Mail is sent only when `smtp` is set. Desktop notifications need no
configuration. Chapter 7 explains who receives what.

| Key | Default | Meaning |
|---|---|---|
| `notifications.email.smtp` | empty (off) | mail server, `host:port` |
| `notifications.email.from` | — (required with `smtp`) | sender address |
| `notifications.email.to` | `{user}` | address for an approver's account name: `{user}` for local delivery by the mail server, or e.g. `{user}@example.com` |
| `notifications.email.starttls` | `auto` | `auto` (if offered), `always` (refuse to send without), `never` |
| `notifications.email.username`, `password_file` | empty | PLAIN authentication; both or neither. The password is read from the file at start. The password is only sent over TLS or to localhost. |
| `notifications.email.include_args` | `false` | include the call's arguments in the mail |

### Metrics

```yaml
metrics:
  listen: 127.0.0.1:9464     # default: empty (off)
```

Root can always read the metrics on the control socket
(`GET /v1/metrics`, chapter 10). `metrics.listen` also serves them over
plain HTTP at `/metrics`, for Prometheus. The listener has no
authentication: whoever reaches the address reads the counts (calls per
action and outcome, instance starts and failures per server, pending
approvals; no names or arguments). Prefer a loopback address and let
Prometheus scrape locally or through a proxy. SELinux: label the port
with `semanage port -a -t mcp_metrics_port_t -p tcp 9464`.

| Key | Default | Meaning |
|---|---|---|
| `metrics.listen` | empty (off) | `host:port` to serve `GET /metrics` on, e.g. `127.0.0.1:9464`; must differ from `http.listen` |

### Audit

```yaml
audit:
  kernel: auto
```

| Key | Default | Meaning |
|---|---|---|
| `audit.kernel` | `auto` | send security-relevant events to the kernel audit subsystem: `auto` (if possible), `on` (refuse to start otherwise), `off` |

### MCP server instances

```yaml
supervisor:
  mode: systemd
  selinux: auto
  idle_timeout: 15m
  mcs_range: c768.c1023
  mcs_avoid: auto
```

| Key | Default | Meaning |
|---|---|---|
| `supervisor.mode` | `systemd` | `systemd`: each instance is a confined transient unit. `exec`: plain child processes without systemd's sandbox and SELinux, under their definitions' `landlock` only (development only). |
| `supervisor.selinux` | `auto` | set each instance's SELinux domain and MCS pair: `auto` (when SELinux is enabled), `on`, `off` |
| `supervisor.idle_timeout` | `15m` | stop an instance this long after its last session ended |
| `supervisor.mcs_range` | `c768.c1023` | the MCS categories instances get their pairs from (at least 8 categories within `c0.c1023`); see chapter 9 on coordinating with libvirt |
| `supervisor.mcs_avoid` | `auto` | skip category pairs held by running containers and virtual machines, and replace an instance whose pair one of them takes later; `off` |

### Limits

```yaml
limits:
  sessions_per_principal: 64
  instances_per_principal: 32
  instances: 0
  requests_per_principal: 64
  streams_per_principal: 16
```

| Key | Default | Meaning |
|---|---|---|
| `limits.sessions_per_principal` | `64` | open sessions of one principal (local and HTTP together). At the limit, the principal's longest-idle HTTP session (no request in flight, no stream attached) is ended to make room; otherwise the new session's `initialize` fails ("session limit reached (64)") |
| `limits.instances_per_principal` | `32` | running instances of one principal. At the limit, its longest-idle instance that no session uses is stopped; otherwise the request that needs a new instance fails ("instance limit reached (32)") |
| `limits.instances` | `0` (none) | running instances of all principals together, handled the same way ("gateway instance limit reached"); size it to the host's memory |
| `limits.requests_per_principal` | `64` | requests of agents of MCP 2026-07-28, which have no session, one principal has in flight (subscription streams aside); more are refused ("request limit reached (64)") |
| `limits.streams_per_principal` | `16` | subscription streams (`subscriptions/listen`) of agents of MCP 2026-07-28 one principal has open; more are refused ("subscription stream limit reached (16)") |

A principal is a local user, or a remote token's issuer and subject.
Discovery instances do not count. Clients that never end their HTTP
sessions (Kit, chapter 5) leave them open until
`http.session_idle_timeout`; the session limit ends the idle ones
first, so such clients keep working. Refusals are audited (`mcp-limit`)
and counted (`mcp_gateway_limit_refusals_total`).

### Pseudonyms

```yaml
pseudonymize:
  vault_idle: 1h
```

| Key | Default | Meaning |
|---|---|---|
| `pseudonymize.vault_idle` | `1h` | agents of MCP 2026-07-28 have no session: their pseudonyms (obligation `pseudonymize`, chapter 6) belong to the user and endpoint and are dropped this long after the user's last request there; at least `1m`. Legacy sessions keep theirs until they end |

### Protocol versions per client

```yaml
agents:
  max_version:
    kit: "2025-11-25"
  no_request_timeout: [kit]
```

| Key | Default | Meaning |
|---|---|---|
| `agents.max_version` | `{kit: "2025-11-25"}` | the newest MCP version the gateway speaks with a client, by the name the client gives (`clientInfo.name`, case-insensitive): one of `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, `2026-07-28`. A client capped below 2026-07-28 is answered as by a gateway without it and uses the `initialize` handshake (chapter 5). Setting the key replaces the default; `{}` caps no client. The name is the client's own claim: it chooses the protocol, never what is allowed |
| `agents.no_request_timeout` | `[kit]` | clients, by name (case-insensitive), that have no request timeout of their own: on MCP 2026-07-28 a round of an approval or a sign-in waits for them until it is decided (up to `approval_timeout`, `sign_in.timeout`) instead of `approvals.retry_wait`. Setting the key replaces the default; `[]` names none. Like `max_version`, it chooses how long a round waits, never what is allowed |

Kit is capped because mcp-go 1.1 gives up on a call after three
answers in a row that ask for nothing, so on 2026-07-28 an approval
that takes longer than about 75 s ends for it; with the handshake the
call waits up to `approval_timeout` (chapter 5). With the cap removed,
`no_request_timeout` keeps Kit's approvals that long on 2026-07-28 too:
a round waits until the decision, so Kit never sees three rounds that
ask for nothing.

### Remote access (HTTPS)

Off unless `http.listen` is set. Chapter 5 walks through a setup.

```yaml
http:
  listen: ":8443"
  cert_file: /etc/mcp-gateway/tls/cert.pem
  key_file: /etc/mcp-gateway/tls/key.pem
  issuer: https://idp.example.com/realms/mcp
  audience: https://gw.example.com:8443/mcp
  jwks_url: ""
  groups_claim: groups
  local_user_claim: preferred_username
  scopes: [mcp]
  allowed_origins: []
  session_idle_timeout: 30m
  client_ca_file: ""
  client_auth: none
  require_bound_tokens: false
```

| Key | Default | Meaning |
|---|---|---|
| `http.listen` | empty (off) | address to listen on, e.g. `:8443` |
| `http.cert_file`, `http.key_file` | — (required) | TLS certificate and key (PEM) |
| `http.issuer` | — (required) | the identity provider's issuer URL; tokens must carry it as `iss` |
| `http.audience` | — (required) | the gateway's public MCP URL; tokens must carry it as `aud` (RFC 8707). Its path is the aggregated endpoint (`/mcp`), `<path>/<server>` the per-server endpoints. |
| `http.jwks_url` | discovered | the issuer's key set; default from `<issuer>/.well-known/openid-configuration` |
| `http.groups_claim` | `groups` | token claim holding the user's groups |
| `http.local_user_claim` | empty | token claim naming a local account (e.g. `preferred_username`); if the account exists, the remote user **is** that local user (uid, home, groups). Otherwise MCP servers run as a throwaway dynamic user. |
| `http.scopes` | `[]` | scopes every token must carry |
| `http.allowed_origins` | `[]` | `Origin` values accepted from browser clients; requests with another `Origin` are refused, requests without are accepted |
| `http.session_idle_timeout` | `30m` | close MCP sessions without traffic |
| `http.list_ttl` | `1m` | how long agents of MCP 2026-07-28 may use a list before asking again (`ttlMs`, on every transport); for a while after a policy or definition change, lists say 0 |
| `http.client_ca_file` | empty | CAs client certificates must chain to (mTLS) |
| `http.client_auth` | `none` (`optional` with a CA file) | `none`, `optional` (verify a certificate if presented), `required` |
| `http.require_bound_tokens` | `false` | accept only tokens bound to the client certificate (RFC 8705) |

### Signing in to servers

```yaml
sign_in:
  timeout: 10m
```

Servers defined with `sign_in` (chapter 4, "Signing in for each user")
send users to their authorization server and back to
`<origin of http.audience>/oauth/callback`, so they need the HTTP
listener above, reachable from the users' browsers.

| Key | Default | Meaning |
|---|---|---|
| `sign_in.timeout` | `10m` | how long a sign-in may take, from the link to the callback; the call that started it waits as long |

## Validating

```bash
mcp-gateway --check                              # /etc, else /usr/etc, else built-in defaults
mcp-gateway --check --config /tmp/gateway.yaml   # a specific file
```

`--check` loads the configuration, all MCP server definitions and the
role data, and reports the first problem with file and key, e.g.
`/etc/mcp-gateway/servers.d/git.yaml: selinux_type: "git_t" must match ^mcpsrv_[a-z0-9_]+_t$`.
