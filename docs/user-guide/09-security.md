# 9. Security

What the gateway protects against and how: trust, SELinux and MCS,
the sandbox, secrets, fail-closed behaviour and the audit trail, with a
hardening checklist at the end.

## Threat model

| Party | Trusted? | Consequence |
|---|---|---|
| the **agent** (LLM, its client) | no | may be manipulated by prompt injection; sees only permitted tools; cannot answer high-trust approvals; its self-reported name is informational only |
| **MCP servers** | no | may be buggy or malicious; run confined, cannot reach the gateway, OPA, other users' instances or secrets they were not given |
| **the user** | as far as their account goes | decides on their own approvals unless policy says otherwise |
| **administrators** | yes | maintain policy, server definitions and keys |

Layers, from outside in:

1. **Authentication**: kernel peer credentials locally; validated OAuth
   tokens (and optionally client certificates) remotely.
2. **Authorization**: OPA, fail-closed (no answer = deny).
3. **Human approval** for what policy marks sensitive.
4. **Obligations**: redaction, output limits, rate limits, argument
   constraints.
5. **Confinement** of each MCP server instance: account, systemd
   sandbox, SELinux domain, MCS categories.
6. **Audit**: journal and kernel audit log.

## SELinux

With `mcp-gateway-selinux`, the gateway, OPA and MCP servers run in
their own domains:

| Domain | Runs | May |
|---|---|---|
| `mcpgw_t` | the gateway | read its configuration, write its state, serve its sockets, bind `mcp_port_t` and `mcp_metrics_port_t`, ask systemd over D-Bus to start `mcp-*` units, talk to OPA; mail with `mcpgw_can_send_mail` |
| `mcpopa_t` | OPA | read the policy, serve its socket; network only with `mcpopa_can_network` |
| `mcpsrv_generic_t` | MCP servers without `selinux_type` | stdio, libraries, `/etc`, syslog |
| `mcpsrv_fs_t` | the file server (`mcp-server-fs`) | additionally user home content (read/write) |
| `mcpsrv_docs_t` | the documentation server `gateway-docs` | read `/usr`, nothing of the users' |
| `mcpsrv_exec_t` | the command server `exec` | run the allowed commands; read system state |
| `mcpsrv_http_t` | servers defined with `url` (`mcp-http-connector`) | connect to HTTP ports (any port with `mcpsrv_http_connect_any`), of the server's addresses only (`IPAddressAllow=`); read the CA certificates |
| `mcpsrv_admin_t` | the diagnostics server `gateway-admin` | read the configuration, state, journal, audit log and file labels; change nothing |
| `mcpsrv_systemd_t`, `mcpsrv_firewalld_t`, `mcpsrv_zypp_t`, `mcpsrv_suseconnect_t`, `mcpsrv_snapper_t` | the system management servers (chapter 13) | talk to their system service over D-Bus |
| `mcpsrv_<name>_t` | your servers (chapter 4) | what the module grants |

Isolation rules for every server domain: no access to the gateway's and
OPA's sockets, configuration, state or keys (of the servers, only
`gateway-admin` and, for its `exec.d`, the command server `exec` read
`/etc/mcp-gateway`; none may write it); no reading of
`/etc/mcp-gateway/credentials` (`mcpgw_cred_t`, systemd reads it for
them). Neither the gateway nor OPA may read the bundle signing key
(`mcpgw_signing_key_t`).

Which user domains may connect: `unconfined_t`, `staff_t` and `user_t`
may use the MCP socket and the control socket. An agent running in
another confined domain (for example in a container) needs a local
module with `mcp_gateway_client(<domain>)` (and
`mcp_gateway_control_client(<domain>)` for the control API).

Check for denials after changes:

```bash
ausearch -m AVC,USER_AVC -ts recent | grep -E 'mcpgw|mcpopa|mcpsrv'
```

## MCS: separating instances

Instances of different principals may run as the same account
(`run_as: <account>`) and always share the server's SELinux domain. Each instance
therefore gets a unique **MCS category pair** from `supervisor.mcs_range`
(default `c768.c1023`), for example `s0:c801,c942`. SELinux denies
access between processes and files of different pairs, whatever the
Unix permissions say.

The same mechanism (sVirt) separates virtual machines (libvirt) and
containers (podman). To keep them from picking the same pair:

- **libvirt**: restrict it to the categories below the gateway's range
  with a drop-in:

  ```bash
  ps -eZ | grep -E 'virtqemud|libvirtd'        # which daemon runs?
  install -D -m0644 /usr/share/mcp-gateway/mcs/virtqemud.conf \
          /etc/systemd/system/virtqemud.service.d/mcs.conf     # or libvirtd.conf → libvirtd.service.d
  systemctl daemon-reload && systemctl restart virtqemud.service
  ```

  The drop-ins set the range `c0.c767`; adjust them if you change
  `mcs_range`. Until then the gateway warns at start: "libvirt picks MCS
  categories from the gateway's range; confine it with a drop-in from
  /usr/share/mcp-gateway/mcs".
- **podman** and other container engines pick pairs from the whole
  range and cannot be restricted per engine. With `supervisor.mcs_avoid:
  auto` (the default) the gateway skips pairs held by running processes
  and checks every 2 s; if a container later takes an instance's pair,
  the instance is stopped (the next call starts a new one with a fresh
  pair) and a `mcp-mcs-collision` audit event is written.

## Sandboxing

Each instance is a transient systemd service with a strict sandbox
(chapter 4, "What an instance gets"): no new privileges, read-only file
system, home read-only by default, private `/tmp` and `/dev`, no
capabilities, `@system-service` system calls, no network unless
`network: true`, memory, task and runtime limits.

Account choices, from most to least isolated:

- `run_as: dynamic`: a throwaway account per instance, no home;
- `run_as: principal` for remote principals without a local account:
  also a throwaway account;
- `run_as: principal` for local users: the user's own account (needed
  to work on their files), confined by the sandbox and the domain;
- `run_as: <account>`: a fixed service account shared by all instances,
  separated only by MCS.

With `landlock` in a definition (chapter 4, "Landlock"), the kernel
also bounds each instance to its trees: the shipped `fs` reaches its
user's home and nothing else of `/home`, so a file another user made
world-readable stays out of reach, which neither SELinux (home files
share a type and carry no MCS categories) nor the sandbox (`ProtectHome`
shows all of `/home`) prevents. Landlock binds root too and cannot be
lifted by the server; it adds to the domain and the sandbox, it does
not replace them. The gateway's own programs (`mcp-server-fs`,
`mcp-server-exec`, `mcp-http-connector`, `mcp-oauth-helper`) restrict
themselves at startup in any case, to their directories, the trees
their commands name, or their credentials and the ports they reach.

`supervisor.mode: exec` disables the sandbox and SELinux confinement
(`landlock` still applies, and our own programs still restrict
themselves); the gateway logs a warning. Use it for
development only.

## Secrets

- MCP server credentials: `credentials:` in the definition, delivered by
  systemd, never readable by the gateway (chapter 4). For a server
  defined with `url`, the connector puts them into headers
  (`${CREDENTIAL:name}`); they are sent to that server only, over TLS
  unless it is on the local host. Through a proxy (`proxy`), the TLS
  connection still ends at the server, and the proxy gets only
  `proxy_headers`.
- Users' tokens for servers with `sign_in` (chapter 4): kept by the
  gateway in `/var/lib/mcp-gateway/tokens` (`mcpgw_token_t`), encrypted
  with a key only the gateway reads, each bound to its user and server;
  an instance gets its user's access token for its own server from
  systemd, never the refresh token; the agent never sees a token. The
  sign-in link goes only to the user's client or their own Cockpit
  view, and is valid once, for `sign_in.timeout`: a user who forwards it
  lets someone else bind their account at the server to the user.
- The OAuth tokens of remote agents are validated and not passed on to
  MCP servers.
- TLS keys, the SMTP password and the audit key are readable by the
  gateway only.
- The bundle signing key is readable by root only, and better kept off
  the host (chapter 6).

## Parameters servers read differently

The gateway decides on a call's parameters as it decodes them, with
exact keys. An MCP server may decode them differently: Go servers match
struct fields case-insensitively and keep the last of several matches,
other parsers keep the first. With `{"path": "/home/alice/x", "Path":
"/etc/shadow"}` policy would check one path and the server open the
other. The gateway therefore refuses, with `invalid params`:

- objects (at any depth) with a repeated key, or with keys that differ
  only in case;
- keys that differ only in case from one the gateway reads (`name`,
  `arguments`, `uri`, `ref`, `_meta`, …);
- arguments whose name differs only in case from an argument the tool
  (its `inputSchema`) or prompt declares.

No MCP client sends such requests on purpose.

## Paths and symbolic links

Permissions with `args` conditions and `arg_constraints` check a path
as a string: `/home/alice/notes/x` matches `/home/alice/**` even if
`notes` is a symbolic link to `/etc`. The gateway cannot resolve the
link itself (it does not see the server's file system, and the link
may change between the decision and the call). Confinement does the
rest: SELinux and the sandbox limit what the server can reach at all,
and a server that serves a directory should open paths beneath it so
that links cannot lead out (Go's `os.Root`, Linux's `openat2` with
`RESOLVE_BENEATH`; chapter 4). The file server `mcp-server-fs` does so.
With `landlock`, the kernel enforces the trees whatever the server does
with links.
Decision D13 in the architecture document has the reasoning.

## Revoked access and running calls

Policy and grants are checked when a call starts. A change to the role
data, a revoked grant or an expiring one applies to the next call, not
to one already forwarded to the server (decision D12); to stop a
running call, cancel it or stop the instance (Cockpit, Servers tab).
Notifications that hand out data later are decided again as they
arrive: an update to a subscribed resource reaches the agent only if
the agent may still subscribe to that resource.

## Fail-closed behaviour

| Situation | Result |
|---|---|
| OPA not running, slow (`policy.timeout`) or answering invalid data | every request denied ("policy evaluation failed") |
| signed bundle missing, unsigned or tampered | OPA does not start; everything denied |
| an obligation cannot be enforced (invalid pattern) | call denied |
| no usable approval channel | call denied |
| approval times out | call denied |
| an instance cannot be started | call fails; restarts back off |
| `audit.kernel: on` and no kernel audit | the gateway does not start |

## Audit trail

### Gateway records (journal)

Every decision is one JSON line in the gateway's journal:

```bash
journalctl -u mcp-gateway.service -o cat | grep '"audit":true' | jq
```

```json
{"time":"2026-09-27T10:12:03.51Z","level":"INFO","msg":"mcp","audit":true,
 "session":"4f1c…","sub":"alice","action":"tools.call","server":"fs",
 "effect":"allow","name":"write_file","reason":"approved","grant":"g-5d0e…",
 "decision_id":"8c2b…","args_hmac":"93a1…"}
```

Arguments are recorded as an HMAC-SHA256 digest keyed with
`/var/lib/mcp-gateway/audit.key`: equal arguments give equal digests, so
records can be compared, but the values cannot be guessed from the log
without the key. With the obligation `audit: "full"` they are recorded
verbatim (`args`).

Security events (approvals, revocations, policy changes, MCS
collisions) are records with `event` and `ok` fields. Chapter 11 lists
all fields.

### Kernel audit

Denials and security events also go to the kernel audit subsystem as
`TRUSTED_APP` records (type 1121), next to SELinux AVC denials:

```bash
ausearch -m TRUSTED_APP -ts today -i | grep 'op=mcp-'
```

```
type=TRUSTED_APP … msg='op=mcp-decision session=4f1c… principal=alice action=tools.call
  server=fs target=delete_file reason="denied by policy" decision_id=8c2b… res=failed'
```

Operations: `mcp-gateway-start`, `mcp-decision` (denials),
`mcp-approval`, `mcp-grant-revoke`, `mcp-policy-change`, `mcp-config-reload`,
`mcp-mcs-collision`, `mcp-limit`, `mcp-token-expired`. `audit.kernel: auto` uses the kernel audit log when
it is available; `on` makes it mandatory.

### OPA decision log

`mcp-opa.service` logs every decision (input and result) to its journal:

```bash
journalctl -u mcp-opa.service -o cat | jq 'select(.msg == "Decision Log")'
```

Tool arguments are masked (`mcp/log.rego`) unless the decision asked
for a full audit. The `decision_id` of a gateway record appears in the
decision log's input (`input.context.decision_id`), linking the two.

#### Shipping decision logs to a collector

Where OPA's decision logs are already collected centrally (for
Kubernetes admission or Envoy authorization, say), the gateway's
decisions can go to the same place, through OPA's decision-log service.
OPA sends batches of decisions, gzip-compressed JSON, with `POST` to
`<url>/logs`; the collector sees what the journal gets, masked the same
way.

```bash
cp /usr/share/mcp-gateway/opa/decision-logs.yaml.example /etc/mcp-gateway/opa-config.yaml
vi /etc/mcp-gateway/opa-config.yaml          # the collector's URL, credentials
install -D -m 0644 /usr/share/mcp-gateway/opa/decision-logs.conf \
    /etc/systemd/system/mcp-opa.service.d/decision-logs.conf
setsebool -P mcpopa_can_network on           # OPA may connect to HTTP(S) ports
systemctl daemon-reload && systemctl restart mcp-opa.service
```

- The drop-in works with every policy mode (chapter 6): it adds the
  configuration file through `OPA_EXTRA_ARGS` and lifts OPA's network
  isolation. With a bundle server, OPA already reads
  `/etc/mcp-gateway/opa-config.yaml`: add the `decision_logs` part (and
  its service) to that file.
- A token for the collector goes in a file only OPA can read, such as
  `/etc/mcp-gateway/opa-logs.token` (`install -m 0600 -o mcp-opa`), not
  in `/etc/mcp-gateway/credentials/`, which OPA may not read.
- The collector must be on a port labelled `http_port_t` (80, 443 and
  others; `semanage port -l | grep http_port_t`).
- While the collector is unreachable, OPA buffers decisions up to
  `buffer_size_limit_bytes` and then drops the oldest. The journal copy
  (`console: true`) remains, so forward that as well if every decision
  must be kept.

Forward both journals to your log management; keep `audit.key` to
compare digests later.

## Data sent to external models

Agents pass what MCP servers return to their model. Where that model is
an external service, the obligation `pseudonymize` replaces personal or
confidential values by per-session pseudonyms before the agent sees them,
and `reidentify` gives chosen tools the real values back (chapter 6,
"Pseudonymization"). The mapping stays in the gateway's memory for the
session only, and the audit trail records classes and counts, never
values. The gateway covers only data that flows through it from MCP
servers; detection is rule-based and pseudonymized data is still
personal data under the GDPR.

## Hardening checklist

- [ ] SELinux enforcing, `mcp-gateway-selinux` installed, no AVC denials
      in normal use.
- [ ] Only the intended users in `mcp-users`.
- [ ] Role bindings reviewed; the shipped `dev`/`wheel` bindings adapted.
- [ ] Destructive tools denied or approval-gated; approvals on `url` or
      `oob`, not `form`; `self` removed from approver rules of high-risk
      servers.
- [ ] Each server with its own `selinux_type`, `network: false` unless
      needed, `protect_home: read-only` or `yes` unless needed,
      `run_as: dynamic` where it need not act as the user; `landlock`
      with the trees it works on, `required: true` where the kernel
      must apply it.
- [ ] Secrets only through `credentials:`, never in `command` or `env`.
- [ ] Servers returning personal or confidential data pseudonymized for
      agents that use external models; `reidentify` only on the tools
      and arguments that need real values.
- [ ] libvirt MCS drop-in installed on virtualization hosts.
- [ ] Remote access: `http.scopes` set, token lifetimes short in the
      IdP, mTLS with bound tokens for agent machines, `allowed_origins`
      minimal, the port opened only where needed.
- [ ] Signed policy bundles, with the key off the host.
- [ ] Journals forwarded; `audit.kernel: on` where required.
- [ ] `/var/lib/mcp-gateway` backed up (grants, audit key).
