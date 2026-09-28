# mcp-gateway — Architecture

Status: **Draft** — decisions D1–D7 accepted (2026-09-27)
Scope: design of a policy-enforcing proxy that exposes local stdio-only MCP
servers on a Linux host to local and remote MCP clients.

---

## 1. Problem statement

A Linux host has several MCP servers installed that speak MCP **only over
stdio**. Clients (AI agents such as Kit, Claude Code, IDE integrations)
should be able to use them:

- **locally** — processes on the same host, running as various Unix users;
- **remotely** — agents on other hosts, over the network.

Access must be governed. The gateway shall

1. provide **access control / RBAC**,
2. provide means for **permission elicitation** (asking a human to approve an
   action),
3. integrate **OPA** as the policy engine,
4. use **SELinux** for OS-level confinement.

## 2. Goals and non-goals

### Goals

- Single, auditable entry point to all MCP servers on the host.
- MCP-aware enforcement: decisions on method, server, tool/resource/prompt
  *and arguments*, not just on "may connect".
- Least privilege at discovery time: principals only *see* the tools they
  may use.
- Human-in-the-loop approval for sensitive operations, with approvals that
  cannot be forged by the agent being governed.
- Defence in depth: a compromised MCP server, or a bug in the policy, must
  still be contained by the kernel (SELinux, cgroups, namespaces, DAC).
- No modification of the existing MCP servers.
- Operable with standard Linux tooling: systemd, journald, auditd, RPM
  (openSUSE/SLES packages built with OBS).

### Non-goals (for now)

- Proxying MCP servers that already speak HTTP (possible later, same
  pipeline).
- Being an identity provider. The gateway consumes identities from the
  kernel (local) or an external OIDC IdP (remote).
- Content-level safety filtering of tool output (prompt-injection
  detection etc.). The design leaves a hook for it (obligations, §6.4).
- High availability / multi-host clustering. One gateway per host.

## 3. Terminology

| Term | Meaning |
|---|---|
| **Backend** | An MCP server on the host, spoken to over stdio. |
| **Instance** | A running process of a backend, bound to one principal/session. |
| **Client** | An MCP client connecting to the gateway. |
| **Principal** | The authenticated identity on whose behalf a client acts. |
| **PEP** | Policy Enforcement Point — code in the gateway that applies decisions. |
| **PDP** | Policy Decision Point — OPA. |
| **Grant** | A recorded human approval, with scope and expiry. |
| **Obligation** | An extra condition attached to an `allow` (redaction, limits…). |

## 4. Architecture overview

```
             LOCAL CLIENTS                          REMOTE CLIENTS
   (Kit, Claude Code, IDEs as user X)        (agents on other hosts)
        │ stdio shim   │ unix socket                │ HTTPS (MCP Streamable HTTP)
        │ (mcp-connect)│ SO_PEERCRED + SO_PEERSEC   │ OAuth 2.1 bearer / mTLS
        ▼              ▼                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  mcp-gateway  (SELinux domain: mcpgw_t)                              │
│                                                                      │
│  ┌────────────┐   ┌──────────────────┐   ┌─────────────────────────┐ │
│  │ Transport  │──▶│ AuthN / Identity │──▶│ MCP Protocol Router     │ │
│  │ adapters   │   │ → Principal      │   │ - JSON-RPC parsing      │ │
│  └────────────┘   └──────────────────┘   │ - namespacing srv__tool │ │
│                                          │ - list filtering        │ │
│                                          │ - session management    │ │
│                                          └──────────┬──────────────┘ │
│   ┌─────────────────────┐   input / decision        │                │
│   │ PEP                 │◀──────────────────────────┘                │
│   │ allow / deny / ask /│──────┐                                     │
│   │ allow+obligations   │      │ unix socket (or embedded library)  │
│   └────────┬────────────┘      ▼                                     │
│            │ ask       ┌───────────────┐  bundles  ┌───────────────┐ │
│            ▼           │ OPA (PDP)     │◀──────────│ Policy repo / │ │
│   ┌─────────────────┐  │ mcpopa_t      │           │ Cockpit admin │ │
│   │ Approval broker │  └──────┬────────┘           └───────────────┘ │
│   │ (elicitation)   │         │ decision logs                        │
│   └────────┬────────┘         ▼                                      │
│            │           ┌──────────────────────────┐                  │
│            │           │ Audit (journald/auditd)  │                  │
│            │           └──────────────────────────┘                  │
│   ┌────────▼───────────────────────────────────────────────────┐     │
│   │ Instance supervisor: spawns/reaps backends via systemd     │     │
│   └────────┬──────────────────┬──────────────────┬─────────────┘     │
└────────────┼──────────────────┼──────────────────┼───────────────────┘
             │ stdio pipes      │                  │
     ┌───────▼──────┐   ┌───────▼──────┐   ┌───────▼──────┐
     │ mcp-fs       │   │ mcp-git      │   │ mcp-db       │
     │ mcpsrv_fs_t  │   │ mcpsrv_git_t │   │ mcpsrv_db_t  │
     │ :s0:c12,c40  │   │ :s0:c12,c40  │   │ :s0:c7,c99   │  ← MCS pair per session
     └──────────────┘   └──────────────┘   └──────────────┘
```

**Central design decision:** the gateway is a *protocol-aware* MCP proxy,
not a byte-level stdio↔socket bridge. It terminates the client's MCP
session, inspects every JSON-RPC message, and opens its own MCP sessions to
backend instances. RBAC, OPA decisions and elicitation all require
knowledge of method, target and arguments; a transparent pipe cannot offer
that.

**Separation of concerns between OPA and SELinux:**

| Layer | Question answered | Enforced by |
|---|---|---|
| OPA | *Should* principal P be allowed to call tool T with args A now? | Gateway (PEP) |
| SELinux | *Can* this process touch this file / socket / port at all? | Kernel |

OPA governs MCP semantics; SELinux bounds what any backend process can do
regardless of what OPA said, and protects the gateway and OPA from their
own backends.

## 5. Components

### 5.1 Transport adapters

| Adapter | Used by | Authentication |
|---|---|---|
| **Unix socket** `/run/mcp-gateway/mcp.sock` | local clients | kernel: `SO_PEERCRED` (uid/gid/pid), `SO_PEERSEC` (SELinux label) |
| **stdio shim** `mcp-connect` | local clients that can only spawn a command | as unix socket (the shim connects to it) |
| **Streamable HTTP** `https://host:8443/mcp` | remote clients | OAuth 2.1 bearer token (JWT from external IdP); optional mTLS |

- The unix socket is `0660` with a dedicated group (`mcp-users`); the
  socket file is labelled `mcpgw_sock_t` so SELinux decides which client
  domains may `connectto` it.
- `mcp-connect` is deliberately dumb: it copies bytes between its stdio and
  the socket. Usage in a client config:
  ```json
  { "command": "mcp-connect", "args": ["--server", "git"] }
  ```
  To select a backend it first sends a JSON-RPC notification on the
  socket, then the client's MCP traffic:
  ```json
  {"jsonrpc":"2.0","method":"mcp-gateway/hello","params":{"version":1,"server":"git"}}
  ```
  A connection whose first message is an MCP message instead (as with
  `--server all`, the default) wants the aggregated endpoint.
- HTTP follows the MCP authorization specification: the gateway is an
  OAuth **resource server**, publishes Protected Resource Metadata
  (RFC 9728) pointing at the configured authorization server, validates
  audience (RFC 8707 resource indicator = gateway URL), issuer, expiry and
  signature. The gateway never issues tokens itself.
  - Keys come from the issuer's JWKS (found by OIDC discovery, or
    configured), cached for an hour and refreshed on an unknown key id at
    most every 30 s. Only asymmetric algorithms are accepted (no `none`,
    no HMAC key confusion); RSA keys below 2048 bits are ignored.
    Required scopes are configurable.
  - Every request carries the token and is validated; the metadata lives
    at `/.well-known/oauth-protected-resource<path>` and every `401`
    points to it.
- **mTLS (optional):** with `http.client_ca_file`, the TLS layer verifies
  client certificates against those CAs; `http.client_auth` is
  `optional` (the default then: a certificate is verified if presented)
  or `required` (no handshake without one). A client certificate does not
  replace the token; it adds:
  - **certificate-bound tokens (RFC 8705):** a token with a
    `cnf.x5t#S256` confirmation is accepted only over a connection with
    that certificate, so a stolen token is useless without the client's
    key. `http.require_bound_tokens` refuses unbound tokens; the metadata
    announces `tls_client_certificate_bound_access_tokens`.
  - **policy input:** the certificate's subject, SANs and thumbprint are
    `input.principal.cert`; permissions with `"require_client_cert":
    true` apply only to clients that presented one (§6.4).
  - a session is bound to the certificate as well as to the subject.

  TLS must terminate at the gateway for this; a reverse proxy in front
  would hide the client certificate.
- Streamable HTTP details: the resource URL's path (e.g. `/mcp`) is the
  aggregated endpoint, `<path>/<server>` the per-server ones. `POST`
  carries one client message (no batches); requests are answered as JSON
  or, if the client accepts it, as an SSE stream that also carries the
  server's requests and notifications for that request (e.g. an approval
  elicitation) and ends with the response. `GET` opens the session's
  stream for everything else; messages with no open stream are queued
  (bounded). `DELETE` ends the session.
  **Resumability:** every SSE event carries an id `<stream>-<seq>`, and
  each stream keeps its last 256 events, also while no connection is
  attached; a stream starts with a priming event (id, no data). A request
  stream whose connection broke keeps receiving its messages up to the
  response, and can be resumed for 5 minutes after it. The client resumes
  a stream with `GET` and `Last-Event-ID`: the events after that id are
  replayed, then the stream goes on (a request stream ends with its
  response); events of other streams are never replayed. A resumption
  replaces a connection the server still considers attached. Unknown or
  expired ids get `400`. `initialize` creates the
  session and returns `Mcp-Session-Id`; a session is bound to its
  principal (issuer + subject, and client certificate if any), and
  requests from anyone else get `404`.
  Sessions without traffic are closed after `http.session_idle_timeout`.
  Browser `Origin`s must be allow-listed (DNS rebinding).
- Transports hand the router a message connection
  (`jsonrpc.MessageConn`) plus the authenticated principal.

### 5.2 Identity → Principal

All identity evidence is normalised into one `Principal`, which is exactly
what policy sees as `input.principal`:

```json
{
  "sub": "alice",
  "uid": 1001,
  "groups": ["dev", "mcp-users"],
  "home": "/home/alice",
  "roles": ["developer"],
  "transport": "unix",
  "selinux": "staff_u:staff_r:staff_t:s0-s0:c0.c1023",
  "client": { "name": "kit", "version": "0.9.1" },
  "session_id": "3f0c…",
  "cert": { "subject": "CN=agent-1", "x5t#S256": "q3Zp…", "dns": ["agent-1.example.com"] }
}
```

(`cert` only for remote clients that presented a verified client
certificate; `uid`, `home` and `selinux` only for local principals and
mapped remote ones.)

- **Local:** `uid` → user name and groups via NSS (works with SSSD/IPA).
- **Remote:** `sub`, `iss` and `groups` (claim name configurable) from the
  token. With `http.local_user_claim` set (e.g. `preferred_username`) and
  a local account of that name, the principal becomes that account: its
  name as `sub`, its uid, home and groups (§9, D1). Otherwise backends run
  as a dynamic user, isolated by the instance's MCS pair.
- **Roles** are derived by policy data (`data.rbac.bindings`) from groups,
  users or claims — role assignment is itself policy, not code.
- `client` comes from the MCP `initialize` request (`clientInfo`); it is
  **self-asserted** and must only be used for convenience rules, never as a
  security boundary.

### 5.3 MCP protocol router

Responsibilities:

1. **Session handling.** Terminates the MCP `initialize` handshake with the
   client itself. The per-server endpoint mirrors the backend's
   capabilities and server info; the aggregated endpoint advertises the
   gateway's own. The gateway holds its *own* MCP session with every
   backend instance (it sends `initialize` as client `mcp-gateway`), opened
   lazily on first use, so an instance can serve several client sessions
   of the same principal (§5.7): request ids and progress tokens are
   remapped per instance, notifications are fanned out to the attached
   sessions, and a request the backend sends to "its client" goes to a
   session that has a request in flight on that instance (otherwise it is
   refused).
2. **Namespacing / aggregation.** Two endpoint styles (§9, D2):
   - *aggregated*: one virtual server; tools are exposed as
     `<server>__<tool>`, prompts as `<server>__<prompt>`, resource URIs and
     URI templates as `mcp+<server>:<original URI>` (e.g.
     `mcp+fs:file:///home/alice/a.txt`), also inside `resources/read`
     results and `notifications/resources/updated`; log messages get the
     server name as logger prefix;
   - *per-server*: one endpoint per backend, names unchanged.
   Lists from all backends are fetched in full (following cursors) and
   returned as one page. On the aggregated endpoint a backend that fails
   is left out of the list instead of failing it.
3. **Discovery filtering.** `tools/list`, `resources/list`,
   `resources/templates/list`, `prompts/list` responses are filtered per
   principal using a batch policy query (§6.3).
4. **Enforcement on invocation.** Every request in the table below goes
   through the PEP before being forwarded.
5. **Reverse-direction requests.** Requests that a *backend* sends to the
   client (`sampling/createMessage`, `elicitation/create`, `roots/list`) are
   also policy-checked and labelled with the originating backend.
6. **Change propagation.** Emits `notifications/tools/list_changed` (and
   the resources/prompts equivalents) to every session when OPA loads a
   changed policy or RBAC data. The gateway polls a fingerprint (a hash of
   OPA's `/v1/policies` and `/v1/data/rbac`) every `policy.watch_interval`
   (default 10 s) and advertises `listChanged` for all three lists.
   Grants do not change visibility (discovery shows items that need
   approval), so they trigger no notification. Backends' own
   `list_changed` notifications are passed through.
7. **Cancellation / progress.** Maps request IDs between client and backend
   sessions; forwards `notifications/cancelled` and progress tokens.

Enforced methods:

| Direction | Method | `input.action` |
|---|---|---|
| client → backend | `tools/call` | `tools.call` |
| client → backend | `resources/read`, `resources/subscribe`, `resources/unsubscribe` | `resources.read`, `resources.subscribe`, `resources.unsubscribe` |
| client → backend | `prompts/get` | `prompts.get` |
| client → backend | `completion/complete` | `completion.complete` |
| client → backend | `*/list` | batch filter (`data.mcp.filter.visible`) |
| backend → client | `sampling/createMessage` | `sampling.create` |
| backend → client | `elicitation/create` | `elicitation.create` |
| backend → client | `roots/list` | `roots.list` |

Unknown methods are **denied by default**.

### 5.4 Policy Enforcement Point (PEP)

- Builds the OPA input document (§6.2), queries OPA, and applies the
  decision:
  - `allow` → re-identify pseudonyms in the arguments the obligations name
    (and decide again on the real values), check the argument constraints
    and rate limits, forward, then apply redaction, pseudonymization and
    the output size limit to the result (§6.3);
  - `deny` → JSON-RPC error `-32001` ("Forbidden") with a policy-provided,
    non-sensitive `reason`; for `tools/call`, respond with a tool result
    `isError: true` so agents can reason about it;
  - `ask` → hand to the approval broker; re-query OPA after the outcome.
- **Fail closed:** OPA unreachable, timeout (default 250 ms), or malformed
  decision ⇒ `deny`.
- Decision cache keyed by the full input hash, TTL ≤ a few seconds, flushed
  on bundle activation or grant change. Only for list filtering; calls are
  always evaluated live.

### 5.5 OPA (Policy Decision Point)

- **Deployment:** sidecar `opa run --server` listening on a unix socket
  (`/run/mcp-gateway/opa.sock`), in its own SELinux domain `mcpopa_t`. The
  distribution's `/usr/bin/opa` is used; `mcp-opa.service` enters the
  domain with `SELinuxContext=` rather than relabelling a shared binary.
  Rationale: hot bundle reload, standard OPA tooling, process isolation,
  language neutrality. Embedding OPA as a Go library remains an option if
  latency requires it; the PEP talks to OPA through an interface so both
  are drop-in.
- **Policy distribution**, three modes, chosen by the `mcp-opa.service`
  unit (drop-ins in `/usr/share/mcp-gateway/opa/`):
  - **directories** (default): policy logic from the package in
    `/usr/share/mcp-gateway/policy/`, roles and bindings from the
    administrator in `/etc/mcp-gateway/policy/` (D4), reloaded on change
    (`--watch`). Unsigned; protected by file permissions and SELinux
    (`mcpgw_etc_t`).
  - **signed bundle file** (`signed-bundle.conf`): `mcp-policy-bundle -k
    <key>` builds a bundle from the same two sources, signs it (RS256),
    writes `/etc/mcp-gateway/bundle/policy.tar.gz` and restarts OPA,
    which verifies it against `/etc/mcp-gateway/bundle/verify.pem` and
    refuses to start with an unsigned or tampered bundle (the gateway
    then denies everything). The signing key is safest off the host,
    e.g. in CI, which builds bundles from the policy repository. For
    signing on the host (and from Cockpit, §5.10), `mcp-policy-bundle -G`
    creates the key pair: `/etc/mcp-gateway/bundle/signing.pem` (root,
    0600, `mcpgw_signing_key_t`, which the gateway, OPA and backends may
    never read) and `verify.pem` next to the bundle. Signing then protects
    against changes by anyone who can write the bundle or role data but
    is not root; root can always sign.
  - **bundle server** (`bundle-server.conf`, `opa-config.yaml.example`):
    OPA polls a bundle server and verifies every download (`signing`
    in its configuration); a bundle that does not verify is rejected and
    the active revision stays. Needs `setsebool -P mcpopa_can_network
    on`.

  Signed bundles are not combined with `--watch`: OPA (checked with 1.21)
  does not verify signatures when `--watch` reloads a bundle file, and a
  tampered bundle would be activated. Bundle files are read once at start
  instead, so a new revision needs a restart of `mcp-opa.service` (the
  gateway, which only `Wants=` OPA, keeps its sessions and denies
  requests for that second). The gateway logs the active revisions at
  start and records them in `mcp-policy-change` audit events.
- **Decision logs:** enabled, masked (`system.log.mask`) to strip argument
  values flagged as sensitive, shipped to the audit sink (§5.9).
- **Status API:** gateway polls OPA health; unhealthy ⇒ fail closed.

### 5.6 Approval broker (permission elicitation)

Two distinct flows with different trust properties.

#### 5.6.1 Gateway-initiated approvals (policy said `ask`)

The broker suspends the request and obtains a human decision via one of
these channels (configured per policy decision, `ask.channel`):

| Channel | Mechanism | Trust | Use for |
|---|---|---|---|
| `form` | MCP `elicitation/create` (form mode) sent to the client | **Low** — the client is the agent's host; a misconfigured or compromised client can auto-accept | low-risk confirmations, "are you sure?" |
| `url` | MCP URL-mode elicitation: client is asked to open an approval URL served by the gateway (Cockpit page); the human authenticates *there* | **High** — approval happens outside the agent's control, bound to a separately authenticated human | sensitive tools (default) |
| `oob` | Out-of-band: Cockpit "Approvals" inbox, desktop notification, push | **High** | unattended / remote agents, clients without elicitation support |

Behaviour:

- If the client did not advertise the required elicitation capability in
  `initialize`, the broker falls back to `oob`, or denies if the policy
  forbids fallback.
- Pending approvals have a timeout (default 120 s); timeout ⇒ `deny`.
- An approval produces a **grant**:
  ```json
  {
    "id": "g-8d1e…",
    "sub": "alice",
    "server": "fs",
    "tool": "write_file",
    "args_match": { "path": "/home/alice/project/**" },
    "scope": "session",            // once | session | duration
    "session_id": "3f0c…",
    "expires": "2026-09-28T10:00:00Z",
    "approved_by": "alice",
    "channel": "url"
  }
  ```
- Grants are kept by the broker and passed to OPA as `input.grants` (only
  those matching the principal, server and tool; session grants only in
  their session), and are revocable from Cockpit. `duration` grants
  (scopes like `"24h"`, at most 30 days) are persisted to
  `/var/lib/mcp-gateway/grants.json` (atomic writes, mode 0600, label
  `mcpgw_var_lib_t`) and apply across sessions and restarts; session
  grants live in memory.
- `scope: once` grants are valid only for the one re-evaluation after the
  approval and are not stored, except for approvals decided while no call
  was waiting (below).

**Pending approvals outlive their call.** `url` and `oob` approvals are
persisted to `/var/lib/mcp-gateway/pending.json` (atomic writes, mode
0600; it holds the arguments shown to approvers). If the waiting call goes
away before the decision (the client disconnects, the gateway shuts down
or restarts), the approval stays pending until it expires, marked as
having no waiting call (`"waiting": false` in the control API, a note on
the Cockpit page), and without the `session` scope, whose session is gone.
Then:

- deciding it stores the grant for the agent's next attempt: a duration
  grant as usual, a `once` grant as a stored one-time grant (valid for
  15 min) that the next matching call takes and uses up (it is put back if
  policy does not allow that call);
- an attempt with the same principal, target and arguments before the
  decision takes the approval over (same id, so an approval page already
  open stays valid; the policy's scopes apply again), instead of creating
  a second one;
- a timeout or a decline removes it, as for a waiting call.

`form` approvals are not persisted: they live in the client's dialog.

**How the `url` and `oob` channels work.** Both create a *pending
approval* with an unguessable id, visible through the control API
(§5.10). With `url`, the client receives a URL-mode `elicitation/create`
(MCP 2025-11-25: `mode: "url"`, `url`, `elicitationId`) pointing at the
approval page (`approvals.url_template`, e.g. the Cockpit page with
`#/approvals/{id}`); the client's answer only says whether the user agreed
to open it, and declining denies the call. The decision is made on the
page, and the gateway then sends `notifications/elicitation/complete`.
With `oob`, the client only gets a `notifications/message` that an
approval is pending; the request shows up in the inbox. Either way the
call waits until a decision or `approval_timeout`.

**Who may decide** is policy (`data.mcp.approvals`, rules in
`data.rbac.approvers`, §6.4); the gateway identifies the approver by the
control socket's peer credentials. The shipped rules allow the principal
themself, matched by local uid (the approval page runs as the logged-in
Cockpit user, so a local principal approves their own requests), and the
admin role. A remote principal without a local account has no uid, so
only role, group or user rules can approve its requests. The same rules
decide who sees and revokes a grant (grants record the principal's uid).
Root may always decide. If OPA fails, nobody else may. The page shows
the exact call: server, tool, arguments, principal, client, and the scopes
the policy offered; nothing else can be chosen.

#### 5.6.2 Backend-initiated elicitation

A backend may itself send `elicitation/create` to ask the user something.
The gateway:

1. checks `elicitation.create` policy for that backend (may it elicit at
   all, which modes);
2. prefixes the message with the backend's identity (the user must always
   know *who* asks) and never lets backend-originated requests use the
   gateway's own approval UI styling or URL namespace;
3. passes the request's mode, URL (URL mode), field names and a
   `sensitive` flag to policy as `input.args`. The flag is set when a
   field's name, title, description or format looks like a secret
   (password, token, secret, API or private key, credential, PIN, OTP,
   card number, …). A sensitive request is only covered by a permission
   with `"allow_sensitive": true`;
4. relays to the client and returns the answer to the backend.

#### 5.6.3 Push channels for out-of-band approvals

Approvers learn about pending approvals without watching the inbox:

- **Desktop:** `mcp-gateway-notify` (package `mcp-gateway-desktop`,
  started with graphical sessions by XDG autostart) follows `GET
  /v1/events` on the control socket as the logged-in user: the pending
  approvals that user may decide on (the approver policy filters the
  stream), then changes. It shows one notification per approval over
  `org.freedesktop.Notifications`, updates it when the call stops waiting
  and closes it when the approval is decided or times out. Its action
  opens the approval page (`approvals.url_template`, else the Cockpit
  page). Notifications deliberately offer no Approve button: any program
  in the user's session, the agent included, can talk to the session bus,
  while the approval page needs the human's own login. The agent is
  single-instance per session, accepts `ActionInvoked` only from the
  notification server, escapes markup, opens http(s) URLs only,
  reconnects after gateway restarts and exits for users without access to
  the control socket.
- **E-mail** (`notifications.email`): for each new approval, the gateway
  asks `data.mcp.approvals.notify` whom to tell: the approvers the
  server's rules name, as local users and groups (`self` is the
  principal's account, `role:<r>` the users and groups bound to it).
  Groups are expanded through NSS (`getent group`; members by primary
  group are not listed), users become addresses by the `to` template
  (`{user}` for local delivery, `{user}@example.com` otherwise), and one
  mail goes to all of them (`To: undisclosed-recipients:;`). The mail
  names the call and links the approval page; arguments are left out
  unless `include_args` is set, since mail may leave the host. SMTP with
  STARTTLS when offered (`starttls: auto|always|never`), optional
  PLAIN authentication (password from a file, e.g. a systemd
  credential). SELinux: `setsebool -P mcpgw_can_send_mail on`.

### 5.7 Instance supervisor

- **Instance model:** stdio backends are single-client and may keep state,
  so there is **one instance per (principal, backend)** by default, or one
  per *session* for backends marked `isolation: session`. Instances are
  never shared across principals. The key of a shared instance is
  (transport, subject, backend). After its last session ends an instance
  stays up for `supervisor.idle_timeout` (default 15 min) and is reused if
  the principal comes back; `isolation: session` instances stop with their
  session.
- **Spawning** via systemd transient units over D-Bus
  (`StartTransientUnit`), unit name `mcp-<backend>-<instanceid>.service`,
  with properties from the backend definition:
  ```ini
  User=alice                 # or DynamicUser=yes (§9, D1)
  SELinuxContext=system_u:system_r:mcpsrv_fs_t:s0:c12,c40
  NoNewPrivileges=yes
  ProtectSystem=strict
  ProtectHome=read-only      # relaxed per backend
  PrivateTmp=yes
  PrivateDevices=yes
  PrivateNetwork=yes         # unless backend needs network
  RestrictAddressFamilies=AF_UNIX
  ProtectKernelTunables=yes, ProtectKernelModules=yes, ProtectKernelLogs=yes
  ProtectControlGroups=yes, ProtectClock=yes, ProtectHostname=yes
  LockPersonality=yes, RestrictRealtime=yes, RestrictSUIDSGID=yes
  CapabilityBoundingSet=     # none
  SystemCallArchitectures=native
  SystemCallFilter=@system-service
  UMask=0077
  MemoryMax=512M
  TasksMax=64
  RuntimeMaxSec=8h
  LoadCredential=github-token:/etc/mcp-gateway/credentials/github-token
  ```
  `MemoryDenyWriteExecute=` is deliberately not set: it breaks JIT
  runtimes such as Node.js, which many MCP servers use.
  stdio is wired by passing one end of a gateway-owned socketpair to
  systemd through the transient-unit properties
  `StandardInputFileDescriptor` / `StandardOutputFileDescriptor`
  (stderr goes to the journal).
- **Lifecycle:** start on first use; idle timeout (default 15 min); stop on
  session end for `isolation: session`; crash ⇒ error to client, restart on
  next call. After an instance failed to start or exited on its own, the
  next start of the same instance (same principal or session and backend)
  waits 1 s, doubling with each further failure up to 2 min; calls in
  the meantime fail at once with "backend unavailable; retry in …". An
  instance that ran for a minute before failing starts the count afresh,
  and stops by the gateway (idle, session end) are not failures.
- **Credentials:** the gateway **never forwards client tokens** to
  backends (token passthrough is prohibited by the MCP authorization
  specification). Backend secrets come from systemd credentials.
- **Backend registry:** one YAML file per backend. Packages install
  theirs to `/usr/share/mcp-gateway/servers.d/`; files in
  `/etc/mcp-gateway/servers.d/` override those of the same name, and an
  empty file (or a symlink to `/dev/null`) disables one, like systemd
  units. Example:
  ```yaml
  name: fs
  command: ["/usr/libexec/mcp-servers/mcp-fs", "--root", "${HOME}"]
  selinux_type: mcpsrv_fs_t
  isolation: principal          # principal | session
  network: false
  run_as: principal             # principal | dynamic | <user>
  env: { LOG_LEVEL: info }
  credentials: []
  sandbox:
    protect_home: read-write
  ```

### 5.8 SELinux policy module (`mcp_gateway`)

Types:

| Type | Purpose |
|---|---|
| `mcpgw_t` / `mcpgw_exec_t` | gateway process / binary |
| `mcpgw_sock_t` | client unix socket |
| `mcpgw_ctl_sock_t` | internal control socket (Cockpit ↔ gateway) |
| `mcpopa_t` / `mcpopa_exec_t` | OPA sidecar |
| `mcpopa_sock_t` | OPA socket |
| `mcpgw_etc_t`, `mcpgw_var_lib_t`, `mcpgw_log_t` | config, state, logs |
| `mcpgw_cred_t` | backend secrets (`/etc/mcp-gateway/credentials`), read only by systemd |
| `mcpgw_signing_key_t` | policy bundle signing key on the host (`/etc/mcp-gateway/bundle/signing.pem`); `neverallow` for the gateway, OPA and backends |
| `mcpsrv_<name>_t` / `mcpsrv_<name>_exec_t` | per-backend domain / binary |
| `mcpsrv_generic_t` | fallback for backends without a dedicated type |
| `mcp_port_t` | gateway HTTPS port |

Key rules (sketch):

- `mcpgw_t` may: bind `mcp_port_t`, create/listen on `mcpgw_sock_t`,
  `connectto` `mcpopa_t` via `mcpopa_sock_t`, talk to systemd over D-Bus,
  read `mcpgw_etc_t`, manage `mcpgw_var_lib_t`. It may **not** read user
  home directories or exec backends directly (systemd does).
- `init_t` (systemd) may transition to `mcpsrv_*_t` only on the
  corresponding `mcpsrv_*_exec_t` (or via explicit `SELinuxContext=`),
  constrained by a `typebounds`/`neverallow` set so that no backend domain
  gains more than `mcpsrv_generic_t` plus its declared extras.
- `mcpsrv_*_t` may **not** `connectto` `mcpgw_sock_t`, `mcpgw_ctl_sock_t`
  or `mcpopa_sock_t` (`neverallow`). Backends cannot talk to, or tamper
  with, the policy path.
- Per-backend extras via interfaces, e.g.
  `mcp_backend_home_rw(mcpsrv_fs_t)`, `mcp_backend_net(mcpsrv_git_t, http_port_t)`.
- `mcpopa_t`: read its bundles, listen on its socket; no network unless a
  remote bundle server is configured (boolean `mcpopa_can_network`).

**MCS isolation per session** (sVirt-style): the supervisor allocates a
unique category pair per instance from `supervisor.mcs_range` (default
`c768.c1023`) and sets it in `SELinuxContext=`. Per-instance scratch
directories are labelled with the same pair. Two instances running as the
same Unix account (e.g. dynamic/service user for remote principals) thus
cannot access each other's processes or files.

**Coordination with libvirt and podman.** Both hand out random pairs as
well and know nothing about the gateway's. Type enforcement already keeps
`mcpsrv_*_t` apart from `svirt_t` and `container_t` and their files, so a
shared pair is not an access path by itself; coordination keeps MCS a
second, independent barrier:

- **libvirt** picks each machine's pair from the category range of its
  own daemon process (`virSecuritySELinuxMCSGetProcessRange` in
  `security_selinux.c`). The drop-ins in `/usr/share/mcp-gateway/mcs/`
  (`virtqemud.conf`, `libvirtd.conf`) start the daemon with
  `s0-s0:c0.c767`, so its machines never get a pair from the gateway's
  range. The gateway warns at start and every 30 s while a libvirt daemon's
  range overlaps its own.
- **podman** (go-selinux) picks from the whole range: go-selinux has
  `SetCategoryRange`, but podman (checked with v6.1.2) does not expose it,
  and it only avoids pairs of its own containers. With
  `supervisor.mcs_avoid: auto` (default) the gateway reads the contexts of
  running container and machine processes, skips their pairs when it
  allocates, and every 30 s stops an instance whose pair a container or
  machine started later holds too (logged and recorded as an
  `mcp-mcs-collision` audit event); its sessions get a new instance with a
  new pair on their next call. Containers given explicit levels
  (`--security-opt label=level:…`) should use categories below c768.

The policy lets the gateway read the process state of container, virtual
machine and libvirt domains only, not of all processes.

**Client label as policy input:** `SO_PEERSEC` delivers the client's
context; it is part of `input.principal.selinux`, allowing rules such as
"only `staff_t`/`unconfined_t` clients may use `db__*`" or "clients in a
sandbox domain get read-only tools". Client domains allowed to `connectto`
the socket are controlled by an interface `mcp_gateway_client(domain)`.

**Optional kernel-backed check:** a custom class
`mcp_tool { list call }` can be defined and checked via
`selinux_check_access(client_ctx, backend_ctx, "mcp_tool", "call")` as a
coarse, admin-controlled second opinion before OPA. This is off by default
and aimed at MLS-style deployments.

### 5.9 Audit

- Every enforced message produces a structured audit record (a JSON line
  with `"audit":true` on stderr, i.e. in the journal of
  `mcp-gateway.service`): session, principal, action, server, target,
  effect, reason, grant id, backend instance, `decision_id` and the
  arguments.
- Arguments are logged as `args_hmac`, an HMAC-SHA256 of their JSON
  encoding keyed with a per-installation key (`state_dir/audit.key`,
  created on first start, mode 0600), so digests can be compared with
  each other but not matched against guessed values without the key. The
  full values are logged only when the decision carries the obligation
  `audit: full`.
- Security-relevant events are also sent to the kernel audit subsystem as
  `AUDIT_TRUSTED_APP` records (`ausearch -m TRUSTED_APP`), next to the
  SELinux AVC records of the same host: denials (`op=mcp-decision`),
  approval decisions (`op=mcp-approval`, declines as `res=failed`), grant
  revocations (`op=mcp-grant-revoke`) and policy changes
  (`op=mcp-policy-change`). Values that are not plain tokens are
  hex-encoded, as auditd does for untrusted strings. This needs
  `CAP_AUDIT_WRITE` (granted by the unit as an ambient capability) and
  the SELinux permission `logging_send_audit_msgs`; `audit.kernel: auto`
  (default) uses it when available, `on` refuses to start without it.
- OPA logs every decision to its journal (`decision_logs.console`). The
  gateway puts a random `decision_id` into each policy input
  (`input.context.decision_id`) and into its audit record, which links
  the two. The mask policy `policy/system/log.rego` removes the arguments
  from OPA's log unless the decision asked for `audit: full`.

### 5.10 Cockpit integration

The gateway serves a small **control API** on
`/run/mcp-gateway/control.sock` (`mcpgw_ctl_sock_t`, same group as the MCP
socket), HTTP with JSON:

| Request | Meaning |
|---|---|
| `GET /v1/whoami` | the caller as the gateway sees them |
| `GET /v1/approvals`, `GET /v1/approvals/{id}` | pending approvals the caller may decide on |
| `POST /v1/approvals/{id}` `{"decision": "approve"\|"deny", "scope": "…"}` | decide |
| `GET /v1/grants`, `DELETE /v1/grants/{id}` | the caller's grants (all for admins); revoke |
| `GET /v1/servers` | the server registry (without command and environment) and the running instances the caller may manage |
| `DELETE /v1/instances/{id}` | stop an instance; its sessions get a new one on their next call |
| `GET /v1/policy` | policy mode (directories or bundle) and the active bundle revisions |
| `GET /v1/events` | server-sent events: the pending approvals the caller may decide on, then changes (§5.6.3) |

Callers are identified by the socket's peer credentials, so the API needs
no tokens: a Cockpit page reaches it with `cockpit.http({unix: …})` as the
logged-in user, who has authenticated to Cockpit, not to the agent.
Anything not the caller's is reported as not found. Who may see and stop
an instance is policy (`data.mcp.approvals.manage_instance`, the same
approver rules as for grants: by default the principal themself and the
admin role).

The Cockpit page ships in this repository (`cockpit/mcp-gateway`,
installed to `/usr/share/cockpit/mcp-gateway`), with four tabs:

- **Approvals:** pending approvals with their details and one button per
  offered scope plus Deny, and the grants list with Revoke. Approval links
  (`#/approvals/<id>`) highlight the request.
- **Servers:** the registry (SELinux domain, isolation, network, run as)
  and the running instances the user may manage, with their journal and
  Stop. Instances start on demand, so there is no Start.
- **Policy:** the policy mode and bundle revisions; role bindings (add or
  remove roles of users and groups), roles with their permissions,
  approver rules, and the whole role data as JSON. Edits are validated
  (structure, bindings to unknown roles) and written to
  `/etc/mcp-gateway/policy/rbac/data.json` with Cockpit's administrative
  access; OPA reloads it by itself. With a signed bundle file and the
  signing key on the host, **Sign and apply** runs `mcp-policy-bundle`
  as root, which signs a new bundle with the revision
  `cockpit-<user>-<time>` (recorded in the gateway's policy change audit
  event) and restarts OPA. Without the key the page explains how to
  create one; with a bundle server, changes must go into the bundle
  published there.
- **Audit:** the gateway's audit records from the journal (`journalctl
  -u mcp-gateway.service`, which needs journal access), newest first,
  filtered by kind (denials, allowed calls, events) and text.

`cockpit/test/smoke.js` checks the page in headless Chrome against a stub
of `cockpit.js` (CI job `cockpit`). Policy tests (`opa test`) are not run
from the page: the Rego tests are not installed.

## 6. Policy model

### 6.1 Packages

```
policy/
  mcp/authz.rego          # main decision: data.mcp.authz.decision
  mcp/filter.rego         # batch visibility for */list
  mcp/elicitation.rego    # rules for backend-initiated elicitation
  mcp/lib/*.rego          # helpers (arg matching, time windows)
  mcp/*_test.rego         # policy tests (opa test)
  system/log.rego         # masking for OPA's decision log
  rbac/data.json          # data.rbac: roles, permissions, bindings, approvers
```

### 6.2 Input document

```json
{
  "principal": { "...": "see §5.2" },
  "action": "tools.call",
  "resource": {
    "server": "fs",
    "kind": "tool",
    "name": "write_file",
    "annotations": { "destructiveHint": true, "readOnlyHint": false }
  },
  "args": { "path": "/home/alice/project/x.txt", "content": "…" },
  "grants": [ { "...": "see §5.6.1" } ],
  "context": {
    "time": "2026-09-27T14:03:11Z",
    "transport": "unix",
    "request_id": "42",
    "decision_id": "5f0c…",
    "client_capabilities": { "elicitation": { "form": {}, "url": {} } }
  }
}
```

Tool annotations are taken from the backend's `tools/list` and are
**untrusted hints**; policy may use them for defaults (e.g. destructive ⇒
ask) but never to grant access.

### 6.3 Decision document

`data.mcp.authz.decision`:

```json
{
  "effect": "allow | deny | ask",
  "reason": "human-readable, safe to show to the client",
  "ask": {
    "channel": "url | form | oob",
    "prompt": "Allow alice to write /home/alice/project/x.txt?",
    "scopes": ["once", "session", "8h"],
    "fallback": "oob | deny"
  },
  "obligations": {
    "redact_output": ["(?i)password=\\S+"],
    "max_output_bytes": 1048576,
    "rate_limit": ["30/m"],
    "arg_constraints": { "path": ["^/home/alice/"] },
    "audit": "digest | full",
    "pseudonymize": {
      "detect": ["email", "iban", "credit_card", "phone", "ipv4", "ipv6"],
      "patterns": { "customer": "CUST-[0-9]{6}" },
      "fields": { "name": "person" }
    },
    "reidentify": ["customer"]
  }
}
```

Obligations, as the gateway enforces them:

| Obligation | Effect |
|---|---|
| `redact_output` | regular expressions; matches in every string of the result are replaced with `[redacted]` |
| `max_output_bytes` | results larger than this (after redaction) are withheld; the call returns an error |
| `rate_limit` | `N/s`, `N/m` or `N/h`, one or a list; each counts calls per principal, action and target; exceeding denies |
| `arg_constraints` | per argument, regular expressions that must all match; a missing or non-string argument fails |
| `audit` | `full` logs the arguments verbatim instead of a digest |
| `pseudonymize` | values found by built-in detectors, named patterns or JSON field rules are replaced by per-session pseudonyms (`[EMAIL_1]`) in results and in sampling requests to the client's model (§6.3.1) |
| `reidentify` | argument names in which the session's pseudonyms are replaced by the original values before forwarding; OPA is asked again with the real arguments, and that decision must allow |

A malformed obligation (bad regex, bad rate, unknown detector) makes the
whole decision invalid, which fails closed. The shipped policy takes
obligations from the matching permissions' `obligations` objects and
merges them. Redactions, rate limits, argument constraints, detectors,
patterns, field rules and arguments to re-identify add up, the smallest
output limit wins, and `full` audit wins.

#### 6.3.1 Pseudonymization

Customers who use external models want their internal data to stay
inside. The gateway sees everything MCP servers return, so it can replace
personal or confidential values before the agent (and with it the model
provider) sees them.

- **Reversible and consistent.** Each MCP session has a vault (in memory,
  `internal/pseudo`) mapping values to tokens of the form
  `[<CLASS>_<n>]`. The same value always gets the same token within the
  session, so the model can relate records and refer to them. The vault
  ends with the session and is never persisted; its size is bounded
  (10,000 values, then values are replaced irreversibly).
- **Deterministic detection.** Field rules (JSON keys, also inside JSON
  returned as text), validated detectors (e-mail, IBAN with checksum,
  payment cards with Luhn check, international phone numbers, IP
  addresses) and named regular expressions. Statistical recognition of
  names in free text (e.g. Presidio as a confined sidecar) is left open;
  it would be another detector behind the same obligation.
- **Controlled re-identification.** Only arguments named by `reidentify`
  are translated back, and only with this session's tokens. Because any
  re-identifying tool can turn a token back into its value, the gateway
  asks OPA again with the arguments as forwarded, so that `args`
  conditions and approvals see real values.
- **Scope.** Results of calls, prompts, resource reads and completions,
  and `sampling/createMessage` requests from backends (which go to the
  client's model). Not covered: lists, notifications, what the user types
  and tools outside the gateway. Approvals show the arguments with tokens;
  the model's answer contains tokens, which the gateway cannot translate
  for the user since it never sees the answer.
- **Audit.** `mcp-pseudonymize` journal events with classes and counts,
  never values; `reidentified` counts on decision records.

Pseudonymized data remains personal data under the GDPR (Art. 4(5)): the
feature reduces risk, it does not replace agreements with the model
provider. Policy can combine it with client identity (e.g. client
certificates of agent hosts that use an internal model) to pseudonymize
only for external models.

`data.mcp.filter.visible` returns, for a principal and a list of
resources, the subset to show — one OPA query per `*/list`, not one per
item.

### 6.4 RBAC data

A permission names a backend (`server` glob) and exactly one target: a
`tool`, `prompt` or `resource` (URI) glob, or `client` for requests a
backend sends to the client (`roots/list`, `sampling/createMessage`,
`elicitation/create`). Globs have no separators (`*` matches `/`) and may
use `${sub}` and `${home}`. Optional fields: `effect: "deny"` (explicit
deny, wins over everything), `require_approval`, `approval_channel`,
`args` (regular expressions per tool/prompt argument, deciding whether the
permission applies), `require_client_cert` (applies only to remote
clients with a verified TLS client certificate, §5.1; ignored for explicit
denies, which always apply), `obligations` (§6.3, conditions on an allowed call),
and for `client` permissions `allow_sensitive` (backend elicitations that
look like they ask for secrets, §5.6.2).

`approvers` maps a server name, or `default`, to the rules for who may
decide on that server's approvals and manage its grants: `self`,
`role:<role>`, `group:<group>`, `user:<user>` (§5.6.1). Without it, only
`self` applies.

Completions follow their target: a prompt's like `prompts.get`; a resource
template's (and its visibility in `resources/templates/list`) wherever the
principal may read some resource of that backend.

```json
{
  "roles": {
    "viewer":    { "permissions": [ { "server": "*", "tool": "read_*" },
                                    { "server": "*", "prompt": "*" } ] },
    "developer": { "permissions": [
        { "server": "git", "tool": "*" },
        { "server": "fs",  "tool": "read_*" },
        { "server": "fs",  "resource": "file://${home}/*" },
        { "server": "fs",  "tool": "write_file", "require_approval": true,
          "args": { "path": "^${home}/" } },
        { "server": "fs",  "tool": "delete_*", "effect": "deny" } ] },
    "admin":     { "permissions": [ { "server": "*", "tool": "*" },
                                    { "server": "*", "resource": "*" },
                                    { "server": "*", "prompt": "*" },
                                    { "server": "*", "client": "*" } ] }
  },
  "bindings": {
    "groups": { "dev": ["developer"], "wheel": ["admin"] },
    "users":  { "bob": ["viewer"] }
  },
  "approvers": { "default": ["self", "role:admin"] }
}
```

### 6.5 Example rule

```rego
package mcp.authz

import rego.v1

default decision := {"effect": "deny", "reason": "no matching permission"}

perms contains p if {
	some role in data.mcp.roles_of[input.principal.sub]
	some p in data.rbac.roles[role].permissions
}

matches(p) if {
	glob.match(p.server, [], input.resource.server)
	glob.match(p.tool, [], input.resource.name)
	args_ok(p)
}

decision := {"effect": "allow"} if {
	some p in perms
	matches(p)
	not p.require_approval
}

decision := {
	"effect": "ask",
	"ask": {
		"channel": "url",
		"prompt": sprintf("Allow %s to call %s/%s?", [input.principal.sub, input.resource.server, input.resource.name]),
		"scopes": ["once", "session"],
		"fallback": "deny",
	},
} if {
	some p in perms
	matches(p)
	p.require_approval
	not granted
}

decision := {"effect": "allow"} if {
	some p in perms
	matches(p)
	p.require_approval
	granted
}

granted if {
	some g in input.grants
	g.server == input.resource.server
	g.tool == input.resource.name
	time.parse_rfc3339_ns(g.expires) > time.now_ns()
}
```

(Simplified. The shipped policy, `policy/mcp/authz.rego`, handles all
target kinds, explicit denies and precedence: deny > allow > allow with
grant > ask > default deny.)

### 6.6 Policy lifecycle

- Rego logic lives in git with `opa test` and `opa check --strict` in CI.
- RBAC data may be edited through Cockpit; with signed bundles, edits
  take effect with a new bundle revision (`mcp-policy-bundle`), keeping
  git as source of truth for logic.
- Bundle activation is atomic; the gateway notices the change (§5.3,
  item 6), emits `list_changed` notifications and records a
  `mcp-policy-change` audit event.

## 7. Key flows

### 7.1 Local `tools/call` requiring approval

```
Client        mcp-connect   Gateway/Router   PEP      OPA     Broker    Cockpit   Supervisor  Backend(fs)
  │ tools/call   │               │            │        │        │          │          │           │
  │─────────────▶│──────────────▶│ identify (SO_PEERCRED/SO_PEERSEC)       │          │           │
  │              │               │──input────▶│───────▶│        │          │          │           │
  │              │               │            │◀─ask───│        │          │          │           │
  │              │               │            │───────────────▶ │ URL elicitation      │           │
  │◀───────────── elicitation/create (url) ───────────────────── │          │          │           │
  │  human opens URL, logs into Cockpit, approves "session" ──────────────▶ │          │           │
  │              │               │            │        │        │◀─grant───│          │           │
  │              │               │            │───────▶│(re-query with grant)          │           │
  │              │               │            │◀─allow─│        │          │          │           │
  │              │               │─────────── get/start instance (alice, fs) ─────────▶│──spawn───▶│
  │              │               │─────────────────── tools/call (stdio) ─────────────────────────▶│
  │              │               │◀───────────────────────── result ───────────────────────────────│
  │              │               │ apply obligations, audit  │          │          │           │
  │◀─────────────│◀──────────────│            │        │        │          │          │           │
```

### 7.2 Remote session setup

1. Client hits `POST /mcp` without token → `401` with
   `WWW-Authenticate: Bearer resource_metadata=".../.well-known/oauth-protected-resource"`.
2. Client performs OAuth 2.1 (auth code + PKCE, or client credentials for
   machine agents) against the IdP, with `resource=https://host:8443/mcp`.
3. Client retries with bearer token; gateway validates and builds the
   principal, maps to local account if configured.
4. `initialize`; gateway returns `Mcp-Session-Id`; normal flow continues.

### 7.3 Discovery

1. `tools/list` from client.
2. For backends with `discovery: shared` (the default), the list comes
   from a cache filled by one **discovery instance** per backend, which the
   gateway runs for its own principal (`mcp-discovery`, no local account:
   a dynamic user under systemd, home `/`) and which only ever receives
   list requests. The cache holds `tools/list`, `prompts/list` and
   `resources/templates/list`; it is dropped when any instance of the
   backend sends the matching `list_changed` (sessions that did not get it
   from their own instance are told too) and when the discovery instance
   stops (idle timeout). A single-server endpoint's `initialize` also
   answers from the discovery instance. Connecting and listing thus start
   no per-principal instance, and no user's view of a server is shown to
   another. If the discovery instance cannot run, the session's own
   instance answers.
3. One batch query to `data.mcp.filter.visible`; filtered, namespaced list
   returned: visibility stays per principal.

`resources/list` is user data (e.g. the files in the user's home) and
always comes from the principal's own instance, as do calls. Servers
whose tool or prompt lists depend on the user set `discovery: instance`.
`logging/setLevel` reaches running instances and is replayed to
instances started later, without starting any.

## 8. Threat model (summary)

| Threat | Mitigation |
|---|---|
| Agent calls tools it shouldn't | RBAC + OPA per call; discovery filtering; default deny |
| Agent auto-approves its own elicitation | URL / OOB approvals authenticated outside the agent; `form` only for low-risk |
| Prompt-injected agent exfiltrates via allowed tool | argument constraints, rate limits, output limits, approvals on destructive/egress tools, audit |
| Malicious/compromised backend | per-backend SELinux domain, no access to gateway/OPA sockets, systemd sandboxing, no network by default, per-session MCS |
| Backend phishing the user via elicitation | policy on `elicitation.create`, origin labelling, secret-field blocking |
| Cross-tenant data leakage | instance per principal (or session), MCS categories, separate Unix users where possible |
| Token theft / confused deputy | audience-bound tokens, no token passthrough, backend creds via systemd credentials |
| Policy tampering | signed bundles verified by OPA (file or bundle server; never with `--watch`), OPA in own domain, config/bundle dirs writable only by admin |
| OPA outage | fail closed |
| Local user spoofing identity | kernel-provided peer credentials; `clientInfo` never trusted |

## 9. Decisions

These resolve the open questions from the initial architecture discussion.
All decisions below were accepted on 2026-09-27.

**D1 — Run-as identity for remote principals.**
*Decision (accepted):* configurable per deployment, default **mapped local account**
when a mapping exists (SSSD/IPA: `sub` → Unix user), otherwise
`DynamicUser=yes` + per-instance MCS pair. Local principals always run as
their own uid.
*Rationale:* keeps DAC meaningful where accounts exist, still isolates
where they don't.

**D2 — Endpoint style.**
*Decision (accepted):* offer **both**: aggregated `/mcp` (and `mcp-connect --server all`)
plus per-server `/mcp/<server>`. Same pipeline, only the naming layer
differs.
*Rationale:* aggregated suits general agents; per-server keeps original tool
names for clients configured per server.

**D3 — Default approval channel.**
*Decision (accepted):* policy chooses per decision; the shipped default policy uses
**`url`** for anything `require_approval`, with `oob` fallback, and
`form` only for rules explicitly marked low-risk.
*Rationale:* the approval must not be answerable by the governed agent.

**D4 — Policy authoring.**
*Decision (accepted):* Rego logic in git (tests in CI); RBAC data editable through
Cockpit, which generates signed bundle revisions.
*Implementation:* bundles are built and signed by `mcp-policy-bundle`
(§5.5). Cockpit signs when the administrator keeps the signing key on the
host (`mcp-policy-bundle -G`); keeping it off the host (CI) is the
stronger setup, then Cockpit only edits the role data.

**D5 — Trust in backends.**
*Decision (accepted):* treat all backends as **untrusted** by default
(`mcpsrv_generic_t`, no network, read-only home). Vetted backends get a
dedicated domain and wider sandbox via their registry entry and policy
interfaces. Output inspection is an obligation hook, not implemented in
v1.

**D6 — Implementation language.**
*Decision (accepted):* **Go**. Official MCP Go SDK, native OPA (sidecar now,
embeddable later), mature SELinux (`github.com/opencontainers/selinux`)
and systemd D-Bus (`github.com/coreos/go-systemd`) libraries, single
static binary.
*Implementation note:* the proxy core uses its own minimal JSON-RPC
framing (`internal/jsonrpc`) instead of the SDK's server abstractions,
because it forwards messages it does not need to understand and must keep
ids, params and results byte-exact. The SDK remains an option for
gateway-originated features (e.g. the aggregated endpoint).

**D7 — OPA deployment.**
*Decision (accepted):* sidecar over unix socket for v1 (§5.5).

## 10. Repository layout

```
cmd/
  mcp-gateway/            # daemon
  mcp-connect/            # stdio ↔ unix-socket shim
internal/
  transport/              # unix, http (streamable), shim protocol
  authn/                  # peercred/peersec, OAuth resource server
  principal/
  router/                 # MCP session, namespacing, filtering
  pep/                    # OPA client, decision application, obligations
  pseudo/                 # pseudonymization: detectors, per-session vault
  broker/                 # approvals, grants store, elicitation
  supervisor/             # systemd transient units, instance pool, MCS allocator
  audit/
  config/
policy/                   # default Rego bundle + tests
selinux/                  # mcp_gateway.te / .fc / .if
systemd/                  # mcp-gateway.service, mcp-gateway.socket, mcp-opa.service
packaging/                # OBS/RPM (suse/), sysusers, polkit, demo server definition
docs/
```

## 11. Roadmap

1. **Design doc** (this document).
2. **Skeleton:** Go module, layout above, Makefile, CI (build, `go test`,
   `opa test`), placeholder SELinux module and systemd units.
3. **PoC** (done, see `examples/poc/README.md`):
   - unix-socket transport + `mcp-connect`;
   - protocol router for one backend (no aggregation yet);
   - OPA sidecar with the example policy; `allow`/`deny`/`ask`;
   - `form`-mode elicitation for `ask`;
   - one backend spawned via systemd in its own SELinux domain (the
     confined path is implemented but not yet exercised on a real host;
     the end-to-end test uses the unconfined `exec` supervisor);
   - pulled forward from step 4: `tools/list` filtering, audit records.
4. **Aggregation** (done): aggregated endpoint with namespacing; policy
   and filtering for resources, resource templates, prompts, completions
   and backend requests; instances shared by a principal's sessions with
   idle timeout; cancellation and progress mapping.
5. **Remote access** (done): Streamable HTTP transport and OAuth resource
   server (JWT/JWKS validation, RFC 9728 metadata, local account mapping).
6. **Approvals** (done): URL-mode and out-of-band approvals, control API,
   Cockpit approvals page, persistent grants.
7. **Packaging and hardening** (done, pending tests on a real host):
   openSUSE/SLES packages via OBS (`packaging/suse`), vendor/admin file
   layout, tighter systemd sandboxes; MCS allocation and per-session
   isolation were done with steps 3 and 4.
8. **Operations** (done): obligations, backend credentials, approver
   rules, sensitive elicitations; `list_changed` on policy changes; kernel
   audit, keyed argument digests and correlated OPA decision logs; signed
   policy bundles; restart backoff; mTLS with certificate-bound tokens;
   Cockpit tabs for servers, policy and audit.
9. **Data protection** (done): pseudonymization of results and sampling
   requests with per-session reversible tokens, policy-controlled
   re-identification (§6.3.1).

## 12. Open items

- Distribution focus is openSUSE and SLES (packages via OBS,
  `packaging/suse`). SLES 15 uses AppArmor, not SELinux; an AppArmor
  profile set would be needed there.

- Path arguments: policy rejects `..` segments, but symlinks inside an
  allowed tree can still point elsewhere. Resolving paths needs knowledge
  of the backend's filesystem view; until then DAC and SELinux are the
  backstop.
- HTTP streams: with several requests in flight on one session, a server
  notification or request goes to the most recently opened request stream,
  which may belong to another of the client's requests. Clients treat all
  streams as one session, so this is harmless, but not precise. Replay is
  bounded (256 events per stream) and lives in memory: a gateway restart
  ends all HTTP sessions anyway.
- Approval mail expands groups through NSS, which does not list users
  whose primary group it is; name such approvers as `user:` or bind them
  by user.
- A token that expires during a long SSE stream keeps that stream alive;
  every new request needs a valid token.
- Exact JSON-RPC error codes for policy denials (align with any future
  MCP-spec guidance).
- Behaviour of long-running `tools/call` when a grant expires mid-call
  (proposal: grants are checked at call start only).
- Handling of `resources/subscribe` notifications after access is revoked
  (proposal: gateway drops notifications and unsubscribes).
- Policy changes are noticed by polling (up to `policy.watch_interval`
  late); OPA has no change notification over its REST API.
- The kernel audit subsystem is optional (`audit.kernel: auto`); in
  containers without `CAP_AUDIT_WRITE` only the journal records remain.
- Rate-limit counters live in the gateway's memory (sliding windows per
  principal, action and target); a restart resets them.
- MCS pairs of stopped containers (their files keep the pair) are not
  known to the gateway, and a container can take an instance's pair for up
  to 30 s before the instance is replaced (§5.8).
