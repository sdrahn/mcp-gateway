# 5. Connecting clients

Agents reach the gateway in one of three ways:

| Client | Transport | Identity |
|---|---|---|
| local agent that spawns MCP servers (most desktop agents and IDEs) | `mcp-connect` shim → unix socket | the local user (kernel peer credentials) |
| local program speaking MCP over a socket | `/run/mcp-gateway/mcp.sock` directly | the local user |
| remote agent | MCP Streamable HTTP over HTTPS | OAuth 2.1 bearer token (optionally with a client certificate) |

## Endpoints and names

A session talks to one **endpoint**:

- **one server** (`--server fs`, `https://…/mcp/fs`): the server's tools,
  prompts and resources under their own names;
- the **aggregated** endpoint (`--server all` or no hello, `https://…/mcp`):
  all servers the principal may use, with names prefixed by the server:

| Item | On the server endpoint | On the aggregated endpoint |
|---|---|---|
| tool | `read_file` | `fs__read_file` |
| prompt | `review` | `git__review` |
| resource | `file:///home/alice/notes.txt` | `mcp+fs:file:///home/alice/notes.txt` |

The gateway translates names in both directions; MCP servers never see
the prefixes. Use the aggregated endpoint for agents that should have
everything in one connection, per-server endpoints to give an agent
exactly one server.

In both cases the agent sees only what policy lets the principal use
(items needing approval included), and it is told to list again when
the policy changes (`notifications/tools/list_changed` and friends).

## Local agents

### Prerequisites

- The user is a member of the socket's group (`mcp-users` as shipped) and
  has logged in again since being added: `id -nG` must list it.
- The user holds a role granting permissions for the server (chapter 6).

### With `mcp-connect`

`mcp-connect` is a tiny stdio ↔ socket bridge: the agent starts it as if
it were the MCP server. It never interprets MCP, carries no credentials and
adds no rights; the gateway identifies the user from the socket.

```
mcp-connect [--server NAME|all] [--socket PATH]
```

| Flag | Default | Meaning |
|---|---|---|
| `--server` | `all` | the endpoint: a server name, or `all` for the aggregated endpoint |
| `--socket` | `/run/mcp-gateway/mcp.sock` | the gateway's socket |
| `--version` | | print the version |

Typical agent configurations (the JSON shape most MCP clients use):

```json
{
  "mcpServers": {
    "fs":  { "command": "mcp-connect", "args": ["--server", "fs"] },
    "git": { "command": "mcp-connect", "args": ["--server", "git"] }
  }
}
```

or everything through one entry:

```json
{
  "mcpServers": {
    "gateway": { "command": "mcp-connect" }
  }
}
```

Replace existing entries that start MCP servers directly (`npx …`,
`uvx …`, a path) with `mcp-connect` entries once the servers are
registered with the gateway; the server then runs confined and under
policy instead of with the agent's rights.

### Directly over the socket

Programs can connect to the socket themselves. The connection carries
newline-delimited JSON-RPC (one message per line). To select an endpoint,
send this notification first; without it, the session uses the
aggregated endpoint:

```json
{"jsonrpc":"2.0","method":"mcp-gateway/hello","params":{"version":1,"server":"fs"}}
```

Then speak MCP as usual (`initialize`, `notifications/initialized`, …).

```bash
socat - UNIX-CONNECT:/run/mcp-gateway/mcp.sock
```

### What the gateway knows about a local client

The principal is the user of the connecting process as the kernel
reports it (uid, and from it name, groups and home), plus the process's
SELinux context. The `clientInfo` the agent sends in `initialize` is
recorded but never used for decisions.

## Remote agents (HTTPS)

Remote access uses MCP Streamable HTTP. The gateway is an OAuth 2.1
**resource server**: it validates access tokens issued by your identity
provider (IdP); it does not issue tokens and has no login page.

### 1. Identity provider

Register the gateway as a resource (an API / audience) in the IdP
(Keycloak, Entra ID, Okta, Authentik, Dex, …):

- **audience**: the gateway's public MCP URL, exactly as clients use it,
  e.g. `https://gw.example.com:8443/mcp`. Tokens must carry it in `aud`
  (RFC 8707 resource indicators).
- a **scope** clients request, e.g. `mcp` (optional, see `http.scopes`).
- a **groups claim** in the access token (`groups` by default), if roles
  are bound to groups.
- optionally a claim with the **local account name**
  (`preferred_username`), if remote users should act as their local
  accounts.

Register the agents as OAuth clients (authorization code with PKCE for
interactive agents; client credentials for services).

### 2. Certificate and port

```bash
install -d -m0750 -o root -g mcp-gateway /etc/mcp-gateway/tls
install -m0640 -g mcp-gateway gw.crt /etc/mcp-gateway/tls/cert.pem
install -m0640 -g mcp-gateway gw.key /etc/mcp-gateway/tls/key.pem
restorecon -R /etc/mcp-gateway/tls

semanage port -a -t mcp_port_t -p tcp 8443      # SELinux: let the gateway bind 8443
firewall-cmd --permanent --add-port=8443/tcp && firewall-cmd --reload
```

### 3. Configuration

```yaml
# /etc/mcp-gateway/gateway.yaml (excerpt)
http:
  listen: ":8443"
  cert_file: /etc/mcp-gateway/tls/cert.pem
  key_file: /etc/mcp-gateway/tls/key.pem
  issuer: https://idp.example.com/realms/mcp
  audience: https://gw.example.com:8443/mcp
  groups_claim: groups
  local_user_claim: preferred_username
  scopes: [mcp]
```

```bash
mcp-gateway --check && systemctl restart mcp-gateway.service   # http.listen takes effect at start
```

A renewed certificate (the files at `cert_file` and `key_file` replaced)
is picked up within `policy.watch_interval`, or at once with `systemctl
reload mcp-gateway.service`, without ending sessions; connections opened
before keep the old one. A certificate that does not load keeps the one
in force (chapter 3).

The gateway fetches the IdP's signing keys from
`<issuer>/.well-known/openid-configuration` (or `http.jwks_url`) and
refreshes them when it sees an unknown key id.

### 4. Endpoints

With `audience: https://gw.example.com:8443/mcp`:

| URL | What |
|---|---|
| `https://gw.example.com:8443/mcp` | aggregated endpoint |
| `https://gw.example.com:8443/mcp/<server>` | one server, e.g. `/mcp/fs` |
| `https://gw.example.com:8443/.well-known/oauth-protected-resource/mcp` | protected resource metadata (RFC 9728): the issuer and scopes, for clients discovering how to get a token |

A request without a token gets `401` with a `WWW-Authenticate: Bearer`
header pointing to the metadata, so MCP clients that implement the MCP
authorization specification find the IdP by themselves. Point the agent
at the endpoint URL:

```json
{
  "mcpServers": {
    "gateway": { "type": "http", "url": "https://gw.example.com:8443/mcp" }
  }
}
```

### Who a remote user is

| Token | Principal |
|---|---|
| `local_user_claim` names an existing local account | that local user: name, uid, home and groups of the account (plus the token's groups). MCP servers run as that user, exactly as for a local connection. |
| otherwise | the token's `sub` (with its issuer) and the token's groups; no home directory. MCP servers with `run_as: principal` run as a throwaway dynamic user. |

Policy bindings name users by `sub` (the local account name, or the
token subject) and groups by name.

### Sessions and resumability

- The gateway creates an MCP session at `initialize` and returns its id
  in `Mcp-Session-Id`; later requests must carry it and the same
  principal's token. Another principal's session id is treated as
  unknown (`404`).
- Sessions without traffic end after `http.session_idle_timeout`
  (30 minutes); the client then gets `404` and starts a new session.
- Responses stream as server-sent events with event ids. A client whose
  connection drops reconnects with `GET` and `Last-Event-ID` and receives
  what it missed (the last 256 events per stream, kept for 5 minutes),
  including approval requests that were pending. A resumption takes over
  from a connection that is still considered open.
- A stream ends when the token of the request that opened it expires
  (one minute of leeway after its `exp`), a comment `: token expired`
  being the last thing on it. Nothing is lost: the client resumes with a
  fresh token and `Last-Event-ID`, as after a dropped connection. A
  plain JSON response (no `text/event-stream`) is still delivered after
  the expiry: it answers a request that was valid when made.
- `DELETE` with the session id ends a session.

### Browser clients

Browser-based agents send an `Origin` header. List accepted origins in
`http.allowed_origins`; requests with any other `Origin` are refused
(`403`), requests without one (non-browser clients) are accepted.

### Client certificates (mTLS) and bound tokens

For agents running on known machines, require a client certificate in
addition to the token:

```yaml
http:
  client_ca_file: /etc/mcp-gateway/tls/clients-ca.pem
  client_auth: required        # or optional: verify a certificate if one is presented
  require_bound_tokens: true   # tokens must be bound to the certificate (RFC 8705)
```

- With a certificate, policy sees it (`input.principal.cert`: subject,
  SHA-256 thumbprint, DNS/URI/e-mail names). Permissions with
  `"require_client_cert": true` apply only to such clients (chapter 6),
  e.g. "writes only from managed machines".
- A token with a `cnf.x5t#S256` confirmation is accepted only over a
  connection with that very certificate, whether or not
  `require_bound_tokens` is set. With `require_bound_tokens`, unbound
  tokens are refused, so a stolen token is useless without the
  certificate's private key.

### Errors

| Status | Meaning |
|---|---|
| `401 authentication required` | no token; see the `WWW-Authenticate` header |
| `401 invalid token` | wrong issuer or audience, expired, bad signature, or not bound to the presented certificate; the gateway's journal says why (`token rejected`) |
| `403 insufficient scope` | the token lacks a scope from `http.scopes` |
| `403 origin not allowed` | `Origin` not in `http.allowed_origins` |
| `404 unknown session` / `session ended` | the session expired or belongs to someone else; initialize again |
| `400 unknown or expired Last-Event-ID` | the stream to resume is gone; send the request again |
| `409 stream already open` | a second `GET` stream (without `Last-Event-ID`) while the session's stream is open |

## Client compatibility

The gateway speaks MCP 2024-11-05 to 2025-11-25 with agents. CI runs the
common client libraries against it, the way agents use them, over
`mcp-connect` and over HTTPS (`test/clients`):

| Library (version tested) | Used by | Notes |
|---|---|---|
| `@modelcontextprotocol/sdk` 1.31 (TypeScript) | Claude Code, most Node-based agents and IDEs | gives up on a request after 60 s by default; only progress notifications keep it going, and only if the agent asked for them and let them extend the timeout |
| `mcp` 2.2 (Python) | Python agents and frameworks | tries MCP 2026-07-28 first (`server/discover`) and falls back to the initialize handshake |
| `mcp-go` 1.1 | Kit and other Go agents | asks for 2026-07-28 and falls back likewise; over HTTP it hears of tool-list changes only with continuous listening, which Kit does not turn on |

Each is tested on: discovery and calls filtered by policy, an approval
out of band that takes longer than the client's request timeout, an
approval in the client's own dialog (form elicitation), `list_changed`
after a policy change, and cancelling a call while it waits for approval
(the request leaves the approval inbox).

What the gateway does for clients:

- **Waiting calls report progress.** A call waiting for approval sends
  progress notifications (`approvals.progress_interval`, 15 s) if the
  agent asked for progress (chapter 7). After the approval, the MCP
  server's own progress continues where the gateway's left off.
- **Only what the gateway implements is offered.** A server's
  capabilities reach the agent only for tools, prompts, resources,
  completions and logging. Tasks (MCP 2025-11-25) and experimental
  features are not passed on: their requests and results would bypass
  policy and obligations. A call that asks for a task anyway runs
  synchronously.
- **Newer protocol versions** are answered with the gateway's own. A
  `server/discover` probe (MCP 2026-07-28) gets "method not found" (over
  HTTP, before a session exists, status 400), on which clients fall back
  to the initialize handshake; the probe is not audited as a denial.

## Agents

How the agents in common use work with the gateway, as of the versions
named; the libraries underneath are tested in CI (above).

### Claude Code

Tested: 2.1.287. It speaks MCP 2025-11-25 and supports form and URL
elicitation, progress, roots and `list_changed`.

```bash
# local: one server, or everything through one entry
claude mcp add --scope user fs -- mcp-connect --server fs
claude mcp add --scope user gateway -- mcp-connect

# remote, with OAuth (the IdP must allow dynamic client registration, or
# register a client and pass --client-id, and --callback-port for a fixed
# redirect URI)
claude mcp add --scope user --transport http fs https://gw.example.com:8443/mcp/fs

# remote, with a token obtained otherwise
claude mcp add --scope user --transport http fs https://gw.example.com:8443/mcp/fs \
  --header "Authorization: Bearer $TOKEN"
```

| Topic | Behaviour |
|---|---|
| Sessions | one MCP session per server for the life of a Claude Code session; a "session" grant lasts as long |
| Approvals | `url` (the default channel): Claude Code asks the user to open the approval page (URL elicitation); `form`: its own dialog. While a call waits, it shows the gateway's progress message ("Waiting for approval of fs/write_file") |
| Timeouts | a tool call may take `MCP_TOOL_TIMEOUT` (per server: `timeout` in its configuration; default about 28 hours); a call that reports nothing is abandoned after `CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT` (default 30 minutes for local servers, 5 minutes for remote ones). The gateway's progress while waiting keeps it alive, so any `approval_timeout` works |
| Policy changes | it lists tools again on `list_changed`, locally and over HTTP: role changes reach it within `policy.watch_interval` (10 s) |

### Kit

Tested: Kit 0.117 (mcp-go 1.1.1). It asks for MCP 2026-07-28 and falls
back to 2025-11-25. It supports neither elicitation nor progress, and
ignores notifications.

```yaml
# ~/.kit.yml
mcpServers:
  fs:
    type: local
    command: ["mcp-connect", "--server", "fs"]
  # remote, with OAuth (dynamic client registration, or oauthClientId)
  fs-remote:
    type: remote
    url: https://gw.example.com:8443/mcp/fs
  # remote, with a token obtained otherwise
  fs-token:
    type: remote
    url: https://gw.example.com:8443/mcp/fs
    noOAuth: true
    headers: ["Authorization: Bearer <token>"]
```

| Topic | Behaviour |
|---|---|
| Sessions | one MCP session per server per `kit` run (`kit -p` runs are one each); within a run, Kit replaces a session that has been idle for 5 minutes. "Session" grants end with it: offer a duration (`approval_scopes`) to Kit users |
| Approvals | Kit cannot answer elicitations, so `url` and `form` fall back to `oob` (the shipped policy's fallback). Kit shows nothing while a call waits: approvers learn of it from the desktop notification or mail (chapter 7) and decide in Cockpit; the call returns when they do, or after `approval_timeout` |
| Timeouts | none of its own on tool calls; `approval_timeout` decides |
| Policy changes | Kit reads the tool list when it starts and does not act on `list_changed` (over HTTP it does not receive it either); start Kit again after role changes. Tools that policy removed meanwhile are refused when called |
| Load | before each tool call Kit lists the server's tools as a health check |
| Tasks | with `tasksMode: always` Kit asks for a task; the gateway runs the call synchronously (it offers no tasks, so `auto` never asks) |

### Other agents

Agents configured with the common `mcpServers` JSON (above) work
through `mcp-connect`. Most are built on the TypeScript or Python SDK;
check two things:

- **Approvals:** an agent without URL elicitation gets out-of-band
  approvals for `url`, one without any elicitation also for `form`;
  set up desktop notifications or mail for them (chapter 7).
- **Timeouts:** an agent that gives up on calls after a fixed time
  (the TypeScript SDK's default is 60 s) fails approvals that take
  longer, unless it asks for progress and lets progress extend the
  timeout. Raise the agent's timeout, or keep `approval_timeout` below
  it so that the agent at least gets the gateway's denial.
