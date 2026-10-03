# 1. Introduction

## What the gateway does

MCP servers give AI agents tools (run a command, write a file, query a
database), prompts and resources. Most of them speak MCP over stdio: the
agent starts the server as a child process, and the server runs with the
agent's full rights. Nothing decides which tool an agent may call, nobody
is asked before something destructive happens, and nothing is recorded.

mcp-gateway sits between agents and MCP servers:

```
  agent (local) ── mcp-connect ──┐                        ┌── MCP server "fs"   (confined, per user)
  agent (local, unix socket) ────┤                        ├── MCP server "git"  (confined, per user)
  agent (remote, HTTPS+OAuth) ───┴──▶  mcp-gateway  ──────┼── MCP server "db"   (confined, per user)
                                        │   │    │        └── …
                        policy (OPA) ◀──┘   │    └──▶ approvals (you, in Cockpit / desktop / mail)
                                            └──▶ audit (journal, kernel audit)
```

- **One place to connect.** Agents connect to the gateway instead of
  spawning servers: locally over a unix socket (or the `mcp-connect`
  shim for agents that can only spawn a command), remotely over MCP
  Streamable HTTP with OAuth 2.1 bearer tokens.
- **Authorization by policy.** Every request (tool calls, prompts,
  resources, completions, and requests servers send back to the agent)
  is decided by the Open Policy Agent against role-based rules you
  maintain. Agents only see the tools they may use.
- **Human approval.** Rules can require a human's approval for a call,
  given on an approval page the agent cannot influence (Cockpit), or
  through the agent's own dialog for low-risk confirmations. Approvals can
  be remembered for the session or for a time.
- **Pseudonymization.** Personal or confidential values in what servers
  return can be replaced by consistent pseudonyms before they reach the
  agent and its (possibly external) model; chosen tools receive the real
  values back.
- **Confinement.** Each server runs as a transient systemd service, as the
  requesting user (or a throwaway user), in a hardened sandbox, in its own
  SELinux domain with a unique MCS category pair per instance.
- **Audit.** Every decision is logged; security-relevant events also go
  to the kernel audit subsystem, next to SELinux denials.

## Concepts

| Term | Meaning |
|---|---|
| **MCP server** (backend) | A program speaking MCP over stdio, registered with the gateway by a definition file (chapter 4). |
| **Instance** | A running copy of an MCP server, started on demand for one principal (or one session) and stopped when idle. |
| **Principal** | Who a request is for: a local user (identified by the kernel through the socket) or a remote identity (from the OAuth token). Policy decides on principals. |
| **Session** | One agent connection (an MCP session). |
| **Endpoint** | What a session talks to: one MCP server (`--server fs`, `/mcp/fs`) or the **aggregated** endpoint offering all servers at once with prefixed names. |
| **Role, permission, binding** | Policy data: roles carry permissions (which server, which tools/prompts/resources, with which conditions); bindings give roles to users and groups. |
| **Approval** | A human decision the policy asks for before a call runs. |
| **Grant** | A remembered approval (for one call, the session, or a duration). |
| **Obligation** | A condition attached to an allowed call: redact output, limit output size, rate-limit, constrain arguments, log arguments in full. |
| **Channel** | How an approval is obtained: `form` (the agent's own dialog), `url` (an approval page the agent's user opens), `oob` (out of band: the Cockpit inbox, desktop notification, mail). |

## Components

| Component | Package | Role |
|---|---|---|
| `mcp-gateway` | `mcp-gateway` | The daemon (`mcp-gateway.service`): transports, authentication, routing, policy enforcement, approvals, instance supervision, audit, control API. |
| `mcp-opa.service` | `mcp-gateway` (requires `opa`) | The policy engine: the distribution's OPA, in its own SELinux domain, on a unix socket. |
| `mcp-connect` | `mcp-gateway` | stdio ↔ socket shim for local agents that can only spawn a command. |
| `mcp-gateway-admin` | `mcp-gateway`; `inspect`, `profile`, `review` in `mcp-gateway-tools` | Commands for administrators: the self-check (`doctor`), the diagnostics server `gateway-admin` (`serve`), and tools for adding MCP servers (chapter 4). |
| `mcp-policy-bundle` | `mcp-gateway` | Builds and signs policy bundles. |
| SELinux module `mcp_gateway` | `mcp-gateway-selinux` | Domains for the gateway, OPA and MCP servers; isolation rules. |
| Cockpit page | `mcp-gateway-cockpit` | Approvals, grants, servers and instances, role bindings, audit records. |
| `mcp-gateway-notify` | `mcp-gateway-desktop` | Desktop notifications for approvals. |
| `mcp-server-fs` | `mcp-gateway-fs-server` | An MCP server for files on the user's home directory (server `fs`): read, list, search, write, edit (chapter 4); also serves this documentation to agents (server `gateway-docs`, chapter 10). |
| `mcp-server-exec` | `mcp-gateway-exec-server` | An MCP server offering commands the administrator allows as tools (server `exec`, chapter 4). |
| setup packages | `mcp-gateway-profile-*` | Definitions, roles, accounts and polkit rules for the systemd, firewalld, zypp, suseconnect and snapper MCP servers (chapter 13). |

## How a request flows

1. An agent connects. The gateway identifies the principal: the local
   user from the socket's peer credentials (and SELinux label), or the
   remote user from the validated OAuth token.
2. The agent lists tools. The gateway asks OPA which tools the principal
   may see and returns only those (names prefixed with the server on the
   aggregated endpoint).
3. The agent calls a tool. The gateway asks OPA: **allow**, **deny**, or
   **ask**.
   - *allow*: the call goes to the principal's instance of that server
     (started if needed), with the policy's obligations applied.
   - *deny*: the agent gets an error explaining the denial.
   - *ask*: the gateway obtains an approval through the channel the policy
     names, then asks OPA again with the new grant.
4. The decision, the grant used and a keyed digest of the arguments are
   written to the audit trail.

## Security model in brief

- The agent is **not trusted**: it cannot answer approvals on high-trust
  channels, cannot see tools it may not use, and never gets the gateway's
  or other users' credentials. The client's self-reported name is
  informational only.
- MCP servers are **not trusted** by default: they run with no network,
  a read-only home, no capabilities and the most restricted SELinux
  domain unless their definition and policy say otherwise.
- The gateway **fails closed**: without an answer from OPA, everything is
  denied.
- Policy logic comes from the package; roles and bindings from the
  administrator; both can be delivered as signed bundles.

Chapter 9 covers the details.
