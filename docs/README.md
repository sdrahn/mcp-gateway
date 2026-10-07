# mcp-gateway documentation

Start here, whether you are a person or an agent reading these files
through the `gateway-docs` server. This page says which file answers
which question, and where each common error message is explained.

| File | What it is |
|---|---|
| [`user-guide/`](user-guide/README.md) | the user guide: installing, configuring and running the gateway, in 13 chapters. Chapter *N* is `user-guide/NN-*.md` (chapter 4 is `04-mcp-servers.md`); "chapter 10, "Self-check"" means the section *Self-check* there. |
| [`architecture.md`](architecture.md) | the design: components, policy model, decisions (D1, D2, …) and their reasons, the roadmap. Large; read the section you need. |
| `CHANGELOG.md` | what changed in each release, with upgrade notes; newest first. Installed next to this file; in the source tree, at its top. |

These files describe how the gateway works and should be configured,
not how this machine is configured. The configuration in force, and
checks of it, come from the `gateway-admin` server: `show_config`,
`check_config`, `doctor` (chapter 10, "Asking an agent"). The other
servers cannot read the gateway's files.

For an agent, which server to ask:

- what the user may do here, on which server, within which limits:
  the gateway's own tool `gateway_capabilities` (aggregated endpoint);

- the gateway's configuration (`gateway.yaml`, server definitions in
  `servers.d`, the exec server's commands in `exec.d`, role data):
  `gateway-admin` `show_config`, after an approval; secrets are masked;
- whether it works, SELinux denials, what the policy decides and why,
  recent decisions: `gateway-admin` `doctor` and `check_config`
  (no approval), `selinux_denials`, `explain_decision`, `recent_audit`
  (after an approval);
- not through the file server (`fs`, which reaches only the user's
  home: "outside the allowed directories") nor the systemd server's
  `get_file` (its shipped roles allow only `/etc/systemd` and
  `/usr/lib/systemd`). Paths outside all of these, such as `/run/netns`,
  no shipped server reads.

## Where to find what

| Question | Where |
|---|---|
| What does the gateway do, what are principals, sessions, instances, grants? | [1. Introduction](user-guide/01-introduction.md) |
| Which packages, first start, transactional systems (MicroOS, SLE Micro) | [2. Installation](user-guide/02-installation.md) |
| Every key of `gateway.yaml`, which file is in force (`/etc` or `/usr/etc`), which keys apply without a restart | [3. Configuration](user-guide/03-configuration.md) |
| Adding an MCP server: definition keys, sandbox, secrets, SELinux domain; `inspect`, `profile`, `review`; the file server `fs` and the command server `exec` | [4. MCP servers](user-guide/04-mcp-servers.md) |
| Servers that speak HTTP (`url`), through a proxy, or that each user signs in to (`sign_in`, OAuth) | [4. MCP servers, "Servers that speak HTTP"](user-guide/04-mcp-servers.md#servers-that-speak-http), ["Signing in for each user"](user-guide/04-mcp-servers.md#signing-in-for-each-user) |
| Changing server definitions while the gateway runs | [4. MCP servers, "Changing definitions while the gateway runs"](user-guide/04-mcp-servers.md#changing-definitions-while-the-gateway-runs) |
| Connecting an agent: `mcp-connect`, the aggregated endpoint and `server__tool` names, remote access with OAuth, Claude Code, Kit | [5. Connecting clients](user-guide/05-connecting-clients.md) |
| Roles, permissions, bindings, approver rules, obligations, pseudonymization, the shipped roles | [6. Policy](user-guide/06-policy.md) |
| Approval channels, scopes ("once", "session", durations), desktop and mail notifications | [7. Approvals](user-guide/07-approvals.md) |
| The Cockpit page | [8. Cockpit](user-guide/08-cockpit.md) |
| Threat model, SELinux domains, MCS, sandbox, audit trail, hardening checklist | [9. Security](user-guide/09-security.md) |
| What to do after a change, logs, metrics, upgrades, the self-check, troubleshooting | [10. Operations](user-guide/10-operations.md) |
| Command-line options, control API, audit record fields, file paths, SELinux types, limits | [11. Reference](user-guide/11-reference.md) |
| Writing Rego: the policy's inputs and decisions, adding to or replacing the shipped logic, testing | [12. Custom policy](user-guide/12-custom-policy.md) |
| systemd, firewalld, zypp, suseconnect and snapper servers: setup packages, accounts, polkit, roles | [13. System management servers](user-guide/13-system-management-servers.md) |
| Why something is designed the way it is | [architecture.md, "9. Decisions"](architecture.md#9-decisions) |

## Error messages

Messages as agents, logs or tools show them, and where they are
explained. Where a message names a server or tool, it is shown here
with placeholders.

| Message | Meaning | Where |
|---|---|---|
| `no matching permission` | no role of the principal allows the call | [10, "Calls fail"](user-guide/10-operations.md#calls-fail) |
| `no matching permission: the arguments are outside what your roles allow (…)` | a role allows the tool, but not with these arguments; the allowed patterns follow | [10, "Calls fail"](user-guide/10-operations.md#calls-fail) |
| `denied by policy` | a permission with `effect: "deny"` matched | [10, "Calls fail"](user-guide/10-operations.md#calls-fail) |
| `policy evaluation failed` | OPA did not answer: everything is denied | [10, "Calls fail"](user-guide/10-operations.md#calls-fail) |
| `approval via url required but not available` | no usable approval channel | [7, "Channels"](user-guide/07-approvals.md#channels) |
| `declined by user`, `approval failed` | the approver denied, or the approval timed out | [7, "The flow"](user-guide/07-approvals.md#the-flow) |
| `rate limit exceeded`, `output withheld: …`, `argument "x" violates a constraint: it must match …` | an obligation of the permission | [6, "Obligations"](user-guide/06-policy.md#obligations) |
| `backend unavailable; retry in …` | the server's instance crashed or does not start | [10, "Instances do not start"](user-guide/10-operations.md#instances-do-not-start) |
| `unknown server "x"` | no server of that name is defined | [10, "The agent cannot connect"](user-guide/10-operations.md#the-agent-cannot-connect) |
| `session limit reached (64)`, `instance limit reached (32)` | a limit of the principal | [3, "Limits"](user-guide/03-configuration.md#limits) |
| `…: outside the allowed directories (…)` (file server) | the file server works below its `--root` only, the user's home | [10, "Errors from servers"](user-guide/10-operations.md#errors-from-servers) |
| `calling method was canceled by user` (systemd-mcp) | systemd-mcp's own authorization refused the call | [10, "Errors from servers"](user-guide/10-operations.md#errors-from-servers), [13](user-guide/13-system-management-servers.md#checking-and-troubleshooting) |
| `Interactive authentication required`, `NOT_AUTHORIZED` | polkit refused the server's account | [13, "Service permissions"](user-guide/13-system-management-servers.md#service-permissions) |
| `read-only file system (on a transactional system, …)` | `/usr` cannot be changed on a transactional system | [2, "Transactional systems"](user-guide/02-installation.md#transactional-systems) |
| `401 invalid token`, `403 insufficient scope`, `404 unknown session` | remote access over HTTPS | [5, "Errors"](user-guide/05-connecting-clients.md#errors) |
| `signing in to … failed: …`, `sign_in needs the HTTP listener`, `… neither supports client ID metadata documents nor registration` | a server each user signs in to | [4, "Signing in for each user"](user-guide/04-mcp-servers.md#signing-in-for-each-user) |
| `status=229/SELINUX_CONTEXT`, `Failed to change SELinux context` | the server's SELinux module is not loaded | [4, "SELinux domains for servers"](user-guide/04-mcp-servers.md#selinux-domains-for-servers) |
| `selinux_type is not in the loaded SELinux policy` | the same, as the gateway warns at start | [4, "SELinux domains for servers"](user-guide/04-mcp-servers.md#selinux-domains-for-servers) |
| `invalid message from backend … parse error` | the server writes something other than MCP to stdout | [10, "Instances do not start"](user-guide/10-operations.md#instances-do-not-start) |
| `server definitions not reloaded; serving the previous ones` | a definition in `servers.d` does not load | [4, "Changing definitions while the gateway runs"](user-guide/04-mcp-servers.md#changing-definitions-while-the-gateway-runs) |
| `gateway.yaml not reloaded; the configuration in force stays` | `gateway.yaml`, its certificate or password file does not load | [3, "Changing the configuration while the gateway runs"](user-guide/03-configuration.md#changing-the-configuration-while-the-gateway-runs) |
| `gateway.yaml changes keys that take effect at the next start only` | a key that needs a restart changed | [3, "Changing the configuration while the gateway runs"](user-guide/03-configuration.md#changing-the-configuration-while-the-gateway-runs) |
| `server … is defined twice` | two files define the same server name | [13, "Setup packages"](user-guide/13-system-management-servers.md#setup-packages) |
| `refusing to run as root`, `state files not owned by mcp-gateway` | the gateway was run as root | [10, "State and backup"](user-guide/10-operations.md#state-and-backup) |
| `mcp-gateway was updated; restart …` | the package was updated, the gateway still runs the old version | [10, "Upgrades"](user-guide/10-operations.md#upgrades) |
| `libvirt picks MCS categories from the gateway's range` | libvirt needs a drop-in | [9, "MCS: separating instances"](user-guide/09-security.md#mcs-separating-instances) |
| `FAIL`/`WARN` lines of `mcp-gateway-admin doctor` | the self-check, each line names its fix | [10, "Self-check"](user-guide/10-operations.md#self-check) |
