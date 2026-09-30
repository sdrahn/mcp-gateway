# mcp-gateway user guide

mcp-gateway makes the MCP (Model Context Protocol) servers installed on a
Linux host available to AI agents, locally and over the network, under
central control: every request is authorized by policy (OPA), sensitive
calls can require a human's approval, each server runs confined by
systemd and SELinux, and everything is audited.

This guide is for administrators who deploy and run the gateway, for
people who write policy and add MCP servers, and for users who connect
their agents to it. The design rationale lives in
[docs/architecture.md](../architecture.md).

| Chapter | Contents |
|---|---|
| [1. Introduction](01-introduction.md) | What the gateway does, concepts, components, security model |
| [2. Installation](02-installation.md) | Packages for openSUSE/SLES, first start, installing from source, development mode |
| [3. Configuration](03-configuration.md) | `gateway.yaml` reference, file layout |
| [4. MCP servers](04-mcp-servers.md) | Registering MCP servers, isolation, sandbox, secrets, SELinux domains, packaging |
| [5. Connecting clients](05-connecting-clients.md) | Local agents (`mcp-connect`), endpoints and naming, remote agents over HTTPS with OAuth and mTLS |
| [6. Policy](06-policy.md) | Roles, permissions, bindings, approver rules, obligations, testing, signed bundles |
| [7. Approvals](07-approvals.md) | Approval channels, scopes and grants, persistence, desktop and e-mail notifications |
| [8. Cockpit](08-cockpit.md) | The web console page: approvals, servers, policy, audit |
| [9. Security](09-security.md) | SELinux, MCS isolation, sandboxing, credentials, audit trail, hardening checklist |
| [10. Operations](10-operations.md) | Logs, monitoring, state, upgrades, troubleshooting |
| [11. Reference](11-reference.md) | Commands, control API, audit records, paths, SELinux types and booleans |
| [12. Custom policy (Rego)](12-custom-policy.md) | The policy contract (queries, inputs, decisions), extending or replacing the shipped logic, writing policy from scratch, testing and deploying |
| [13. System management servers](13-system-management-servers.md) | systemd, firewalld and snapper MCP servers: accounts, SELinux domains, polkit, read freely and change only with approval |

## Quick start (openSUSE Tumbleweed)

```bash
# 1. Install (repository: the OBS project that builds mcp-gateway)
zypper install mcp-gateway mcp-gateway-cockpit mcp-gateway-desktop

# 2. Let a user connect, and start the service
usermod -aG mcp-users alice
systemctl enable --now mcp-gateway.service

# 3. Register an MCP server
cat >/etc/mcp-gateway/servers.d/git.yaml <<'EOF'
name: git
command: ["/usr/libexec/mcp-servers/mcp-git"]
EOF
systemctl restart mcp-gateway.service   # definitions are read at start

# 4. Give the user a role (developers may use git; see chapter 6)
#    in /etc/mcp-gateway/policy/rbac/data.json:
#    "bindings": {"users": {"alice": ["developer"]}, ...}

# 5. As alice, point the agent at the gateway
#    { "command": "mcp-connect", "args": ["--server", "git"] }
```

Then open Cockpit (`https://<host>:9090`, "MCP Gateway") to decide on
approvals, watch the servers and read the audit records.
