# mcp-gateway

A policy-enforcing gateway that makes local, stdio-only
[MCP](https://modelcontextprotocol.io/) servers available to local and
remote MCP clients, with:

- access control / RBAC,
- permission elicitation (human approval of sensitive actions),
- [OPA](https://www.openpolicyagent.org/) as the policy engine,
- SELinux confinement of the gateway, the policy engine and every MCP server.

Status: design phase. See [docs/architecture.md](docs/architecture.md).
