# mcp-gateway

A policy-enforcing gateway that makes local, stdio-only
[MCP](https://modelcontextprotocol.io/) servers available to local and
remote MCP clients, with:

- access control / RBAC,
- permission elicitation (human approval of sensitive actions),
- [OPA](https://www.openpolicyagent.org/) as the policy engine,
- SELinux confinement of the gateway, the policy engine and every MCP server.

Status: design phase. See [docs/architecture.md](docs/architecture.md).

## Repository layout

| Path | Contents |
|---|---|
| `cmd/mcp-gateway` | gateway daemon (currently: configuration validation only) |
| `cmd/mcp-connect` | stdio ↔ unix-socket shim for local clients (stub) |
| `internal/` | gateway packages: `config`, `principal`, `pep` (decision types, fail-closed evaluation), and stubs for `transport`, `authn`, `router`, `broker`, `supervisor`, `audit` |
| `policy/` | default OPA policy bundle (`data.mcp.authz.decision`, `data.mcp.filter.visible`), RBAC data and tests |
| `selinux/` | `mcp_gateway` SELinux policy module (placeholder: domains, types, isolation invariants) |
| `systemd/` | `mcp-gateway.service`, `mcp-opa.service` |
| `config/` | example `gateway.yaml` and backend definitions (`servers.d/`) |
| `packaging/` | sysusers.d and polkit snippets |

## Development

Requirements: Go ≥ 1.24, [`opa`](https://www.openpolicyagent.org/docs/latest/#running-opa),
`golangci-lint`, and for the SELinux module the reference-policy devel
files (`selinux-policy-dev` on Debian/Ubuntu, `selinux-policy-devel` on
Fedora) plus `checkpolicy`.

```bash
make build      # bin/mcp-gateway, bin/mcp-connect
make check      # gofmt/opa fmt, go vet, go test, opa check, opa test
make lint       # golangci-lint
make selinux    # selinux/mcp_gateway.pp

bin/mcp-gateway --check --config config/gateway.yaml
```

CI builds the SELinux module against Ubuntu's reference policy; the
module uses `ifdef` shims where reference policy and Fedora policy
differ.
