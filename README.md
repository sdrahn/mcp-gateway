# mcp-gateway

A policy-enforcing gateway that makes local, stdio-only
[MCP](https://modelcontextprotocol.io/) servers available to local and
remote MCP clients, with:

- access control / RBAC,
- permission elicitation (human approval of sensitive actions),
- [OPA](https://www.openpolicyagent.org/) as the policy engine,
- SELinux confinement of the gateway, the policy engine and every MCP server.

Target distributions: openSUSE (Tumbleweed, Leap) and SLES, packaged with
the Open Build Service; see [packaging/suse](packaging/suse/README.md).

Status: proof of concept; local clients (unix socket) and remote clients
(MCP Streamable HTTP with OAuth bearer tokens). The
[user guide](docs/user-guide/README.md) covers installation,
configuration, MCP servers, clients, policy (including custom Rego),
approvals and operations;
see [docs/architecture.md](docs/architecture.md) for the design and
[examples/poc](examples/poc/README.md) to try it.

## Repository layout

| Path | Contents |
|---|---|
| `cmd/mcp-gateway` | gateway daemon |
| `cmd/mcp-connect` | stdio ↔ unix-socket shim for local clients |
| `cmd/mcp-gateway-notify` | desktop notifications for approvals (per-user agent) |
| `internal/` | `transport` (unix socket, peer credentials, hello; Streamable HTTP), `authn` (peer credentials; OAuth/JWT), `router` (MCP proxy core), `pep` (OPA client, fail-closed evaluation), `broker` (approvals via form/URL/out-of-band, grants), `control` (approvals, grants, servers and policy status API on a unix socket), `supervisor` (systemd / exec launchers, MCS allocation), `notify` (approval mail), `notifyagent` (desktop notifications), `jsonrpc`, `audit`, `config`, `principal` |
| `cockpit/` | Cockpit page (approvals and grants, servers and instances, role bindings, audit records) and its smoke test |
| `examples/` | `mcp-fs-demo` (demo MCP server) and the PoC walkthrough |
| `e2e/` | end-to-end tests: OPA + gateway + mcp-connect or an HTTPS client with a test IdP + demo servers |
| `policy/` | default OPA policy bundle (`data.mcp.authz.decision`, `data.mcp.filter.visible`), RBAC data and tests |
| `selinux/` | `mcp_gateway` SELinux policy module (domains, types, isolation invariants, PoC launch path) |
| `systemd/` | `mcp-gateway.service`, `mcp-opa.service` |
| `tools/` | `mcp-policy-bundle`: builds and signs a policy bundle |
| `config/` | example `gateway.yaml` and backend definitions (`servers.d/`) |
| `packaging/` | OBS package for openSUSE/SLES (`suse/`), `mcp-opa.service` drop-ins for signed bundles (`opa/`), sysusers.d, polkit rule, demo server definition |
| `docs/` | [user guide](docs/user-guide/README.md), [architecture](docs/architecture.md) |

## Development

Requirements: Go ≥ 1.24, [`opa`](https://www.openpolicyagent.org/docs/latest/#running-opa),
`golangci-lint`, and for the SELinux module the reference-policy devel
files (`selinux-policy-devel` on openSUSE/SLES and Fedora,
`selinux-policy-dev` on Debian/Ubuntu) plus `checkpolicy`.

```bash
make build      # bin/mcp-gateway, bin/mcp-connect, bin/mcp-fs-demo
make check      # gofmt/opa fmt, go vet, go test (incl. e2e if opa is found), opa check, opa test
make lint       # golangci-lint
make selinux    # selinux/mcp_gateway.pp
make install install-selinux install-cockpit install-demo DESTDIR=... # see the Makefile's directory variables

bin/mcp-gateway --check --config config/gateway.yaml
```

CI builds the SELinux module against Ubuntu's reference policy and, in
the openSUSE job, against openSUSE's policy while building the RPMs; the
module uses `ifdef` shims where reference policy and Fedora-derived
policies (openSUSE, Fedora) differ.

## License

MIT; see [LICENSE](LICENSE).
