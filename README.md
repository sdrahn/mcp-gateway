# mcp-gateway

A policy-enforcing gateway that makes local, stdio-only
[MCP](https://modelcontextprotocol.io/) servers available to local and
remote MCP clients, with:

- access control / RBAC,
- permission elicitation (human approval of sensitive actions),
- [OPA](https://www.openpolicyagent.org/) as the policy engine,
- pseudonymization of personal data before it reaches external LLMs,
- SELinux confinement of the gateway, the policy engine and every MCP server.

Target distributions: SLES 16 and openSUSE Leap 16 (openSUSE Tumbleweed
for development), packaged with the Open Build Service; see
[packaging/suse](packaging/suse/README.md).

Status: released (0.14.0), ready to be used; working towards 1.0 for
SLES 16 and Leap 16 (roadmap in [docs/architecture.md](docs/architecture.md),
section 11). Releases marked as pre-releases on GitHub (tags such as
v1.0.0-rc1) bring new features ahead of the next release recommended for
use.
Packages are built and tested in VMs on Leap 16 and Tumbleweed for every
change; from 0.4 on, configuration, role data and APIs change compatibly
([CHANGELOG](CHANGELOG.md)). Local clients connect over a unix socket,
remote clients over MCP Streamable HTTP with OAuth bearer tokens. The
[user guide](docs/user-guide/README.md) covers installation,
configuration, MCP servers, clients, policy (including custom Rego),
approvals and operations; see [docs/architecture.md](docs/architecture.md)
for the design and [examples/dev](examples/dev/README.md) to run it from a
checkout.

## Repository layout

| Path | Contents |
|---|---|
| `cmd/mcp-gateway` | gateway daemon |
| `cmd/mcp-gateway-admin` | commands for administrators: doctor, the server `gateway-admin` (diagnostics for agents: doctor, configuration, policy explanations, audit records) |
| `cmd/mcp-gateway-tools` | inspect, profile and review, run by `mcp-gateway-admin` (package `mcp-gateway-tools`) |
| `cmd/mcp-connect` | stdio ↔ unix-socket shim for local clients |
| `cmd/mcp-gateway-notify` | desktop notifications for approvals (per-user agent) |
| `cmd/mcp-http-connector` | each instance of a server defined with `url`: relays between the gateway (stdio) and an MCP server that speaks Streamable HTTP, directly or through a proxy, in its own domain (`mcpsrv_http_t`) |
| `cmd/mcp-oauth-helper` | the requests of a user's sign-in to a server with `sign_in` (discovery, registration, code exchange, refresh, revocation), one step per run in its own domain (`mcpsrv_oauth_t`) |
| `internal/` | `transport` (unix socket, peer credentials, hello; Streamable HTTP), `authn` (peer credentials; OAuth/JWT), `router` (MCP proxy core, live reload), `pep` (OPA client, fail-closed evaluation), `broker` (approvals via form/URL/out-of-band, grants), `control` (approvals, grants, servers and policy status API on a unix socket), `supervisor` (systemd / exec launchers, MCS allocation, network limits of HTTP servers), `fswatch` (inotify for configuration and policy), `signin` (users' sign-ins to servers, the encrypted token store), `oauth` (OAuth client side, the helper's steps), `egress` (the HTTP clients of the connector and the helper), `notify` (approval mail), `notifyagent` (desktop notifications), `pseudo` (pseudonymization), `doctor`, `inspect`, `profile` and `review` (the administrator's commands), `policydata` (role data checks), `contract` (fixed fields of the interfaces), `metrics`, `mcpserver` (protocol core of the shipped servers), `jsonrpc`, `audit`, `config`, `principal`, `statedir`, `version` |
| `cockpit/` | Cockpit page (approvals and grants, servers and instances, role bindings, audit records) and its smoke test |
| `cmd/mcp-server-fs/` | the file server (package `mcp-gateway-fs-server`) |
| `cmd/mcp-server-exec/` | the command server for commands an administrator allows (package `mcp-gateway-exec-server`) |
| `examples/` | running the gateway from a checkout (`examples/dev`) |
| `e2e/` | end-to-end tests: OPA + gateway + mcp-connect or an HTTPS client with a test IdP + the file server |
| `test/` | reference-client compatibility suite (`clients/`: Go, Python, TypeScript), compatibility with earlier releases' files (`compat/`), VM tests on Leap 16 and Tumbleweed (`vm/`) |
| `policy/` | default OPA policy bundle (`data.mcp.authz.decision`, `data.mcp.filter.visible`), RBAC data and tests |
| `selinux/` | `mcp_gateway` SELinux policy module (domains, types, isolation invariants) and the modules of the server setups |
| `profiles/` | server setups for system management (zypp, systemd, firewalld, snapper, SUSEConnect): definitions and roles, packaged as `mcp-gateway-profile-<name>` |
| `systemd/` | `mcp-gateway.service`, `mcp-opa.service` |
| `tools/` | `mcp-policy-bundle`: builds and signs a policy bundle; `check-release`: checks a commit is ready to be tagged (run by the Release workflow); `check-tree`: checks a commit holds sources only (run by CI) |
| `config/` | example `gateway.yaml` and backend definitions (`servers.d/`) |
| `packaging/` | OBS package for openSUSE/SLES (`suse/`), `mcp-opa.service` drop-ins for signed bundles (`opa/`), sysusers.d, tmpfiles.d, polkit rule, the shipped servers' definitions and roles (`fs-server/`, with the server of the gateway's own docs; `exec-server/`; `admin/`), MCS settings for libvirt (`mcs/`), the notification agent's autostart (`desktop/`) |
| `docs/` | [user guide](docs/user-guide/README.md), [architecture](docs/architecture.md) |

## Development

Requirements: Go ≥ 1.24, [`opa`](https://www.openpolicyagent.org/docs/latest/#running-opa),
`golangci-lint`, and for the SELinux module the reference-policy devel
files (`selinux-policy-devel` on openSUSE/SLES and Fedora,
`selinux-policy-dev` on Debian/Ubuntu) plus `checkpolicy`.

```bash
make build      # bin/mcp-gateway, bin/mcp-gateway-admin, bin/mcp-gateway-tools, bin/mcp-connect, bin/mcp-gateway-notify, bin/mcp-server-fs, bin/mcp-server-exec
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
