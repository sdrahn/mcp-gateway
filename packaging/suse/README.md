# Packaging for openSUSE and SLES (OBS)

`mcp-gateway.spec`, `_service` and `mcp-gateway-rpmlintrc` are ready to be
used in an Open Build Service project. CI builds the same spec in an
openSUSE Tumbleweed container (job `opensuse` in `.github/workflows/ci.yml`),
including rpmlint and an installation test.

## Setting up the OBS package

```bash
osc mkpac mcp-gateway            # in your project, e.g. home:<you>
cd mcp-gateway
cp <repo>/packaging/suse/{mcp-gateway.spec,_service,mcp-gateway-rpmlintrc} .
osc service manualrun            # fetch sources, set version, vendor Go modules
osc vc -m "Initial package"      # creates mcp-gateway.changes
osc add *
osc commit
```

The services run in `manual` mode: `tar_scm` fetches `main` from GitHub and
names the tarball `mcp-gateway-0.1.0+git<date>.<hash>.tar.gz`, `set_version`
puts that version into the spec, and `go_modules` creates `vendor.tar.gz`,
because OBS builds have no network access. Re-run `osc service manualrun` to
update, then `osc vc` and commit.

Build targets: openSUSE Tumbleweed, Leap 16 and SLES 16 out of the box. For
Leap/SLES 15 the build needs Go ≥ 1.24 (`golang(API) >= 1.24`, e.g. from
`devel:languages:go`); note that SLES 15 uses AppArmor rather than SELinux,
so `mcp-gateway-selinux` does not apply there.

## Packages

| Package | Contents |
|---|---|
| `mcp-gateway` | `mcp-gateway`, `mcp-connect`, systemd units, sysusers config, default configuration, policy, polkit rule |
| `mcp-gateway-selinux` | SELinux module `mcp_gateway` (installed with the `%selinux_*` macros); pulled in automatically where `selinux-policy-targeted` is installed |
| `mcp-gateway-cockpit` | the approvals page for Cockpit (`/usr/share/cockpit/mcp-gateway`) |
| `mcp-gateway-demo-server` | demo filesystem MCP server, registered as server `fs` |

`mcp-gateway` requires `opa` (the Open Policy Agent binary at
`/usr/bin/opa`). If your target repositories do not provide it, build it in
the same project or link it from a project that does.

## Filesystem layout

The layout separates vendor files (below `/usr`, owned by packages) from
the administrator's (below `/etc`), which suits transactional systems
(MicroOS, SLE Micro) and `/usr/etc` (UsrEtc):

| Path | What | Owner |
|---|---|---|
| `/usr/etc/mcp-gateway/gateway.yaml` | default configuration (`%{_distconfdir}`; `/etc` where the distribution has no `/usr/etc`) | package |
| `/etc/mcp-gateway/gateway.yaml` | local configuration; read instead of the default if it exists | admin |
| `/usr/share/mcp-gateway/servers.d/*.yaml` | MCP server definitions shipped by packages | packages |
| `/etc/mcp-gateway/servers.d/*.yaml` | local definitions; a file with the same name overrides a vendor file, an empty file or a symlink to `/dev/null` disables it | admin |
| `/usr/share/mcp-gateway/policy/` | policy logic (Rego) | package |
| `/etc/mcp-gateway/policy/rbac/data.json` | roles and bindings (`%config(noreplace)`) | admin |
| `/var/lib/mcp-gateway/` | persistent grants (`StateDirectory=`) | service |
| `/run/mcp-gateway/` | sockets (`RuntimeDirectory=`) | service |

After installation:

```bash
systemctl enable --now mcp-gateway.service      # pulls in mcp-opa.service
usermod -aG mcp-users <user>                    # who may connect
```

## Packaging an MCP server for the gateway

An MCP server package makes itself available through the gateway by
installing a definition to `/usr/share/mcp-gateway/servers.d/<name>.yaml`
(see `config/servers.d/fs.yaml` and `packaging/demo/fs-demo.yaml.in`):

```yaml
name: git
command: ["/usr/libexec/mcp-servers/mcp-git"]
selinux_type: mcpsrv_git_t      # default: mcpsrv_generic_t (most restricted)
network: true                   # default: false
```

For a dedicated SELinux domain, ship a small policy module that uses the
template from `mcp_gateway.if` (build-require `selinux-policy-devel` and
install `mcp_gateway.if` alongside, or copy the template):

```
policy_module(mcp_git, 1.0)
mcp_gateway_backend_template(git)
corenet_tcp_connect_http_port(mcpsrv_git_t)
```

and label the binary `mcpsrv_git_exec_t` in its `.fc` file. Without a
module, servers run in `mcpsrv_generic_t`.

## Before submitting to openSUSE:Factory or SLE

- **License:** the repository has no `LICENSE` file yet; the spec says
  `MIT` with a FIXME. Set the real license and add `%license LICENSE`.
- **polkit rule:** `50-mcp-gateway.rules` lets the `mcp-gateway` user
  start and stop `mcp-*.service` transient units. polkit rules need review
  and whitelisting by the SUSE security team (open a bug for
  "polkit-default-privs"/security review); `mcp-gateway-rpmlintrc` filters
  the rpmlint errors only to keep devel/home builds working.
- **opa:** must be available in the target distribution.
- **Security review:** the package runs a network-facing daemon; SUSE's
  security team reviews such packages as part of the Factory submission.
