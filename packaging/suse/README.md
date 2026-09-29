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

### Releases

Each release has a branch `release-X.Y` and tags `vX.Y.Z`. Pushing a tag
publishes a GitHub release with `mcp-gateway-X.Y.Z.tar.gz`,
`vendor.tar.gz` and `SHA256SUMS` (`.github/workflows/release.yml`). On a
release branch, `_service` fetches that branch and takes the version from
its latest tag (`@PARENT_TAG@` without the leading `v`), so the package
version is `X.Y.Z`. For an OBS project that follows a release, use the
`_service` of that branch, run `osc service manualrun`, then
`osc vc -m "Update to X.Y.Z"` with the release's CHANGELOG.md section, and
commit.

Build targets: openSUSE Tumbleweed, Leap 16 and SLES 16 out of the box. For
Leap/SLES 15 the build needs Go ≥ 1.24 (`golang(API) >= 1.24`, e.g. from
`devel:languages:go`); note that SLES 15 uses AppArmor rather than SELinux,
so `mcp-gateway-selinux` does not apply there.

## Packages

| Package | Contents |
|---|---|
| `mcp-gateway` | `mcp-gateway`, `mcp-connect`, `mcp-policy-bundle`, systemd units and OPA drop-ins, sysusers config, default configuration, policy, polkit rule |
| `mcp-gateway-selinux` | SELinux module `mcp_gateway` (installed with the `%selinux_*` macros); pulled in automatically where `selinux-policy-targeted` is installed |
| `mcp-gateway-cockpit` | the Cockpit page (`/usr/share/cockpit/mcp-gateway`): approvals and grants, servers and instances, role bindings, audit records |
| `mcp-gateway-desktop` | `mcp-gateway-notify`: desktop notifications for approvals the logged-in user may decide on (XDG autostart) |
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
| `/etc/mcp-gateway/policy/rbac/data.json` | roles, bindings and approver rules (`%config(noreplace)`) | admin |
| `/usr/share/mcp-gateway/mcs/` | drop-ins confining libvirt's MCS categories to c0.c767, away from the gateway's (`virtqemud.conf`, `libvirtd.conf`) | package |
| `/usr/share/mcp-gateway/opa/` | `mcp-opa.service` drop-ins for signed bundles (`signed-bundle.conf`, `bundle-server.conf`) and an OPA configuration example | package |
| `/etc/mcp-gateway/bundle/` | signed policy bundle (`policy.tar.gz`, from `mcp-policy-bundle`), its verification key (`verify.pem`) and, if signing happens on the host, the signing key (`signing.pem`, 0600, `mcpgw_signing_key_t`; `mcp-policy-bundle -G`) | admin |
| `/etc/mcp-gateway/credentials/` | secrets for MCP servers (`credentials:` in their definitions), mode 0700, label `mcpgw_cred_t`; read by systemd, never by the gateway | admin |
| `/var/lib/mcp-gateway/` | persistent grants and pending approvals, audit key (`StateDirectory=`) | service |
| `/run/mcp-gateway/` | sockets; created by `tmpfiles.d/mcp-gateway.conf` (0771, shared by both services) | service |

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

- **Licenses:** mcp-gateway is MIT. The binaries also contain the
  vendored Go modules: MIT (golang-jwt, yaml.v3), Apache-2.0 (go-systemd,
  parts of yaml.v3), BSD-2-Clause (godbus) and BSD-3-Clause
  (golang.org/x/sys), all permissive and compatible. Reviewers may ask for
  the bundled licenses in the `License:` tag (e.g. `MIT AND Apache-2.0 AND
  BSD-2-Clause AND BSD-3-Clause`).
- **polkit rule:** `50-mcp-gateway.rules` lets the `mcp-gateway` user
  start and stop `mcp-*.service` transient units. polkit rules need review
  and whitelisting by the SUSE security team (open a bug for
  "polkit-default-privs"/security review); `mcp-gateway-rpmlintrc` filters
  the rpmlint errors only to keep devel/home builds working.
- **opa:** must be available in the target distribution.
- **Security review:** the package runs a network-facing daemon; SUSE's
  security team reviews such packages as part of the Factory submission.
