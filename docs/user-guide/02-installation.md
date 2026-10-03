# 2. Installation

## Requirements

- **SLES 16 or openSUSE Leap 16**; openSUSE Tumbleweed is built too, as
  the development platform. SLES 15 and Leap 15 are not supported (they
  use AppArmor; the confinement relies on SELinux).
- **OPA** (`/usr/bin/opa`), the Open Policy Agent binary.
- **SELinux** in enforcing mode is recommended (the gateway also runs
  without it, with less isolation).
- For the web console: **Cockpit** (`cockpit`, `cockpit-bridge`).
- For remote agents: an OAuth 2.1 / OpenID Connect identity provider and
  a TLS certificate for the gateway.

## Installing the packages (openSUSE / SLES)

The packages are built in the Open Build Service (`packaging/suse`). Add
the repository of the OBS project that builds them and install:

```bash
zypper addrepo https://download.opensuse.org/repositories/<project>/<distribution>/ mcp-gateway
zypper refresh
zypper install mcp-gateway            # daemon, mcp-connect, policy, units
zypper install mcp-gateway-cockpit    # optional: web console page
zypper install mcp-gateway-desktop    # optional: desktop notifications
zypper install mcp-gateway-demo-server  # optional: demo server "fs"
```

`mcp-gateway-selinux` is pulled in automatically where the targeted
SELinux policy is installed. The packages create:

| Account / group | Purpose |
|---|---|
| user `mcp-gateway` | runs the gateway |
| user `mcp-opa` | runs OPA |
| group `mcp-gateway` | shared by both (runtime directory) |
| group `mcp-users` | local users allowed to connect to the gateway |

### Transactional systems

On openSUSE MicroOS, SLE Micro, Leap Micro and other systems with
transactional updates, `/usr` is read-only: packages are installed into
a new snapshot that becomes active at the next boot.

```bash
transactional-update pkg install mcp-gateway mcp-gateway-profile-systemd systemd-mcp
reboot
```

- Install a server program and the package with its SELinux module in
  the same transaction, or relabel the program in a later one: a program
  that keeps the label it had before its module was there (for example
  `bin_t`) cannot start in its domain. `mcp-gateway doctor` names such a
  program ("program *name*: … is labeled bin_t, the policy says …") with
  the fix, `transactional-update run restorecon -v <program>` and a
  reboot. `restorecon` alone reports "Read only filesystem".
- `/etc` and `/var` stay writable: definitions, role data and the
  gateway's state are changed as on other systems.
- A privileged server cannot change `/usr`: the privileged zypp server
  cannot install or remove packages (zypper refuses on a read-only
  root); install with `transactional-update` instead. Searching and
  planning work. `mcp-gateway doctor` warns ("read-only /usr").
- Snapshots and the default subvolume belong to transactional-update
  (`transactional-update rollback`); do not use the snapper server's
  `rollback` there.

## First start

```bash
# Who may use the gateway: members of mcp-users.
usermod -aG mcp-users alice

# Start the gateway (it pulls in mcp-opa.service).
systemctl enable --now mcp-gateway.service

# Check.
systemctl status mcp-gateway.service mcp-opa.service
journalctl -u mcp-gateway.service -b
mcp-gateway --check          # validates the configuration and the MCP server definitions
```

`mcp-gateway --check` prints the configuration file in use and the
number of registered MCP servers, or the first error it finds; the unit
runs it before every start.

Out of the box the gateway:

- listens on `/run/mcp-gateway/mcp.sock` (mode 0660, group `mcp-users`
  as shipped in `gateway.yaml`) and serves the control API on
  `/run/mcp-gateway/control.sock`;
- knows the MCP servers defined in `/usr/share/mcp-gateway/servers.d`
  (installed by packages) and `/etc/mcp-gateway/servers.d` (yours);
- decides with the shipped policy and the role data in
  `/etc/mcp-gateway/policy/rbac/data.json` (roles `viewer`, `developer`,
  `admin`; group `dev` → developer, group `wheel` → admin);
- does not listen on the network (remote access is off until configured,
  chapter 5).

Users must log in again after being added to `mcp-users`.

### Try it with the demo server

```bash
zypper install mcp-gateway-demo-server
systemctl restart mcp-gateway.service
usermod -aG dev alice           # "developer" role in the shipped role data
```

As alice (after logging in again), start an MCP client with
`mcp-connect --server fs`, or talk to it directly:

```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 | mcp-connect --server fs
```

The developer role may read and list files in the home directory, must get
approval to write (on the approval page), and may not delete.

## SELinux

With `mcp-gateway-selinux` installed:

```bash
semodule -l | grep mcp_gateway           # module loaded
ps -eZ | grep -E 'mcpgw_t|mcpopa_t'      # gateway and OPA in their domains
```

Booleans (all off by default):

| Boolean | Turn on when |
|---|---|
| `mcpopa_can_network` | OPA fetches policy bundles from a bundle server (chapter 6) |
| `mcpgw_can_send_mail` | the gateway sends approval mail (chapter 7) |

```bash
setsebool -P mcpgw_can_send_mail on
```

For remote access, label the HTTPS port:

```bash
semanage port -a -t mcp_port_t -p tcp 8443
```

## Other packages

- **Cockpit page** (`mcp-gateway-cockpit`): enable Cockpit
  (`systemctl enable --now cockpit.socket`) and open
  `https://<host>:9090`, section "MCP Gateway". Chapter 8.
- **Desktop notifications** (`mcp-gateway-desktop`): starts with every
  graphical session (XDG autostart) and does nothing for users outside
  `mcp-users`. Chapter 7.

## Installing from source

```bash
git clone https://github.com/sdrahn/mcp-gateway.git && cd mcp-gateway
make build                       # bin/mcp-gateway, mcp-connect, mcp-gateway-notify, mcp-fs-demo
sudo make install install-selinux install-cockpit install-desktop install-demo \
     PREFIX=/usr SYSCONFDIR=/etc DISTCONFDIR=/usr/etc
sudo systemd-sysusers /usr/lib/sysusers.d/mcp-gateway.conf
sudo semodule -i /usr/share/selinux/packages/targeted/mcp_gateway.pp.bz2
sudo restorecon -RF /etc/mcp-gateway /usr/etc/mcp-gateway /usr/bin/mcp-gateway
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-gateway.service
```

Build requirements: Go ≥ 1.24, `opa` (tests), `golangci-lint` (lint),
and the SELinux reference policy development files for the module
(`selinux-policy-devel` on openSUSE). `make check` runs formatting, vet,
unit and end-to-end tests and the policy tests.

The Makefile's directory variables (`PREFIX`, `BINDIR`, `SBINDIR`,
`LIBEXECDIR`, `DATADIR`, `SYSCONFDIR`, `DISTCONFDIR`, `UNITDIR`,
`SYSUSERSDIR`, `POLKITDIR`, `COCKPITDIR`, `SELINUXDIR`, `DESTDIR`) adapt the
layout to other distributions.

The gateway starts MCP server instances as transient systemd units over
D-Bus. The package's polkit rule
(`/usr/share/polkit-1/rules.d/50-mcp-gateway.rules`) lets the
`mcp-gateway` user start and stop units named `mcp-*.service`, and
nothing else.

## Development mode

For trying the gateway without root, systemd units or SELinux:

```bash
examples/poc/run-dev.sh            # OPA + gateway in exec mode, demo server on $HOME
```

`supervisor.mode: exec` starts MCP servers as plain child processes of the
gateway, **without any confinement**. Use it for development only.

## Uninstalling

```bash
systemctl disable --now mcp-gateway.service mcp-opa.service
zypper remove mcp-gateway mcp-gateway-selinux mcp-gateway-cockpit mcp-gateway-desktop mcp-gateway-demo-server
```

`/etc/mcp-gateway` (your configuration) and `/var/lib/mcp-gateway`
(grants, pending approvals, audit key) are left in place; remove them by
hand if they are no longer needed.
