# 4. MCP servers

The gateway runs MCP servers that speak MCP over **stdio**. Each server is
registered by a small YAML file; the gateway starts instances of it on
demand, one per principal (or per session), confined by systemd and
SELinux, and stops them when idle.

## Registering a server

Create one file per server in `/etc/mcp-gateway/servers.d/` (packages
install theirs to `/usr/share/mcp-gateway/servers.d/`), then check and
restart:

```yaml
# /etc/mcp-gateway/servers.d/git.yaml
name: git
command: ["/usr/libexec/mcp-servers/mcp-git"]
```

```bash
mcp-gateway --check
systemctl restart mcp-gateway.service
```

A server is only usable by principals whose roles have permissions for it
(chapter 6). A server nobody has permissions for is invisible.

### Overriding and disabling package definitions

A file in `/etc/mcp-gateway/servers.d/` replaces the package file **of
the same file name**; an empty file, or a symlink to `/dev/null`,
disables it:

```bash
# change the demo server
cp /usr/share/mcp-gateway/servers.d/fs-demo.yaml /etc/mcp-gateway/servers.d/
$EDITOR /etc/mcp-gateway/servers.d/fs-demo.yaml

# disable it
ln -s /dev/null /etc/mcp-gateway/servers.d/fs-demo.yaml
```

Server names must be unique across all files.

## Definition reference

| Key | Default | Meaning |
|---|---|---|
| `name` | — (required) | the server's name: lower case letters, digits and `-`, starting with a letter, at most 32 characters. It appears in endpoint paths (`--server git`, `/mcp/git`), in tool name prefixes (`git__commit`) and in policy (`"server": "git"`). |
| `command` | — (required) | the command line; the first element must be an absolute path. `${HOME}` and `${USER}` are replaced by the principal's home directory and name; other `${…}` are left as they are. |
| `env` | none | extra environment variables (map); `${HOME}` and `${USER}` are replaced as in `command` |
| `selinux_type` | `mcpsrv_generic_t` | the SELinux domain instances run in; must be `mcpsrv_<name>_t` (see [SELinux domains](#selinux-domains-for-servers)) |
| `isolation` | `principal` | `principal`: one instance per principal, shared by that principal's sessions. `session`: a new instance per session. |
| `network` | `false` | allow network access. Without it, the instance has a private network namespace and only unix sockets. |
| `run_as` | `principal` | whom the instance runs as: `principal` (the local user; remote users without a local account get a throwaway dynamic user), `dynamic` (always a throwaway dynamic user), or the name of a system account |
| `discovery` | `shared` | where tool and prompt lists come from: `shared` (one gateway-owned instance per server, cached; listing starts no per-user instances), `instance` (each principal's own instance, for servers whose tools depend on the user) |
| `credentials` | none | secrets handed to the server by systemd, see [Secrets](#secrets) |
| `sandbox.protect_home` | `read-only` | access to home directories: `yes` (none), `read-only`, `read-write` |

Example with everything:

```yaml
name: fs
command: ["/usr/libexec/mcp-servers/mcp-fs", "--root", "${HOME}"]
env:
  LOG_LEVEL: info
selinux_type: mcpsrv_fs_t
isolation: principal
network: false
run_as: principal
discovery: shared
sandbox:
  protect_home: read-write
credentials: [fs-license]
```

## What an instance gets

Each instance runs as a transient systemd service named
`mcp-<server>-<id>.service` with:

- **stdio** connected to the gateway (a private socket pair); **stderr**
  goes to the journal of the unit;
- the **environment** `PATH=/usr/local/bin:/usr/bin`, `LANG=C.UTF-8`,
  `HOME` and `USER` of the principal (if it has a local account), and
  the definition's `env`;
- the **working directory** of the principal's home (local principals);
- a **sandbox**: `NoNewPrivileges`, `ProtectSystem=strict` (the whole
  file system read-only except `/dev`, `/proc`, `/sys` and the home as
  configured), `ProtectHome` as configured, private `/tmp` and `/dev`, no
  capabilities, the `@system-service` system call set only, protected
  kernel tunables, modules, logs, clock, hostname and control groups,
  `UMask=0077`; without `network: true` a private network namespace and
  only `AF_UNIX` sockets;
- **limits**: 512 MiB memory, 64 tasks, 8 hours runtime;
- with SELinux: the definition's domain and a unique **MCS category
  pair**, so instances running as the same account (for example dynamic
  users of different remote principals) cannot touch each other.

### Lifecycle

- An instance starts with the first call that needs it and is shared by
  the principal's sessions (`isolation: principal`) or belongs to one
  session (`isolation: session`).
- It stops `supervisor.idle_timeout` (15 minutes) after its last session
  ended, or at session end with `isolation: session`.
- If it crashes or fails to start, the next start of the same instance
  waits: 1 s, then doubling up to 2 minutes; meanwhile calls fail at once
  with `backend unavailable; retry in …`. A minute of stable running
  resets the wait.
- Administrators (and each principal for their own instances) can list
  and stop instances in Cockpit (chapter 8) or through the control API.

### Discovery instances

With `discovery: shared`, tool, prompt and resource template lists come
from one instance per server that the gateway runs for its own principal
`mcp-discovery`: no local account (a dynamic user, home `/`), only list
requests. The lists are cached until the server reports a change or the
instance stops. Connecting and listing therefore start no per-user
instances; calls and `resources/list` (which lists user data, such as a
user's files) always run on the principal's own instance.

Use `discovery: instance` for servers whose tool list depends on the user
(for example on files in the home directory or the user's configuration).

## Secrets

MCP servers often need an API token. The gateway never handles such
secrets itself: systemd reads them and hands them to the instance.

```yaml
credentials:
  - github-token                       # reads /etc/mcp-gateway/credentials/github-token
  - db-password:/etc/db/mcp-password    # reads the given path
```

```bash
install -m 0600 /dev/stdin /etc/mcp-gateway/credentials/github-token <<<'ghp_…'
```

The server finds each secret as the file `$CREDENTIALS_DIRECTORY/<name>`
(systemd's `LoadCredential=`). Names consist of letters, digits, `_`,
`.` and `-`; paths must be absolute. `/etc/mcp-gateway/credentials` is
mode 0700 and labelled `mcpgw_cred_t`, which neither the gateway nor any
MCP server may read. Every instance of the server gets the same secret;
servers that need per-user secrets must obtain them otherwise.

Many servers expect the token in an environment variable. Wrap them:

```bash
#!/bin/sh
# /usr/libexec/mcp-servers/mcp-github-wrapper
GITHUB_TOKEN=$(cat "$CREDENTIALS_DIRECTORY/github-token")
export GITHUB_TOKEN
exec /usr/libexec/mcp-servers/mcp-github "$@"
```

Label such a wrapper like the server itself (it becomes the entry point
of the domain, see [SELinux domains](#selinux-domains-for-servers)).

## Examples

### A file server on the user's home

```yaml
name: fs
command: ["/usr/libexec/mcp-servers/mcp-fs", "--root", "${HOME}"]
selinux_type: mcpsrv_fs_t          # may read and write user home content
sandbox:
  protect_home: read-write
```

Policy decides what the principal may do within the home (for example:
read freely, write only with approval, never delete; chapter 6).

### A server with network access and an API token

```yaml
name: github
command: ["/usr/libexec/mcp-servers/mcp-github-wrapper"]
selinux_type: mcpsrv_github_t      # needs a module allowing HTTPS, see below
network: true
run_as: dynamic                    # no need for the user's account
sandbox:
  protect_home: yes
credentials: [github-token]
```

### A server installed with npm or pip

Install the server on the host (not with `npx -y` or `uvx` at run time,
which needs network access, a writable home and downloads code on every
start), then reference its absolute path:

```bash
npm install -g @example/mcp-server-postgres        # /usr/local/bin/mcp-server-postgres
```

```yaml
name: postgres
command: ["/usr/local/bin/mcp-server-postgres", "postgresql://localhost/app"]
network: true
run_as: dynamic
```

Interpreted servers run through their interpreter (`node`, `python3`);
see the SELinux note below.

### A server per session

```yaml
name: scratch
command: ["/usr/libexec/mcp-servers/mcp-scratchpad"]
isolation: session                  # fresh state for every agent session
run_as: dynamic
```

## SELinux domains for servers

Without `selinux_type`, instances run in `mcpsrv_generic_t`, the most
restricted domain: it may use its stdio, load libraries, read `/etc`
and the localization files, and log to syslog. That is enough for simple
servers, not for ones that read the home directory or use the network.

A dedicated domain comes from a small policy module using the gateway's
template:

```
# mcp_git.te
policy_module(mcp_git, 1.0)

mcp_gateway_backend_template(git)

# What the server needs, e.g.:
mcp_gateway_backend_home_rw(mcpsrv_git_t)       # read and write user home content
corenet_tcp_connect_http_port(mcpsrv_git_t)      # HTTPS to a forge
sysnet_dns_name_resolve(mcpsrv_git_t)
files_read_usr_files(mcpsrv_git_t)               # e.g. scripts below /usr
```

```
# mcp_git.fc
/usr/libexec/mcp-servers/mcp-git   --   gen_context(system_u:object_r:mcpsrv_git_exec_t,s0)
```

```bash
make -f /usr/share/selinux/devel/Makefile mcp_git.pp   # needs selinux-policy-devel
semodule -i mcp_git.pp
restorecon -v /usr/libexec/mcp-servers/mcp-git
```

Then set `selinux_type: mcpsrv_git_t` in the definition.

Notes:

- `mcp-gateway-selinux` installs the template's interface file
  (`/usr/share/selinux/devel/include/services/mcp_gateway.if`), so
  building a module needs only `selinux-policy-devel`.
- Servers that talk to system services over D-Bus (systemd, firewalld,
  snapper) need `dbus_system_bus_client(mcpsrv_<name>_t)` and the
  service's chat interface, e.g. `init_dbus_chat` or
  `firewalld_dbus_chat`; what the service then allows the instance's
  user is up to its polkit rules.
- The template defines `mcpsrv_<name>_t` and `mcpsrv_<name>_exec_t`.
  If the server's program keeps a generic label (for example an
  interpreter such as `/usr/bin/node`, labelled `bin_t`), also add
  `corecmd_bin_entry_type(mcpsrv_<name>_t)`, and allow reading the
  scripts (`files_read_usr_files`).
- To find missing rules, run the domain permissive for a while
  (`semanage permissive -a mcpsrv_git_t`), use the server, then read
  `ausearch -m AVC -ts recent | audit2allow`. Remove the permissive
  setting afterwards.
- The gateway's isolation rules still apply to every server domain: no
  access to the gateway's and OPA's sockets, no writes to the gateway's
  configuration or state, no reading of the credentials directory.

## Packaging a server for the gateway (openSUSE / OBS)

An MCP server package makes itself available by installing its definition
to `/usr/share/mcp-gateway/servers.d/<name>.yaml` and, for a dedicated
domain, a policy module. See `packaging/suse/README.md`, section
"Packaging an MCP server for the gateway", and `packaging/demo/` for the
demo server's package.
