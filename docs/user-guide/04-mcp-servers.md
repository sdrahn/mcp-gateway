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

`mcp-gateway doctor --server git` (as root) then checks that the server
starts, that roles do not name tools it lacks, and whether SELinux
denied it something (chapter 10, "Self-check").

### Inspecting a server

`mcp-gateway inspect` starts a server, lists its tools, prompts and
resource templates, classifies each tool as reading or changing, and
drafts roles for it. Use it before writing roles, and to check roles
after a server update:

```bash
# A registered server, started as the gateway starts it for discovery
# (through systemd, in its sandbox and SELinux domain; as root):
mcp-gateway inspect --server git

# Check role data against the tools the server really has:
mcp-gateway inspect --server git --roles /etc/mcp-gateway/policy/rbac/data.json

# A server not registered yet, as a plain child process of yours (no
# sandbox: only for servers you trust; refused as root). Writes the
# drafts git.yaml and roles.json to ./git-drafts:
mcp-gateway inspect --name git --out ./git-drafts -- /usr/libexec/mcp-servers/mcp-git
```

The report shows for each tool its class and why: the MCP annotations
the server gives (`readOnlyHint`, `destructiveHint`) and the first word
of its name (`get`, `list`, … read; `set`, `delete`, `install`, …
change). Arguments that look like paths are listed as candidates for an
`args` constraint (chapter 6).

The drafted roles are `<server>-reader`, with the tools the server marks
read-only by exact name, and `<server>-operator`, which adds every other
tool after an out-of-band approval. Tools that only their name marks as
reading need approval in the draft: annotations and names come from the
server and prove nothing. Review the report, move tools you have checked
into the reader role (or use `--read-by-name`), and copy the roles into
your role data or a setup package.

The role check reports a permission that names a tool or prompt the
server does not have as an error (exit status 1), a pattern that matches
none as a warning, and tools no permission names as information. A
server that changes its tools in an update shows up this way before
users miss them.

What a server lists can depend on how it runs: mcp-server-zypp offers
its installing tools only as root (the privileged definition), and
systemd-mcp offers `get_man_page` only where `man` is installed.
`inspect` reports what the definition it starts offers on this system;
check roles meant for another definition with that definition (for
example through `--config` with a configuration whose `servers_dir`
holds it).

What `inspect` does not find out is what the server needs from the
system: SELinux rules, polkit actions, an account, the network. That is
what `mcp-gateway profile` is for.

### Profiling a server

`mcp-gateway profile` runs a registered server with its SELinux domain
permissive (only that domain), calls its tools and drafts a policy
module from the denials of the run:

```bash
# Register the server first (with run_as, if it should run as an account):
cat >/etc/mcp-gateway/servers.d/git.yaml <<'END'
name: git
command: ["/usr/libexec/mcp-servers/mcp-git"]
END

# As root, with selinux-policy-devel installed:
mcp-gateway profile --server git --out ./git-profile
```

A server that still runs in the default domain `mcpsrv_generic_t` gets a
new domain, `mcpsrv_git_t`, from the gateway's template; for one with a
domain of its own, the draft adds to it (`mcp_git_local`). While it
runs, a temporary module `mcpprof_git` makes the domain permissive (and
labels the program), and the policy's dontaudit rules are off
(`semodule -DB`): a denial they keep silent is allowed without a trace in
a permissive domain, and the server would fail on it once enforcing
(firewalld-mcp needs to search `/run/dbus`, which the policy denies
silently). At the end the module is removed and the rules are back on;
both switches rebuild the policy and take a while. `--keep-dontaudit`
skips the switch. The rules are off for the whole system, so the audit
log has denials of other programs from that time too (the gateway's
own scan of `/proc` for MCS categories, for one); they are not
problems.

It calls the tools that read (chapter 4, "Inspecting a server") with
arguments made up from their schemas: enough to run the code that talks
to the system, not to succeed. Real arguments, and calls of other tools,
come from a file:

```json
{"get_file": {"path": "/etc/hosts"}, "log": [{"count": 5}, {"count": 0}]}
```

```bash
mcp-gateway profile --server git --out ./git-profile --calls calls.json
```

`--call-all` calls every tool with made-up arguments: only on a system
that may be changed, such as a test VM.

The drafts directory then holds:

| File | Content |
|---|---|
| `mcp_git.te`, `mcp_git.fc` | the module: the template and one allow rule per kind of access seen, with paths and programs as comments; already compiled to `mcp_git.pp` |
| `git.yaml` | the definition with `selinux_type: mcpsrv_git_t` (and `network: true` if the server connected to the network) |
| `report.txt` | the calls and their answers, the denials, and hints |
| `calls.json` | the calls and their answers, for scripts |

The hints say what allow rules cannot: a helper the server runs that
belongs in its own domain (zypper: `rpm_t`, see
`mcp_gateway_backend_rpm`), capabilities it used (perhaps it should run
as another account), authorizations a service refused (a polkit rule for
the account), and SELINUX_ERR records.

Review the module before loading it: it allows what one run did, which
can be more than the server needs (a path it only looked at), and lacks
what the run did not reach. Replace rules by interfaces of the reference
policy where one fits (`sesearch`, `audit2allow -R`). Then:

```bash
cd git-profile
make -f /usr/share/selinux/devel/Makefile mcp_git.pp && semodule -i mcp_git.pp
restorecon -F /usr/libexec/mcp-servers/mcp-git
cp git.yaml /etc/mcp-gateway/servers.d/    # after comparing it with yours
mcp-gateway --check && systemctl restart mcp-gateway.service

# The same calls, enforcing; fails if there is a denial:
mcp-gateway profile --server git --verify
```

### Reviewing a server's source

A profiling run sees only the code its calls reach. `mcp-gateway review`
reads the server's source for what it does to the system, to find the
rest:

```bash
# The source of the server (for Go: --main, the server's main package,
# so that other programs and tools in the repository are left out).
# --profile: the drafts directory of a profiling run, for its denials.
mcp-gateway review --source ./mcp-git --main ./cmd/mcp-git --profile ./git-profile
```

It lists, each with file and line:

| Kind | What it finds | What it may need |
|---|---|---|
| Programs it runs | `exec.Command`, `subprocess`, `spawn`, `popen`, `Command::new`, paths in `bin`/`libexec` | execute rights, or a transition (zypper, rpm: `rpm_t`) |
| D-Bus | names, interfaces and polkit actions (`org.freedesktop.…`) | talking to the service; a polkit rule for actions |
| Paths | absolute paths in the code | access to their type; writable paths in the sandbox |
| Network | HTTP clients, sockets, URLs | `network: true`, connect rules |
| Root checks | `geteuid()` and the like | the right `run_as`: some servers hide tools from non-root users |
| Environment | variables it reads | `env` in the definition |

On the system it runs on, programs are looked up on root's PATH and each
program and path shows its SELinux type. With `--profile`, every finding
with a type says whether the profiling run recorded a denial for that
type; one without ("not reached, or allowed already") is a code path to
give a call for (`--calls`), or to look at in the code. For systemd-mcp
the review lists `rpm`, `man` and `getfacl`, the polkit actions it
checks itself and `/run/log/journal`, each of which step 10 had to find
by hand.

The scan is textual: it shows what the code mentions, not what each
tool does, and misses what the code puts together at run time. Tests,
vendored code and comments are left out. `--json` prints the findings
for scripts.

### Overriding and disabling package definitions

A file in `/etc/mcp-gateway/servers.d/` replaces the package file **of
the same file name**; an empty file, or a symlink to `/dev/null`,
disables it:

```bash
# change the file server
cp /usr/share/mcp-gateway/servers.d/fs-demo.yaml /etc/mcp-gateway/servers.d/
$EDITOR /etc/mcp-gateway/servers.d/fs-demo.yaml

# disable it
ln -s /dev/null /etc/mcp-gateway/servers.d/fs-demo.yaml
```

Server names must be unique across all files.

## Definition reference

| Key | Default | Meaning |
|---|---|---|
| `version` | `1` | the version of the definition format (see chapter 3, [Format version](03-configuration.md#format-version)) |
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
| `sandbox.read_write_paths` | none | existing absolute paths the instance may write despite `ProtectSystem=strict` (systemd `ReadWritePaths=`); paths of the gateway itself, and directories containing them, are refused |
| `privileged` | `false` | run without the sandbox, with the rights of a root service, for servers that change the system as a whole (package installation); needs `run_as: root` and is accepted only in `/etc/mcp-gateway/servers.d`. See [Privileged servers](#privileged-servers). |
| `sandbox.state_directory` | none | a directory below `/var/lib` (a relative name, e.g. `my-server`) that systemd creates for the instance, owned by its user, mode 0700, writable and kept across instances (systemd `StateDirectory=`) |

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
  configured, the `state_directory` and the `read_write_paths`),
  `ProtectHome` as configured, private `/tmp` and `/dev`, no
  capabilities, the `@system-service` system call set only, protected
  kernel tunables, modules, logs, clock, hostname and control groups,
  `UMask=0077`; without `network: true` a private network namespace and
  only `AF_UNIX` sockets;
- **limits**: 512 MiB memory, 64 tasks, 8 hours runtime;
- with SELinux: the definition's domain and a unique **MCS category
  pair**, so instances running as the same account (for example dynamic
  users of different remote principals) cannot touch each other.

### Writable paths and state

`ProtectSystem=strict` keeps everything but the private `/tmp` read-only,
which also holds for servers running as root. A server that keeps state
in a fixed place gets it with `sandbox.state_directory`:

```yaml
name: suseconnect
command: ["/usr/bin/suseconnect-mcp"]
run_as: root
network: true
sandbox:
  state_directory: suseconnect-mcp     # /var/lib/suseconnect-mcp
```

systemd creates the directory before the instance starts, owned by the
instance's user, and makes it writable; it needs no
`read_write_paths` entry. All instances of the server share it, so it
suits servers with a fixed `run_as`; with `run_as: principal`, systemd
hands it to each user in turn.

`sandbox.read_write_paths` makes other existing paths writable (an
instance whose path does not exist fails to start). Each one widens what
an agent can change through the server: keep the list short and
specific.

Neither option changes SELinux: in enforcing mode the server's domain
also needs write access to these paths, for example a type of its own
for its state directory:

```
# mcp_suseconnect.te (excerpt)
type mcpsrv_suseconnect_var_lib_t;
files_type(mcpsrv_suseconnect_var_lib_t)
manage_dirs_pattern(mcpsrv_suseconnect_t, mcpsrv_suseconnect_var_lib_t, mcpsrv_suseconnect_var_lib_t)
manage_files_pattern(mcpsrv_suseconnect_t, mcpsrv_suseconnect_var_lib_t, mcpsrv_suseconnect_var_lib_t)
files_search_var_lib(mcpsrv_suseconnect_t)
```

```
# mcp_suseconnect.fc (excerpt)
/var/lib/suseconnect-mcp(/.*)?  gen_context(system_u:object_r:mcpsrv_suseconnect_var_lib_t,s0)
```

In development mode (`supervisor.mode: exec`) there is no sandbox, and
both options have no effect.

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

## Privileged servers

A server that installs packages (mcp-server-zypp) writes anywhere below
`/`, changes owners, sets file capabilities and labels and runs package
scripts; no sandbox allows that. Mark such a server `privileged`:

```yaml
# /etc/mcp-gateway/servers.d/zypp.yaml
name: zypp
command: ["/usr/bin/mcp-server-zypp"]
run_as: root
network: true
selinux_type: mcpsrv_zypp_t
privileged: true
```

- Only the administrator's directory may define one: a privileged
  definition in `/usr/share/mcp-gateway/servers.d` stops the gateway
  from starting, so installing a package never creates one (a symlink in
  `/etc` to a shipped file is the administrator's choice).
- The instance runs as a root system service: all capabilities, a
  writable system, no system call filter, no `NoNewPrivileges`; private
  `/tmp`, `UMask=0022`, 4 GiB memory and 4096 tasks; without
  `network: true` still no network. With SELinux it runs in its domain
  **without an MCS pair**, so the files it installs stay readable for
  everyone. The process that installs (the zypp worker, `rpm`) runs in
  `rpm_t`, as with zypper (`mcp_gateway_backend_rpm`, below).
- Calls are allowed without approval only by permissions naming server
  and tool without wildcards (chapter 6); every decision on the server
  goes to the kernel audit log.
- The gateway does not stop the instance while a call is running: not
  after the idle timeout, not from Cockpit, and on `systemctl stop` or
  restart it refuses new calls and waits up to 28 minutes for running
  ones ("waiting for privileged calls").
- `mcp-gateway --check` and the start log warn about every privileged
  server; Cockpit marks them.

SELinux module for mcp-server-zypp (its worker labelled like zypper):

```
# mcp_zypp.te
policy_module(mcp_zypp, 1.0)

mcp_gateway_backend_template(zypp)
mcp_gateway_backend_rpm(zypp)
```

```
# mcp_zypp.fc
/usr/bin/mcp-server-zypp                     --  gen_context(system_u:object_r:mcpsrv_zypp_exec_t,s0)
/usr/libexec/mcp-server-zypp/zypp-mcp-tool   --  gen_context(system_u:object_r:rpm_exec_t,s0)
```

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

The package `mcp-gateway-fs-server` installs `mcp-server-fs` and
registers it as the server `fs` on the connecting user's home directory
(`/usr/share/mcp-gateway/servers.d/fs-demo.yaml`; the file keeps the name
of the demo server's definition, so that a copy of it in
`/etc/mcp-gateway/servers.d` still replaces it):

```yaml
name: fs
command: ["/usr/libexec/mcp-servers/mcp-server-fs", "--root", "${HOME}"]
selinux_type: mcpsrv_fs_t          # may read and write user home content
sandbox:
  protect_home: read-write
```

Its tools have the names and arguments of the MCP project's reference
filesystem server, which agents know:

| Tool | Does |
|---|---|
| `read_text_file` | a text file, whole or its first (`head`) or last (`tail`) lines |
| `read_media_file` | an image, audio or other binary file, base64 with its MIME type |
| `read_multiple_files` | several text files; one that fails does not fail the others |
| `list_directory`, `list_directory_with_sizes` | a directory's entries (`[DIR]`, `[FILE]`, `[LINK]`), with sizes |
| `directory_tree` | the tree below a directory as JSON, without following links |
| `search_files` | paths matching a glob: `*.go` at any depth, `src/**/*.go` relative to the start; `excludePatterns` |
| `get_file_info` | type, size, permissions, times, MIME type |
| `list_allowed_directories` | the directories the server works in |
| `write_file` | creates or replaces a file, at once (temporary file renamed over it) |
| `edit_file` | replaces text that occurs exactly once (`oldText` → `newText`); returns a diff, `dryRun` only shows it |
| `create_directory` | a directory and its parents |
| `move_file` | moves or renames within one directory tree; never replaces |
| `delete_file` | a file or an empty directory |
| `read_file`, `list_dir` | older names, kept for roles that name them |

The last five change files; all tools carry MCP annotations (read-only,
destructive), which `mcp-gateway inspect` uses for its draft roles.
Options, for a copy of the definition in `/etc/mcp-gateway/servers.d`:

| Option | Default | Meaning |
|---|---|---|
| `--root DIR` | current directory | a directory the tools work in; repeatable; relative paths are relative to the first |
| `--read-only` | off | offer only the reading tools |
| `--instructions TEXT` | | what the files are, for the client's model (the `gateway-docs` server uses it; chapter 10, "Asking an agent") |
| `--max-read BYTES` | 10 MiB | what one call reads (summed over `read_multiple_files`); larger files are read with `head`/`tail` |
| `--max-write BYTES` | 10 MiB | what one call writes |
| `--max-entries N` | 10000 | entries a listing, tree or search returns |

On a transactional system (chapter 2), home directories are writable as
anywhere else. A `--root` on the read-only root file system (`/usr`,
`/`) is shown as read-only by `list_allowed_directories` and in the
server's instructions; changes there are refused with "read-only file
system (on a transactional system, … change only through
transactional-update …)", also where a path below a writable root reaches
a read-only mount. `search_files` and `directory_tree` do not enter
btrfs `.snapshots` directories (a copy of the tree per snapper snapshot)
unless the path given is inside one.

Policy decides what the principal may do within the home (for example:
read freely, write only with approval, never delete; chapter 6). The
shipped `developer` role allows the reading tools and asks for approval
for `write_file`, `edit_file`, `create_directory` and `move_file` within
the home; `delete_*` is denied. `move_file` names two paths, so its
permission constrains both (`"args": {"source": …, "destination": …}`).

Policy checks paths as strings and does not follow symbolic links
(chapter 9). If you write or choose a file server, make sure it opens
every path beneath its root, so that a link inside the home cannot
lead to files policy did not allow: in Go with `os.OpenRoot` and the
methods of `os.Root`, in C with `openat2(2)` and `RESOLVE_BENEATH`,
in Python by opening relative to a directory descriptor and refusing
links (`O_NOFOLLOW`) or by checking `os.path.realpath` of the opened
file. `mcp-server-fs` shows the Go way.

### Commands an administrator allows

Agents such as Kit bring their own shell, which runs as the user without
any of the gateway's confinement; you may have turned it off. When an
agent should still run a few commands, `mcp-gateway-exec-server` offers
them as tools of the server `exec`, under the gateway's policy, approvals
and audit, in the domain `mcpsrv_exec_t`, without network, as the calling
user (`run_as: principal`):

```bash
zypper install mcp-gateway-exec-server
cp /usr/share/mcp-gateway/exec/examples.yaml /etc/mcp-gateway/exec.d/
/usr/libexec/mcp-servers/mcp-server-exec --check      # lists the commands, warns
```

Each command in `/etc/mcp-gateway/exec.d/*.yaml` is one tool:

```yaml
version: 1
commands:
  disk_usage:
    description: Space on the mounted file systems
    argv: [/usr/bin/df, -h]
    read_only: true
  unit_log:
    description: The last lines of a unit's journal
    argv: [/usr/bin/journalctl, --no-pager, -u, "{unit}", -n, "{lines}"]
    args:
      unit:  {pattern: "[A-Za-z0-9@._-]+\\.service", description: the unit}
      lines: {pattern: "[0-9]{1,4}", default: "50"}
    timeout: 30s
```

| Key | Default | Meaning |
|---|---|---|
| `argv` | — (required) | the program (an absolute path) and its arguments; `{name}` is replaced by the caller's argument `name`, also inside an element (`--unit={unit}`) |
| `args.NAME.pattern` | — (required) | a regular expression the whole value must match |
| `args.NAME.default` | none (required argument) | the value when the caller gives none |
| `args.NAME.allow_dash` | `false` | let a value start with `-`; otherwise refused, so that it cannot become an option of the program |
| `description` | the command line | what the tool does, for the agent |
| `timeout` | `60s` | then the program and everything it started are killed (at most `1h`) |
| `max_output` | 1 MiB | bytes of stdout and stderr kept (at most 16 MiB); the rest is cut |
| `read_only` | `false` | the MCP annotation (`readOnlyHint`); a hint for clients, never a permission |
| `env` | none | variables beyond `PATH=/usr/sbin:/usr/bin:/sbin:/bin` and `LANG=C.UTF-8`; nothing else is passed on |
| `dir` | `/` | the working directory |

There is no shell: `argv` is passed to the program as it is, one element
one argument, so `;`, `$(…)`, quotes or globs in a value are just
characters. Patterns are what keep values in bounds; make them as narrow
as the command needs, and let no value name a file the command should
not read. stdin is empty. A file that does not validate keeps the server
from starting (its error is in the journal, `journalctl -u 'mcp-exec-*'`,
and `mcp-gateway doctor` reports the server), so that no command goes
missing unnoticed. The server reads the files when an instance starts:
after a change, stop the running instances (Cockpit, Servers tab) or
wait until they end when idle.

Who may run which command is policy. The shipped role `exec-operator`
runs every command with approval; a role of your own can allow some
freely and others with approval (tool names are the command names):

```json
"roles": {"ops": {"permissions": [
  {"server": "exec", "tool": "disk_usage"},
  {"server": "exec", "tool": "unit_log"},
  {"server": "exec", "tool": "*", "require_approval": true, "approval_channel": "oob"}
]}}
```

Roles for every server reach commands too: the shipped `viewer` allows
`list_*`, `read_*` and `get_*` on all servers, so avoid such names
(`--check` warns). Add `"audit": "full"` to a permission to record the
arguments in the audit log instead of their digest (chapter 6).

Commands run with the calling user's rights and the domain's: they read
`/etc`, `/usr`, system state, mounts and the rpm database, and change
nothing beyond what the user may. For a command that needs more (another
user's journal, files in homes), run it in a test with `mcp-gateway
profile --server exec` and load the module it drafts, or define a second
command server with a domain of its own (copy `exec.yaml` under another
name, with its own `selinux_type` and `--commands` directory). Do not
allow a shell or an interpreter with arguments from the caller
(`/bin/sh -c "{cmd}"`): that is a shell again, only without the
confinement this is for.

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

- The type must be in the loaded policy before a definition names it.
  Without its module, systemd cannot start instances, in permissive
  mode too ("Failed to change SELinux context to
  system_u:system_r:mcpsrv_git_t:s0"). The gateway warns at start of
  every `selinux_type` the policy does not know ("selinux_type is not in
  the loaded SELinux policy"), and `mcp-gateway doctor` fails the check
  `SELinux type`; `semodule -l` lists the loaded modules.

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
"Packaging an MCP server for the gateway", and `packaging/fs-server/` for
the file server's package.
