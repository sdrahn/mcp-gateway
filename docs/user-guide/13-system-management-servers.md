# 13. System management servers (systemd, firewalld, zypp, suseconnect, snapper)

MCP servers that manage the host itself, such as `systemd-mcp`,
`firewalld-mcp` and a snapper MCP server, differ from servers that work
on a user's files: they talk to system services over D-Bus, and those
services decide for themselves (through polkit or their own
configuration) what a caller may do. This chapter shows how to run them
behind the gateway so that:

- agents can read the system state freely,
- every change waits for a human's approval in Cockpit,
- the servers hold only the rights they need, and no one types an admin
  password into an agent.

The examples use the program names of the openSUSE/SLES packages
(`/usr/bin/systemd-mcp`, `/usr/bin/firewalld-mcp`,
`/usr/bin/snapper-mcp`); adjust the paths to your installation.
Upstream projects: [systemd-mcp](https://github.com/openSUSE/systemd-mcp)
(notes below are for version 0.3.5),
[firewalld-mcp](https://github.com/janvhs/firewalld-mcp) (0.1.0),
[mcp-server-zypp](https://github.com/openSUSE/mcp-server-zypp) (0.1.2),
and `suseconnect-mcp`, package
`mcp-server-suseconnect`, part of
[connect-ng](https://github.com/SUSE/connect-ng).

## Setup packages

For systemd-mcp, firewalld-mcp, mcp-server-zypp and suseconnect-mcp, a
package sets everything in this chapter up:

| Package | Server | Roles to bind |
|---|---|---|
| `mcp-gateway-profile-systemd` | `systemd` | `systemd-reader` (units, logs, man pages, unit files); `systemd-operator` (also changes and other files, with approval) |
| `mcp-gateway-profile-firewalld` | `firewalld` | `firewalld-reader` |
| `mcp-gateway-profile-zypp` | `zypp` | `zypp-reader` (search, dependencies, updates, plans); `zypp-installer` (also install and remove, with approval; privileged server) |
| `mcp-gateway-profile-suseconnect` | `suseconnect` | `suseconnect-reader`; `suseconnect-admin` (also registration changes, with approval) |

Each installs the server definition (in
`/usr/share/mcp-gateway/servers.d`), its roles (chapter 6, "Roles of
server setups"), and where needed the account `mcp-sysmgmt` and a polkit
rule. The SELinux domains come with `mcp-gateway-selinux`. The server
itself is only recommended, since it may come from elsewhere.

```bash
zypper install mcp-gateway-profile-systemd systemd-mcp
systemctl restart mcp-gateway.service        # reads the new definition
```

Then bind users or groups to the roles, in Cockpit or in the role data:

```json
"bindings": {"groups": {"sysops": ["systemd-operator", "firewalld-reader", "zypp-reader"]}}
```

- Approvals for these servers follow your approver rules
  (`"approvers"`); a setup does not set any.
- To change a shipped role, define a role of the same name in the role
  data; it replaces the shipped one.
- To change a definition, put a file of the same name in
  `/etc/mcp-gateway/servers.d`; an empty file there disables the server.
- With signed policy bundles, rebuild the bundle after installing a
  setup (`mcp-policy-bundle`): the roles are part of the policy.
- To let mcp-server-zypp install and remove packages, make it a
  privileged server (chapter 4) by linking the shipped definition into
  the administrator's directory, where privileged servers are accepted:

  ```bash
  ln -s /usr/share/mcp-gateway/profiles/zypp-privileged.yaml /etc/mcp-gateway/servers.d/zypp.yaml
  systemctl restart mcp-gateway.service
  ```

  Users then need `zypp-installer`; every installation and removal waits
  for an approval.

The rest of this chapter explains what the packages set up, and how to
do the same by hand for other servers.

## Three layers of authorization

A call from an agent to, say, `change_unit_state` passes three checks:

| Layer | Decides | Configured in |
|---|---|---|
| **gateway policy** | whether *this principal* may call *this tool* now: allow, deny, or ask for approval | role data (chapter 6) |
| **the MCP server's own authorization** (some servers) | whether the server acts at all | the server's command-line options |
| **the system service** (systemd, firewalld, snapperd) | whether the *account the instance runs as* may do this | polkit rules, service configuration |

An instance is a background service without a login session, so nothing
can answer a polkit password prompt: a call the service would
authenticate interactively fails with "Interactive authentication
required" or similar. The gateway does not collect passwords (MCP
forbids asking for them through the agent's client, and the gateway
would become a store of admin passwords). Instead, the gateway's
approval takes the place of the password prompt, and a polkit rule
grants the server's account the rights it needs, without a password.

## The account the servers run as

By default an instance runs as the requesting user (`run_as:
principal`). A polkit rule for that user then also applies outside the
gateway, for example to `systemctl` in the user's shell. To keep the
rights inside the gateway, run the servers as a dedicated system account
and write the polkit rules for that account:

```bash
# a system account without login (or: useradd --system)
cat >/etc/sysusers.d/mcp-sysmgmt.conf <<'EOF'
u mcp-sysmgmt - "mcp-gateway system management servers" / /usr/sbin/nologin
EOF
systemd-sysusers
```

For the system journal (`list_log`), add the account to the journal's
group; otherwise `systemd-mcp` falls back to its gatekeeper service,
which asks polkit for an admin password, and then shows only the
account's own (empty) journal:

```bash
echo 'm mcp-sysmgmt systemd-journal' >>/etc/sysusers.d/mcp-sysmgmt.conf
systemd-sysusers
```

With `run_as: mcp-sysmgmt`, every principal's instance runs as that
account; what each principal may do is then decided by the gateway's
policy alone, which is the point: the gateway's roles and approvals are
the only way to these rights.

## Server definitions

```yaml
# /etc/mcp-gateway/servers.d/systemd.yaml
name: systemd
command: ["/usr/bin/systemd-mcp"]
run_as: mcp-sysmgmt
selinux_type: mcpsrv_systemd_t
```

```yaml
# /etc/mcp-gateway/servers.d/firewalld.yaml
name: firewalld
command: ["/usr/bin/firewalld-mcp"]
run_as: mcp-sysmgmt
selinux_type: mcpsrv_firewalld_t
```

```yaml
# /etc/mcp-gateway/servers.d/snapper.yaml
name: snapper
command: ["/usr/bin/snapper-mcp"]
run_as: mcp-sysmgmt
selinux_type: mcpsrv_snapper_t
```

Notes:

- On stdin/stdout, `systemd-mcp` allows all reads and checks every
  change with polkit itself (`org.freedesktop.systemd1.manage-units` for
  its own process, without a login session to ask in). The polkit rule
  below answers that check as well as systemd's own. Calls that end with
  "calling method was canceled by user" mean the rule does not apply
  (wrong account, or the rule file is missing). The `--allow-read` and
  `--allow-write` options have no effect in version 0.3.5; do not use
  `--noauth`, which is meant for its HTTP mode.
- `firewalld-mcp` (0.1.0) only reads: `get_default_zone`,
  `get_active_zones`, `get_services_for_zone`, `get_service_info` and
  `is_default_zone`. It needs polkit's `…FirewallD1.info` (runtime
  state) and, for `get_services_for_zone` and `get_service_info`,
  `…FirewallD1.config.info` (reading the permanent configuration), and
  nothing more (rule below).
- `get_file` reads any file or directory the account can read, and
  `get_file`, `get_man_page` and `list_log` run `getfacl`, `man` and
  `rpm`; the SELinux domain needs rules for those (see below).
- None of these servers needs `network: true`: the system bus is a unix
  socket.
- The servers speak MCP on stdin/stdout. A server that also writes log
  lines to stdout breaks the protocol (the gateway logs "invalid message
  from backend … parse error" with the start of the line); use its
  option to log to stderr or a file.
- The definitions are read at start: `mcp-gateway --check && systemctl
  restart mcp-gateway.service`.

### suseconnect-mcp

`suseconnect-mcp` registers the system with SCC (or an RMT server) and
shows its registration. It refuses to run without root, talks to SCC,
counts the calls of each tool in `/var/lib/suseconnect-mcp`, and writes the system
credentials, even for the status, because SCC may hand out a new system
token with any request:

```yaml
# /etc/mcp-gateway/servers.d/suseconnect.yaml
name: suseconnect
command: ["/usr/bin/suseconnect-mcp"]
run_as: root
network: true
selinux_type: mcpsrv_suseconnect_t
sandbox:
  state_directory: suseconnect-mcp                # /var/lib/suseconnect-mcp
  read_write_paths: ["/etc/zypp/credentials.d"]   # SCCcredentials
```

- Running as root does not lift the sandbox: no capabilities, and
  everything but the paths above stays read-only. `RegistrationStatus`
  and `ListExtensions` work with this definition; the tools that change
  the registration (`RegisterSystem`, `ActivateProduct`,
  `DeactivateProduct`, `DeregisterSystem`) also set up repositories and
  services and are likely to need more paths (`/etc/zypp/repos.d`,
  `/etc/zypp/services.d`, `/var/cache/zypp`); open them only if agents
  are to change registrations, behind approval.
- `RegisterSystem` and `ActivateProduct` take the **registration code**
  as an argument: the agent supplies it, so its model sees it. Prefer
  registering by hand and leaving those tools to no one, or to approval
  by someone else (approver rules without `self`).
- The credentials file is labelled `system_conf_t`; the server's domain
  needs read and write access to it (find the rules with a permissive
  round, below). Keep that access to this one domain.
- In a role, allow the two reading tools and require approval for the
  rest:

  ```json
  {"server": "suseconnect", "tool": "RegistrationStatus"},
  {"server": "suseconnect", "tool": "ListExtensions"},
  {"server": "suseconnect", "tool": "*", "require_approval": true, "approval_channel": "oob"}
  ```

### mcp-server-zypp

[mcp-server-zypp](https://github.com/openSUSE/mcp-server-zypp) (notes
for version 0.1.2) searches packages, resolves dependencies and plans
installations with libzypp. `/usr/bin/mcp-server-zypp` speaks MCP and
starts a new worker, `/usr/libexec/mcp-server-zypp/zypp-mcp-tool`, for
every call. Six tools only read and plan (`search_packages`,
`find_providers`, `find_dependents`, `check_updates`, `plan_install`,
`plan_remove`) and work as any account:

```yaml
# /etc/mcp-gateway/servers.d/zypp.yaml
name: zypp
command: ["/usr/bin/mcp-server-zypp"]
run_as: mcp-sysmgmt
selinux_type: mcpsrv_zypp_t
```

- `confirm_install` and `confirm_remove` change the system and refuse to
  run unless the worker is root. An RPM transaction writes all over the
  file system, changes owners and runs package scripts, which no sandbox
  allows: for them, run the server as a **privileged server** (chapter
  4, with its SELinux module) instead of the definition above. Calls to
  it then need an approval unless a permission names the tool exactly,
  and the gateway does not stop it while a transaction runs.
- The worker asks the user, by elicitation, whether to trust a new GPG
  key of a repository. The gateway passes such a request to the agent's
  client only with a `client` permission for `elicitation.create`
  (chapter 6), and only a client that supports elicitation can show it.
- Licenses are accepted with the `accepted_licenses` argument of
  `confirm_install`, which the agent fills in; the approval of that call
  is where a human sees them.
- In a role, allow the six reading tools by name (`search_packages`,
  `find_*`, `check_updates`, `plan_*`) and require approval for the rest.

## SELinux domains

`mcp-gateway-selinux` ships the modules `mcp_systemd`, `mcp_firewalld`,
`mcp_zypp` and `mcp_suseconnect` (sources in the gateway's `selinux/`
directory); for those servers you need no module of your own, and a
module of yours with one of these names would be replaced. What follows
shows how they are built, for other servers such as snapper.

The default domain for servers, `mcpsrv_generic_t`, may not use the
system bus, so these servers exit at start ("backend instance exited").
Give each its own domain with the gateway's template
(`mcp-gateway-selinux` installs the interface file; building needs
`selinux-policy-devel`):

```
# mcp_systemd.te
policy_module(mcp_systemd, 1.0)

mcp_gateway_backend_template(systemd)

dbus_system_bus_client(mcpsrv_systemd_t)
init_dbus_chat(mcpsrv_systemd_t)
optional_policy(`
	policykit_dbus_chat(mcpsrv_systemd_t)
')
```

```
# mcp_systemd.fc
/usr/bin/systemd-mcp  --  gen_context(system_u:object_r:mcpsrv_systemd_exec_t,s0)
```

For firewalld and snapper, the same with their names, and instead of
`init_dbus_chat` the service's interface:

```
optional_policy(`
	firewalld_dbus_chat(mcpsrv_firewalld_t)
')
```

```
# snapper: not every policy has an interface for snapperd, so plainly:
optional_policy(`
	gen_require(`
		type snapperd_t;
		class dbus send_msg;
	')
	allow mcpsrv_snapper_t snapperd_t:dbus send_msg;
	allow snapperd_t mcpsrv_snapper_t:dbus send_msg;
')
```

Build, install and label:

```bash
make -f /usr/share/selinux/devel/Makefile mcp_systemd.pp mcp_firewalld.pp mcp_snapper.pp
semodule -i mcp_systemd.pp mcp_firewalld.pp mcp_snapper.pp
restorecon -v /usr/bin/systemd-mcp /usr/bin/firewalld-mcp /usr/bin/snapper-mcp
```

Install the modules **before** naming the domains in the definitions: an
unknown `selinux_type` makes every start fail with
`status=229/SELINUX_CONTEXT`.

The tools may need more than the start does (reading the journal, for
example). Find the rest by running the domains permissive while using
the tools, then turn the denials into rules:

```bash
semanage permissive -a mcpsrv_systemd_t
# use the server's tools from an agent, then:
ausearch -m AVC,USER_AVC -ts recent | grep mcpsrv_systemd_t | audit2allow
semanage permissive -d mcpsrv_systemd_t
```

Many D-Bus denials are hidden by `dontaudit` rules; `semodule -DB` shows
them, `semodule -B` hides them again. D-Bus denials are logged by the
bus as `USER_AVC`, not `AVC`.

## Service permissions

### systemd and firewalld: polkit

```js
// /etc/polkit-1/rules.d/60-mcp-sysmgmt.rules
// The gateway's system management servers (run_as: mcp-sysmgmt) may manage
// units and read the firewall configuration. Which calls run is decided by
// the gateway, which requires approval for every change.
polkit.addRule(function(action, subject) {
    if (subject.user != "mcp-sysmgmt")
        return polkit.Result.NOT_HANDLED;
    if (action.id == "org.freedesktop.systemd1.manage-units" ||
        action.id == "org.freedesktop.systemd1.manage-unit-files" ||
        action.id == "org.freedesktop.systemd1.reload-daemon")
        return polkit.Result.YES;
    if (action.id == "org.fedoraproject.FirewallD1.info" ||
        action.id == "org.fedoraproject.FirewallD1.config.info")
        return polkit.Result.YES;
    return polkit.Result.NOT_HANDLED;
});
```

polkit reads new rules immediately. Keep the rule as narrow as your use
allows: `action.lookup("unit")` holds the unit name for systemd's
actions, so a rule can name the units the servers may touch;
`pkaction | grep -E 'systemd1|FirewallD1'` lists the actions.

firewalld allows queries (`…FirewallD1.info`, `…FirewallD1.config.info`)
without a password only in an active login session, so even reading
needs the rule for a background account. A firewalld MCP server that
also changes the firewall needs the actions it uses as well
(`…FirewallD1.config`, `…FirewallD1.all`);
grant them only together with an approval permission for its changing
tools.

### snapper: the snapper configuration

snapperd does not use polkit; it lets non-root callers use a snapper
configuration named in `ALLOW_USERS` or `ALLOW_GROUPS`:

```bash
snapper -c root set-config ALLOW_USERS="mcp-sysmgmt"
```

Allowed callers can list, create and delete snapshots of that
configuration; rollbacks need root.

## Roles and approvals

A role that lets its holders read freely and makes every change wait for
approval (chapter 6 explains how permissions combine: one matching
permission **without** `require_approval` allows the call, so a role like
the shipped `admin`, which allows everything, never asks):

```json
"roles": {
  "sysops": {
    "description": "systemd, firewalld, snapper: read freely, change only with approval",
    "permissions": [
      {"server": "systemd",   "tool": "list_*"},
      {"server": "systemd",   "tool": "get_man_page"},
      {"server": "systemd",   "tool": "check_restart_reload"},
      {"server": "systemd",   "tool": "get_file", "args": {"path": "^/(etc|usr/lib)/systemd/"}},
      {"server": "systemd",   "tool": "*", "require_approval": true, "approval_channel": "oob"},
      {"server": "firewalld", "tool": "get_*"},
      {"server": "firewalld", "tool": "is_default_zone"},
      {"server": "firewalld", "tool": "*", "require_approval": true, "approval_channel": "oob"},
      {"server": "snapper",   "tool": "list_*"},
      {"server": "snapper",   "tool": "*", "require_approval": true, "approval_channel": "oob"}
    ]
  }
},
"bindings": {"users": {"alice": ["sysops"]}},
"approvers": {
  "default": ["self", "role:admin"],
  "systemd":   ["role:admin"],
  "firewalld": ["role:admin"],
  "snapper":   ["role:admin"]
}
```

- Check the read patterns against the servers' actual tool names (a
  `tools/list` through `mcp-connect --server systemd`): a changing tool
  whose name starts with `list_` or `get_` would run without approval.
  Name `get_file` on its own, with the paths it may read freely: other
  paths fall through to the approval permission.
- `oob` puts the request into the Cockpit inbox (and desktop and mail
  notifications) whatever the agent's client supports; the agent waits,
  up to `approval_timeout` (chapter 3). Raise it if approvers need longer
  than the default two minutes.
- Without `self` in the server's approver rule, users cannot approve
  their own changes: someone holding `admin` must.
- Agents that open a new MCP session for every prompt (Kit does) lose
  "session" grants after each prompt. Offer a short duration instead,
  e.g. `"approval_scopes": ["once", "1h"]` on the approval permissions
  (chapter 7).
- Do not also bind these users to `admin`: its permissions allow every
  call and nothing would ask.

## Checking and troubleshooting

`mcp-gateway inspect --server systemd --roles
/usr/share/mcp-gateway/policy/mcp/profiles/systemd/data.json` (as root)
starts the server as the gateway does and reports roles that name tools
it does not have, for example after a server update (chapter 4,
"Inspecting a server").

```bash
# Can the gateway list each server's tools? (lists servers it could not)
curl -s --unix-socket /run/mcp-gateway/control.sock -X POST \
  --data-binary @/etc/mcp-gateway/policy/rbac/data.json http://gw/v1/policy/whatif | jq .unchecked
# The gateway's decision for each call:
journalctl -u mcp-gateway.service -o cat | grep '"audit":true' | jq -c '{server,name,effect,reason}'
# What the servers said:
journalctl -u 'mcp-systemd-*' -u 'mcp-firewalld-*' -u 'mcp-snapper-*' -b
```

| Symptom | Cause | Fix |
|---|---|---|
| `unchecked`: "backend instance exited", the server's journal shows only systemd's start and exit messages | the server may not reach the system bus (and cannot even log why) | dedicated SELinux domain, as above; `semodule -DB` shows the hidden denials |
| `status=229/SELINUX_CONTEXT` | the definition names a domain whose module is not installed | install the module, or remove `selinux_type` |
| "invalid message from backend … parse error" | the server writes non-MCP output to stdout | its option for logging to stderr or a file |
| a change runs without approval (audit: `effect: allow`) | a role of the principal allows the tool without approval (often `admin`) | check the principal's roles; only reads may match a permission without `require_approval` |
| audit: `ask`, but nothing appears in Cockpit | the approval could not be delivered | `journalctl -u mcp-gateway.service \| grep -iE 'approval\|elicit'`; the control socket must be enabled |
| "calling method was canceled by user" | `systemd-mcp`'s own authorization | `--allow-read` / `--allow-write`, or `--noauth ThisIsInsecure` behind the gateway |
| "Interactive authentication required", `NOT_AUTHORIZED` after approval | the service's polkit check for the instance's account | the polkit rule above, for the account in `run_as` |
| snapper calls refused after approval | the account is not in the snapper configuration's `ALLOW_USERS`/`ALLOW_GROUPS` | `snapper -c <config> set-config ALLOW_USERS=…` |
| role data edits do not take effect | OPA did not notice the change (some editors replace the file) | `systemctl restart mcp-opa.service`; compare `curl -s --unix-socket /run/mcp-gateway/opa.sock http://opa/v1/data/mcp/rbac/bindings` with the file |
