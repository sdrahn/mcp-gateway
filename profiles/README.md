# Server setups

One directory per MCP server that the packages `mcp-gateway-profile-<name>`
set up behind the gateway (docs/user-guide/13-system-management-servers.md).
The SELinux modules are in `../selinux/mcp_<name>.te`, next to the
interface they build on.

| File | Installed as |
|---|---|
| `<name>.yaml` | `/usr/share/mcp-gateway/servers.d/<name>.yaml` (active once installed) |
| `roles.json` | `/usr/share/mcp-gateway/policy/mcp/profiles/<name>/data.json` (roles to bind users to) |
| `polkit.rules` | `/usr/share/polkit-1/rules.d/60-mcp-gateway-<name>.rules` |
| `sysusers.conf` | `/usr/lib/sysusers.d/mcp-gateway-profile-<name>.conf` |
| `zypp/zypp-privileged.yaml` | `/usr/share/mcp-gateway/profiles/zypp-privileged.yaml` (opt-in, see chapter 13) |
