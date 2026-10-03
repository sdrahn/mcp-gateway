# Development setup

Running mcp-gateway from a source checkout, without installing packages:
for development, and to try the gateway with an MCP client before
installing it. For installations, see the
[user guide](../../docs/user-guide/README.md).

## Development mode

Runs as your user, without systemd or SELinux. Needs Go and `opa`.

```bash
examples/dev/run-dev.sh
```

It prints an MCP client configuration for the `fs` endpoint (drop
`--server fs` for the aggregated endpoint). Point any MCP client (Kit,
Claude Code, an IDE, the MCP Inspector) at it, or talk to it by hand:

```bash
{ echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"elicitation":{}},"clientInfo":{"name":"sh"}}}'
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"'$HOME'/x"}}}'
  sleep 1
} | bin/mcp-connect --socket /tmp/mcpgw.XXXXXX/mcp.sock --server fs
```

`tools/list` shows the file server's tools without `delete_file`, which
the example role denies; `resources/list` shows the files in `$HOME`; the
`delete_file` call comes back as a tool error
"mcp-gateway: denied by policy". A `write_file` below `$HOME` triggers an
`elicitation/create` request; the example role data uses the `form`
channel to show it (the shipped default policy asks for
`url`, per decision D3).

## Approvals page

`make install` puts the Cockpit page into `/usr/share/cockpit/mcp-gateway`
("MCP Gateway approvals" in Cockpit's tools menu). It talks to
`/run/mcp-gateway/control.sock` as the logged-in user: you see and decide
your own agents' requests, and holders of the admin role see everyone's
(the `approvers` rules in the RBAC data decide). For URL-mode approvals,
point clients at it:

```yaml
approvals:
  url_template: https://gateway.example.com:9090/mcp-gateway#/approvals/{id}
```

The shipped default policy asks via `url` with `oob` as fallback, so
clients without URL-mode support still work: the request waits in the
inbox. In development mode the same API is on the work directory's
`control.sock` (see the output of `run-dev.sh`).

## Remote access

Add an `http` section to `gateway.yaml` (see `config/gateway.yaml`):

```yaml
http:
  listen: ":8443"
  cert_file: /etc/mcp-gateway/tls/cert.pem
  key_file: /etc/mcp-gateway/tls/key.pem
  issuer: https://idp.example.com/realms/mcp        # e.g. Keycloak
  audience: https://gateway.example.com:8443/mcp    # this gateway's URL
  local_user_claim: preferred_username              # optional (D1)
  scopes: [mcp]
```

Register the gateway as a resource (audience) at the IdP and give
clients the URL `https://gateway.example.com:8443/mcp` (aggregated) or
`.../mcp/fs`. MCP clients with OAuth support discover the IdP from the
`401` response. Bind remote subjects or groups to roles in the RBAC data
(`bindings.users` / `bindings.groups`). With SELinux:
`semanage port -a -t mcp_port_t -p tcp 8443`.

## Confined mode (systemd + SELinux)

On openSUSE Tumbleweed or SLES 16 (SELinux enforcing), install the
packages built from `packaging/suse` (see `packaging/suse/README.md`), as
root:

```bash
zypper in mcp-gateway mcp-gateway-selinux mcp-gateway-fs-server mcp-gateway-cockpit
# Bind users or groups to roles in /etc/mcp-gateway/policy/rbac/data.json,
# e.g. "bindings": {"users": {"alice": ["developer"]}, ...}
# (examples/dev/rbac/data.json shows a form-approval variant).
usermod -aG mcp-users alice
systemctl enable --now mcp-gateway.service
```

Without packages, from a checkout (`make install` and the `install-*`
targets take the usual directory variables):

```bash
make build selinux
make install install-selinux install-demo install-cockpit DISTCONFDIR=/usr/etc
semodule -i /usr/share/selinux/packages/targeted/mcp_gateway.pp.bz2
restorecon -R /usr/bin/mcp-gateway /usr/libexec/mcp-servers /etc/mcp-gateway /usr/etc/mcp-gateway
systemd-sysusers
systemctl enable --now mcp-gateway.service
```

Connect as a member of `mcp-users`:

```bash
mcp-connect --server fs
```

Each principal gets its own `mcp-fs-<instance>.service`:

```bash
systemctl list-units 'mcp-*'
ps -eZ | grep mcp-fs        # system_u:system_r:mcpsrv_fs_t:s0:cX,cY
journalctl -u mcp-gateway   # audit records
ausearch -m avc -ts recent  # SELinux denials
```

The SELinux module covers the launch path; keep a new backend domain
permissive (`semanage permissive -a mcpsrv_fs_t`) until its rules are
complete. The confined mode has not been exercised on a real host yet;
the end-to-end tests (`e2e/`) use development mode, and CI only checks
that the packages build, pass rpmlint, install and load the module.
