# Proof of concept

What works (docs/architecture.md, section 11, step 3):

- local clients on the gateway's unix socket, identified by kernel peer
  credentials (`SO_PEERCRED`, `SO_PEERSEC`);
- `mcp-connect` as the stdio shim, selecting a backend with a
  `mcp-gateway/hello` notification;
- one backend per connection, proxied by the protocol-aware router:
  - `tools/call` decided by OPA (`allow` / `deny` / `ask`),
  - `tools/list` filtered by OPA, other `*/list` results hidden,
  - resources, prompts, completions and unknown methods denied,
  - backend requests to the client (`sampling`, `elicitation`, `roots`)
    decided by OPA, backend elicitations labelled with the backend name;
- `ask` answered through form-mode elicitation to the client, with
  `once` / `session` grants;
- fail closed when OPA is slow, unreachable or returns garbage;
- audit records (JSON, argument digests) on stderr;
- backend instances as systemd transient units in their own SELinux
  domain with a per-instance MCS pair, or as plain child processes in
  development mode.

Not yet: aggregated endpoint, remote access (HTTP/OAuth), URL/OOB
approvals, persistent grants, obligations, per-principal instance sharing.

## Development mode

Runs as your user, without systemd or SELinux. Needs Go and `opa`.

```bash
examples/poc/run-dev.sh
```

It prints an MCP client configuration. Point any MCP client (Kit,
Claude Code, an IDE, the MCP Inspector) at it, or talk to it by hand:

```bash
{ echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"elicitation":{}},"clientInfo":{"name":"sh"}}}'
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"'$HOME'/x"}}}'
  sleep 1
} | bin/mcp-connect --socket /tmp/mcpgw.XXXXXX/mcp.sock --server fs
```

`tools/list` shows `list_dir`, `read_file` and `write_file` (not
`delete_file`); the `delete_file` call comes back as a tool error
"mcp-gateway: denied by policy". A `write_file` below `$HOME` triggers an
`elicitation/create` request; the example role data uses the `form`
channel so the PoC can demonstrate it (the shipped default policy asks for
`url`, per decision D3).

## Confined mode (systemd + SELinux)

On a Fedora/RHEL host with SELinux enforcing, as root:

```bash
make build selinux
semodule -i selinux/mcp_gateway.pp
make install                        # binaries, units, config, policy bundle
install -Dm0755 "$(command -v opa)" /usr/libexec/mcp-gateway/opa
install -Dm0755 bin/mcp-fs-demo /usr/libexec/mcp-servers/mcp-fs
restorecon -R /usr/bin/mcp-gateway /usr/libexec/mcp-gateway /usr/libexec/mcp-servers \
    /etc/mcp-gateway
systemd-sysusers
install -m0644 config/servers.d/fs.yaml /etc/mcp-gateway/servers.d/
cp examples/poc/rbac/data.json /etc/mcp-gateway/policy/rbac/data.json   # bind users/groups there
systemctl enable --now mcp-gateway.service
```

Connect as a member of `mcp-users`:

```bash
mcp-connect --server fs
```

Each session starts `mcp-fs-<session>.service`:

```bash
systemctl list-units 'mcp-*'
ps -eZ | grep mcp-fs        # system_u:system_r:mcpsrv_fs_t:s0:cX,cY
journalctl -u mcp-gateway   # audit records
ausearch -m avc -ts recent  # SELinux denials
```

The SELinux module covers the launch path; keep a new backend domain
permissive (`semanage permissive -a mcpsrv_fs_t`) until its rules are
complete. The confined mode has not been exercised on a real host yet;
the end-to-end test (`e2e/`) uses development mode.
