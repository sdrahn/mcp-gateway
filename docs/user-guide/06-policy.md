# 6. Policy

Every request an agent makes, and every request an MCP server sends back
to the agent, is decided by the Open Policy Agent (`mcp-opa.service`).
The policy has two parts:

| Part | Where | Who maintains it |
|---|---|---|
| **logic** (Rego): how roles, permissions, grants and approver rules are evaluated | `/usr/share/mcp-gateway/policy/` | the package |
| **data**: roles, bindings, approver rules | `/etc/mcp-gateway/policy/rbac/data.json` | you (by hand or in Cockpit) |

For most installations, editing the data is all that is needed.

## The role data

```json
{
  "roles": {
    "developer": {
      "permissions": [
        {"server": "git", "tool": "*"},
        {"server": "fs",  "tool": "read_*"},
        {"server": "fs",  "tool": "list_*"},
        {"server": "fs",  "resource": "file://${home}/*"},
        {"server": "fs",  "tool": "write_file", "require_approval": true,
                          "approval_channel": "url", "args": {"path": "^${home}/"}},
        {"server": "fs",  "tool": "delete_*", "effect": "deny"},
        {"server": "*",   "prompt": "*"}
      ]
    }
  },
  "bindings": {
    "users":  {"alice": ["developer"]},
    "groups": {"dev": ["developer"], "wheel": ["admin"]}
  },
  "approvers": {
    "default": ["self", "role:admin"],
    "db":      ["role:dba"]
  }
}
```

- **roles**: named sets of permissions.
- **bindings**: which users (by principal name) and groups hold which
  roles. A principal's roles are the union of its user binding and the
  bindings of all its groups.
- **approvers**: who may decide on approvals, per server (see
  [Approver rules](#approver-rules)).

### The shipped roles

| Role | Permissions |
|---|---|
| `viewer` | tools named `list_*`, `read_*`, `get_*` on every server; all prompts |
| `developer` | everything on `git`; on `fs`: read and list, resources below the home directory, `write_file` below the home directory with approval (approval page), never `delete_*`; all prompts |
| `admin` | everything, including requests servers send to the client (sampling, elicitation, roots) |

Bindings as shipped: group `dev` → `developer`, group `wheel` → `admin`.
Adjust both to your organisation; they are examples, not a
recommendation.

## Permissions

A permission is an object with a `server` glob and exactly one target:

| Target field | Matches | Used for |
|---|---|---|
| `tool` | tool name | `tools/call` |
| `prompt` | prompt name | `prompts/get` (and completions of its arguments) |
| `resource` | resource URI | `resources/read`, `subscribe`, `unsubscribe` |
| `client` | request method | requests an MCP server sends to the agent: `sampling.create`, `elicitation.create`, `roots.list` |

Names are the server's own names, never the aggregated endpoint's
prefixed ones.

Further fields:

| Field | Meaning |
|---|---|
| `effect: "deny"` | forbid what the permission matches; a deny always wins |
| `require_approval: true` | allowed only with a human's approval (chapter 7) |
| `approval_channel` | `url` (default), `form` or `oob`: how approval is obtained |
| `args` | map of argument name → regular expression; the permission applies only if every listed argument is a string matching its expression |
| `obligations` | conditions on an allowed call, see [Obligations](#obligations) |
| `require_client_cert: true` | applies only to remote clients that presented a verified client certificate (mTLS) |
| `allow_sensitive: true` | for `client` permissions: also covers elicitation requests that appear to ask the user for secrets (passwords, tokens), which are otherwise refused |

### Patterns

- `server`, `tool`, `prompt`, `resource` and `client` are **globs**:
  `*` matches any sequence of characters (including `/`), `?` one
  character, `[abc]` and `{a,b}` as usual. `"tool": "*"` is every tool.
- `${sub}` is replaced by the principal's name, `${home}` by its home
  directory (both escaped). A pattern with `${home}` never matches for a
  principal without a home (remote users without a local account).
- Resource URIs containing `..` segments (also percent-encoded) never
  match, so `file://${home}/*` cannot be escaped.
- `args` values are **regular expressions** (anchor them: `^…$`).
  `${sub}` and `${home}` are substituted as above. A string argument
  containing a `..` path segment never matches, so `^${home}/` does not
  admit `/home/alice/../bob/x`. Symbolic links are left to file
  permissions and SELinux.

### How a decision is made

For a request, all permissions of all the principal's roles whose
`server`, target and `args` match are collected. Then, in this order:

1. any matching permission has `effect: "deny"` → **deny**
   ("denied by policy");
2. a matching permission without `require_approval` → **allow**;
3. a matching permission requires approval and the principal holds a
   valid grant for this server and tool → **allow** ("approved");
4. a matching permission requires approval → **ask**, through its
   `approval_channel`, offering the scopes "once" and "session", with
   out-of-band as fallback;
5. otherwise → **deny** ("no matching permission").

Everything not explicitly allowed is denied. If OPA does not answer
within `policy.timeout`, or answers something invalid, the request is
denied ("policy evaluation failed", "invalid policy decision").

### What agents see

`tools/list`, `prompts/list`, `resources/list` and
`resources/templates/list` are filtered: an item is shown unless using it
would be denied outright. Items needing approval are shown (the agent
can ask); `args` conditions are ignored for listing, since arguments are
not known yet. Resource templates are shown where the principal may read
some resource of that server.

### Obligations

Obligations attach conditions to an allowed call:

```json
{"server": "db", "tool": "query",
 "obligations": {
   "redact_output": ["\\b\\d{16}\\b", "(?i)password=\\S+"],
   "max_output_bytes": 65536,
   "rate_limit": ["10/m", "100/h"],
   "arg_constraints": {"sql": ["^(?i)\\s*select\\b"]},
   "audit": "full"
 }}
```

| Obligation | Effect |
|---|---|
| `redact_output` | regular expressions (a string or a list); matches in any string of the result are replaced by `[redacted]` |
| `max_output_bytes` | a larger result is withheld; the agent gets "output withheld: …" |
| `rate_limit` | `N/s`, `N/m` or `N/h` (a string or a list); per principal, server and tool, sliding window; excess calls are denied ("rate limit exceeded") |
| `arg_constraints` | argument name → regular expressions the (string) argument must all match, otherwise the call is denied |
| `audit: "full"` | the audit record contains the arguments verbatim instead of a keyed digest, and OPA's decision log keeps them |

When several matching permissions carry obligations, they are merged:
redaction patterns, rate limits and argument constraints add up (all
apply), the smallest `max_output_bytes` wins, and `audit: "full"` wins.
A malformed obligation (an invalid regular expression, a bad rate)
denies the call.

`args` and `arg_constraints` differ: `args` decides whether a
permission applies (so a non-matching write can fall through to another
permission or to "no matching permission"), `arg_constraints` is checked
after the decision and denies.

### Requests from MCP servers

MCP servers can ask the agent for things: an LLM completion (sampling),
input from the user (elicitation), the agent's root directories. These
are decided like tool calls, with `client` permissions:

```json
{"server": "research", "client": "sampling.create"},
{"server": "*",        "client": "roots.list"},
{"server": "setup",    "client": "elicitation.create", "allow_sensitive": true}
```

Without such permissions, servers cannot make these requests (only
`admin` has them as shipped).

## Approver rules

`approvers` maps a server name, or `default`, to a list of rules; the
first key that exists applies (`<server>`, else `default`, else
`["self"]`):

| Rule | Who |
|---|---|
| `self` | the principal themself (same local uid); not available for remote principals without a local account |
| `role:<role>` | users holding the role through the bindings |
| `group:<group>` | members of a local group |
| `user:<user>` | a local user |

The same rules decide who may **see and revoke grants** and who may
**see and stop instances** of a server, and whom approval **e-mail**
goes to (chapter 7). Approvers are identified by the kernel on the
control socket, never by an agent.

Examples:

```json
"approvers": {
  "default": ["self", "role:admin"],
  "db":      ["group:dba"],
  "prod-*":  ["user:oncall"]
}
```

(Keys are server names, not globs: `"prod-*"` above would only match a
server literally named so. List servers individually.)

For high-risk servers, leave out `self`: then the requesting user cannot
approve their own agent's calls.

## Changing the policy

Edit `/etc/mcp-gateway/policy/rbac/data.json` (or use the Policy tab in
Cockpit, chapter 8). OPA watches the policy directories and loads
changes within seconds; the gateway notices within `policy.watch_interval`
(10 s), tells connected agents to list their tools again and writes a
`mcp-policy-change` audit event. No restart is needed.

Check the file first; a syntax error makes OPA keep the previous policy
and log an error:

```bash
python3 -m json.tool /etc/mcp-gateway/policy/rbac/data.json >/dev/null
opa check /usr/share/mcp-gateway/policy /etc/mcp-gateway/policy
journalctl -u mcp-opa.service -n 20
```

## Testing a decision

Ask OPA what it would decide, with the same input the gateway sends:

```bash
cat >/tmp/input.json <<'EOF'
{
  "principal": {"sub": "alice", "uid": 1000, "groups": ["users", "dev"],
                "home": "/home/alice", "transport": "unix", "session_id": "s1"},
  "action": "tools.call",
  "resource": {"server": "fs", "kind": "tool", "name": "write_file"},
  "args": {"path": "/home/alice/notes.txt", "content": "hi"},
  "grants": []
}
EOF
opa eval -f pretty \
    -d /usr/share/mcp-gateway/policy -d /etc/mcp-gateway/policy \
    -i /tmp/input.json 'data.mcp.authz.decision'
```

```json
{
  "ask": {
    "channel": "url",
    "fallback": "oob",
    "prompt": "Allow alice: tools.call fs/write_file?",
    "scopes": ["once", "session"]
  },
  "effect": "ask"
}
```

Actions are `tools.call`, `prompts.get`, `resources.read`,
`resources.subscribe`, `resources.unsubscribe`, `completion.complete`,
`sampling.create`, `elicitation.create` and `roots.list`. The gateway's
audit records and OPA's decision log (chapter 9) show the real inputs
and decisions.

Unit tests for your own rules can be written as Rego tests next to the
data and run with `opa test`; the repository's `policy/mcp/*_test.rego`
are examples.

## Custom policy logic

The shipped logic covers roles, approvals with the scopes "once" and
"session", obligations and approver rules. For more (time windows,
approval for a fixed duration, decisions on SELinux contexts or
client certificates, …), write your own Rego:

- The gateway queries `data.mcp.authz.decision`, `data.mcp.filter.visible`,
  `data.mcp.approvals.allow`, `…manage_grant`, `…manage_instance` and
  `…notify`; `system.log` masks the decision log. The input and decision
  documents are described in [docs/architecture.md](../architecture.md),
  section 6.
- An `ask` decision may offer durations as scopes, e.g.
  `"scopes": ["once", "session", "1h", "24h"]` (at most 30 days); the
  approval page then offers them and the resulting grant is valid for
  that time.
- Put modified logic into a signed bundle (below), rather than editing
  files below `/usr`, which package updates overwrite.

## Signed policy bundles

By default OPA loads the policy directories. To make sure only policy you
signed is enforced, even if someone can write to `/etc/mcp-gateway/policy`,
switch OPA to a signed bundle.

### On the gateway host

```bash
# 1. a key pair: /etc/mcp-gateway/bundle/signing.pem (private) and verify.pem
mcp-policy-bundle -G

# 2. build and sign the bundle from the shipped logic and your role data
mcp-policy-bundle -n                 # -n: do not restart OPA yet

# 3. switch OPA to the bundle
install -D -m0644 /usr/share/mcp-gateway/opa/signed-bundle.conf \
        /etc/systemd/system/mcp-opa.service.d/policy.conf
systemctl daemon-reload && systemctl restart mcp-opa.service
```

After every change to the role data, run `mcp-policy-bundle` again (or
use "Sign and apply" in Cockpit): it builds a new revision and restarts
OPA, which verifies the signature. OPA refuses an unsigned or tampered
bundle; the gateway then denies everything until a valid bundle is in
place.

`mcp-policy-bundle` options:

| Option | Default | Meaning |
|---|---|---|
| `-k KEY` | `/etc/mcp-gateway/bundle/signing.pem` | private key (PEM, RSA) |
| `-G` | | create a key pair instead of a bundle |
| `-a ALG` | `RS256` | signing algorithm |
| `-o FILE` | `/etc/mcp-gateway/bundle/policy.tar.gz` | bundle file |
| `-r REV` | UTC timestamp | revision recorded in the bundle |
| `-n` | | do not restart `mcp-opa.service` |
| `-V DIR` | `/usr/share/mcp-gateway/policy` | policy logic |
| `-L DIR` | `/etc/mcp-gateway/policy` | role data |

The private key is labelled `mcpgw_signing_key_t`: neither the gateway
nor OPA can read it. It is safer still to keep it off the gateway host:
build and sign elsewhere with `-k`, and copy only `policy.tar.gz` (and
once `verify.pem`) to the gateway.

> **Never add `--watch` to OPA in bundle mode.** OPA does not verify
> signatures when `--watch` reloads a bundle file. The shipped drop-in
> leaves it out; new revisions take effect by restarting OPA.

### From a bundle server

For many gateways, serve signed bundles over HTTPS (any web server or
an OCI registry) and let OPA poll:

```bash
install -D -m0644 /usr/share/mcp-gateway/opa/bundle-server.conf \
        /etc/systemd/system/mcp-opa.service.d/policy.conf
cp /usr/share/mcp-gateway/opa/opa-config.yaml.example /etc/mcp-gateway/opa-config.yaml
$EDITOR /etc/mcp-gateway/opa-config.yaml        # bundle URL, verification key
setsebool -P mcpopa_can_network on
systemctl daemon-reload && systemctl restart mcp-opa.service
```

OPA verifies every download and keeps the active revision if a new one
does not verify. Until the first bundle is active, everything is denied.

The Policy tab in Cockpit and `GET /v1/policy` on the control API show
the mode (`directories` or `bundle`) and the active revisions.
