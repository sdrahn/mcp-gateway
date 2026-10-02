# 12. Custom policy (Rego)

The shipped policy (chapter 6) is driven by data: roles, permissions,
bindings and approver rules in `data.json`. When data is not enough (you
need time windows, decisions on client certificates or SELinux contexts,
approvals that last a fixed time, managers approving their team's
requests, or a completely different model), write your own policy in
**Rego**, the language of the Open Policy Agent.

This chapter explains the contract between the gateway and the policy,
three ways to customise it, how to test and deploy the result, and the
pitfalls. It assumes basic Rego knowledge; the
[OPA documentation](https://www.openpolicyagent.org/docs/latest/policy-language/)
is the reference. The gateway ships with OPA 1.x, so policies use Rego v1
syntax (`if`, `contains`, `in`).

## How OPA loads the policy

In the default **directory mode**, `mcp-opa.service` loads two directory
trees into one policy:

| Directory | Contents |
|---|---|
| `/usr/share/mcp-gateway/policy/` | the shipped logic: `mcp/authz.rego`, `mcp/filter.rego`, `mcp/approvals.rego`, `mcp/log.rego` |
| `/etc/mcp-gateway/policy/` | your files: `rbac/data.json`, and any `.rego` and `data.json` files you add |

- A `.rego` file defines rules in the package it declares
  (`package mcp.authz`), wherever the file lies. Files declaring the same
  package are **merged** into one package.
- A file named `data.json` (or `data.yaml`) in `/etc/mcp-gateway/policy/`
  becomes data below `data.mcp`, at the path of its directory:
  `/etc/mcp-gateway/policy/rbac/data.json` is `data.mcp.rbac`,
  `/etc/mcp-gateway/policy/rbac/managers/data.json` is
  `data.mcp.rbac.managers`. The shipped policy directory is loaded the
  same way: the server setup packages put their roles in
  `/usr/share/mcp-gateway/policy/mcp/profiles/<setup>/data.json`
  (`data.mcp.profiles.<setup>.roles`); the shipped `mcp.authz` merges
  them below the roles of `data.mcp.rbac` (`role_defs`).
- Everything the gateway uses lives below `mcp`: its packages
  (`mcp.authz`, …), the role data and the decision-log mask
  (`mcp.log.mask`). Keep your own packages below `mcp` too
  (`package mcp.custom.hours`, say): a signed bundle claims only `mcp`, so
  that it can share an OPA with other teams' policies, and a package
  outside it fails the bundle build.
- OPA runs with `--watch`: it reloads changed files within seconds. If a
  file does not parse or compile, OPA logs the error and **keeps the
  previous policy**. If it cannot load the policy when it (re)starts,
  it refuses to start and the gateway denies everything.

In **signed bundle mode** (chapter 6) the same two trees are combined by
`mcp-policy-bundle` into a signed bundle: the shipped logic first, then
your files on top (a `.rego` file of yours with the same relative path
replaces the shipped one; data files go below `mcp/`, as above),
`*_test.rego` files are left out, and the result must pass
`opa check --strict` before it is signed. The bundle's manifest declares
the root `mcp`.

## The contract

The gateway asks OPA these questions, always with an `input` document it
builds itself. Anything an agent says about itself is marked in the
input as self-reported.

| Query | When | Must return |
|---|---|---|
| `data.mcp.authz.decision` | every call, and every request an MCP server sends to the agent | a decision document (below) |
| `data.mcp.filter.visible` | every `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list` | the subset of `input.resources` to show |
| `data.mcp.approvals.allow` | control API: may this approver decide on this pending approval? | `true`/`false` |
| `data.mcp.approvals.manage_grant` | control API: may this caller see and revoke this grant? | `true`/`false` |
| `data.mcp.approvals.manage_instance` | control API: may this caller see and stop this instance? | `true`/`false` |
| `data.mcp.approvals.notify` | a new pending approval, with mail configured | a set of `"user:<name>"` and `"group:<name>"` |
| `data.mcp.log.mask` | OPA itself, for every decision it logs (`mcp-opa.service` sets `decision_logs.mask_decision` to it) | a set of JSON pointers to remove from the decision log |

**Failing closed.** A query that fails, times out (`policy.timeout`,
250 ms) or is **undefined** counts as the most restrictive answer: an
undefined or invalid `decision` denies ("policy evaluation failed",
"invalid policy decision"), an undefined `visible` hides everything, an
undefined `allow`, `manage_grant` or `manage_instance` refuses. Give
your rules `default` values so they are never undefined by accident.

**Versions.** Every input has `"version": 1`, the version of the input
documents. Within a version, new gateway releases only add fields; a
field is never renamed, dropped or given another meaning without a new
version (chapter 3, [Format version](03-configuration.md#format-version)).
A decision may say which version of the decision document it is written
for (`"version": 1`); the gateway denies a decision of a version it does
not enforce.

### Decision input

```json
{
  "version": 1,
  "principal": {
    "sub": "alice",
    "iss": "https://idp.example.com/realms/mcp",
    "uid": 1000,
    "groups": ["users", "dev"],
    "home": "/home/alice",
    "transport": "unix",
    "selinux": "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
    "client": {"name": "some-agent", "version": "1.2"},
    "session_id": "4f1c…",
    "cert": {"subject": "CN=ci-runner,O=Example", "x5t#S256": "…", "dns": ["ci1.example.com"]}
  },
  "action": "tools.call",
  "resource": {
    "server": "fs",
    "kind": "tool",
    "name": "write_file",
    "annotations": {"destructiveHint": false}
  },
  "args": {"path": "/home/alice/notes.txt", "content": "…"},
  "grants": [
    {"id": "g-5d0e…", "sub": "alice", "uid": 1000, "server": "fs", "tool": "write_file",
     "scope": "session", "session_id": "4f1c…", "expires": "2026-09-27T18:00:00Z",
     "approved_by": "bob", "channel": "url"}
  ],
  "context": {
    "time": "2026-09-27T10:12:03Z",
    "transport": "unix",
    "decision_id": "8c2b…",
    "client_capabilities": {"elicitation": {}}
  }
}
```

| Field | Meaning |
|---|---|
| `version` | the version of the input documents (`1`) |
| `principal.sub` | the local user name (local clients, and remote users mapped to a local account), else the token subject |
| `principal.iss` | token issuer; remote principals only |
| `principal.uid`, `home` | local account; absent for remote principals without one |
| `principal.groups` | local groups, plus the token's groups for remote principals |
| `principal.transport` | `unix` or `http` |
| `principal.selinux` | the local client's SELinux context; empty for remote clients |
| `principal.client` | **self-reported** by the agent; never base a decision on it |
| `principal.session_id` | the MCP session |
| `principal.cert` | the verified client certificate (mTLS); absent without one |
| `action` | `tools.call`, `prompts.get`, `resources.read`, `resources.subscribe`, `resources.unsubscribe`, `completion.complete`; for requests from MCP servers: `sampling.create`, `elicitation.create`, `roots.list` |
| `resource.server` | the MCP server |
| `resource.kind`, `name` | `tool`/tool name, `prompt`/prompt name, `resource`/URI, `resource_template`/URI template (completions), `client`/request method |
| `resource.privileged` | `true` for privileged servers (no sandbox, chapter 4); the shipped policy then allows only through permissions naming server and target exactly |
| `resource.annotations` | the tool's annotations (`readOnlyHint`, `destructiveHint`, …) as the MCP server declared them: **untrusted**, use them only to deny more |
| `args` | tool or prompt arguments; for `elicitation.create`: `mode`, `fields`, `sensitive` (the gateway's guess whether secrets are asked for), `url` |
| `grants` | the principal's unexpired grants for this server and tool (for calls only) |
| `context.time` | the time of the request (RFC 3339, UTC) |
| `context.client_capabilities` | the capabilities the agent announced (self-reported) |
| `discovery` | `true` when the decision is asked on behalf of the filter (below) |

Not every field is present in every query: the filter's inner decisions
have no `args`, `grants` or `context`; requests from MCP servers have no
`grants`. Rules must cope with missing fields (in Rego a missing field
makes an expression undefined, so the rule simply does not apply).

### Decision document

```json
{"effect": "allow", "obligations": {"max_output_bytes": 65536}}
{"effect": "deny", "reason": "outside office hours"}
{"effect": "ask", "ask": {"channel": "url", "prompt": "Allow alice to push?",
                          "scopes": ["once", "session", "1h"], "fallback": "oob"}}
```

| Field | Values |
|---|---|
| `version` | optional: the version of the decision document it is written for (`1`); another version is invalid (deny) |
| `effect` | `allow`, `deny` or `ask`; anything else is invalid (deny) |
| `reason` | free text; shown to the agent (`mcp-gateway: <reason>`) and in the audit record |
| `obligations` | as in chapter 6: `redact_output`, `max_output_bytes`, `rate_limit`, `arg_constraints`, `audit`, `pseudonymize` (`{"detect": [...], "patterns": {...}, "fields": {...}}`), `reidentify` (argument names); a malformed obligation makes the decision invalid (deny) |
| `ask.channel` | `form`, `url` or `oob`; required with `ask` |
| `ask.prompt` | the question shown to the approver |
| `ask.scopes` | what the approver may choose: `once`, `session`, or durations like `30m`, `1h`, `24h` (at most 30 days); default `["once"]` |
| `ask.fallback` | a second channel to try if the first is unavailable |

After an approval the gateway asks again, now with the new grant in
`input.grants` (a `once` grant is included only in that re-evaluation).
The policy must then answer `allow`; if it asks again, the call is
denied ("policy did not accept the approval"). `ask` is honoured for
calls (tools, prompts, resources, completions); for requests from MCP
servers only `allow` lets the request through.

### Filter input and result

```json
{
  "principal": { … as above … },
  "resources": [
    {"server": "fs", "kind": "tool", "name": "write_file"},
    {"server": "fs", "kind": "prompt", "name": "summarize"}
  ]
}
```

`visible` must be a set (or array) of entries of `input.resources`; the
shipped filter shows an entry unless `decision` for using it would be
`deny`, evaluated with `"discovery": true` and without arguments, grants
or context. Keep that approach unless you have a reason not to: it keeps
listing and calling consistent.

### Approval inputs

```json
{"approver": {"name": "bob", "uid": 1001, "groups": ["users", "wheel"]},
 "request":  {"principal": { … }, "server": "fs", "name": "write_file", "action": "tools.call"}}
```

`approver` is identified by the kernel on the control socket. For
`manage_grant` the input has `grant` (a grant object as above) instead
of `request`; for `manage_instance` it has `instance`
(`{"server", "uid"}`). `notify` gets `request` without `approver`. Filter and approval inputs
have `version` too.
`root` may always decide, whatever the policy says.

## Three ways to customise

| Approach | For | Effort on upgrades |
|---|---|---|
| **A. Add rules** to the shipped packages from files in `/etc/mcp-gateway/policy/` | extra denials, extra roles, extra approvers, extra masking | re-run your tests |
| **B. Replace** the shipped logic with a modified copy | changing the decision itself: scopes, channels, reasons, precedence | merge upstream changes into your copy |
| **C. Write** your own policy from scratch | a different authorization model | none from upstream; you own everything |

### A. Adding rules to the shipped logic

Because files of the same package are merged, a file in
`/etc/mcp-gateway/policy/` can add rules to `mcp.authz`,
`mcp.approvals` and `mcp.log`. This works for rules that may have
several definitions:

| Rule | Kind | Adding a definition… |
|---|---|---|
| `mcp.authz.denied` | boolean | denies more requests ("denied by policy"); a deny always wins |
| `mcp.authz.roles` | set | gives principals additional roles |
| `mcp.authz.perms` | set | adds permissions (objects as in `data.json`) |
| `mcp.approvals.allow`, `manage_grant`, `manage_instance` | boolean | lets more approvers act |
| `mcp.approvals.notify` | set | mails more people |
| `mcp.log.mask` | set | removes more from the decision log |

Do **not** define `decision`, `ask_channel`, `obligations` or any other
single-valued rule of the shipped packages again: OPA accepts the files,
but as soon as both definitions produce a value the evaluation fails
("complete rules must not produce multiple outputs") and the gateway
denies the request. Use approach B for those.

These rule names are internals of the shipped policy, not a stable API.
Keep tests for your additions and run them after every package update
(see [Testing](#testing)).

#### Example: changing tools only during office hours

```rego
# /etc/mcp-gateway/policy/custom/office_hours.rego
#
# Changing tools (write_*, delete_*) only on weekdays, 07:00-19:00
# Europe/Berlin. Outside those hours such calls are denied, even with an
# approval.
package mcp.authz

import rego.v1

changing_tool(name) if startswith(name, "write_")

changing_tool(name) if startswith(name, "delete_")

denied if {
	not input.discovery # keep the tools listed; decide when called
	input.action == "tools.call"
	changing_tool(input.resource.name)
	not office_hours
}

office_hours if {
	ns := time.parse_rfc3339_ns(input.context.time)
	[hour, _, _] := time.clock([ns, "Europe/Berlin"])
	not time.weekday([ns, "Europe/Berlin"]) in {"Saturday", "Sunday"}
	hour >= 7
	hour < 19
}
```

`not input.discovery` matters: the filter's decisions carry no
`context`, so without it `office_hours` would never hold during listing
and the tools would disappear from the agent's list for good (and lists
are not refreshed when the hour changes anyway).

#### Example: distrusting tools the server calls destructive

```rego
# /etc/mcp-gateway/policy/custom/annotations.rego
#
# Tools a server marks as destructive (annotation destructiveHint) are
# denied to everyone but admins. Annotations come from the MCP server and
# are untrusted: use them only to deny more, never to allow.
package mcp.authz

import rego.v1

denied if {
	input.action == "tools.call"
	input.resource.annotations.destructiveHint == true
	not "admin" in roles
}
```

Annotations are not part of the filter input, so such tools stay listed
and are denied when called.

#### Example: nothing for agents in containers

```rego
# /etc/mcp-gateway/policy/custom/containers.rego
#
# Agents running in containers (SELinux domain container_t) get nothing.
package mcp.authz

import rego.v1

denied if {
	input.principal.transport == "unix"
	contains(input.principal.selinux, ":container_t:")
}
```

#### Example: a role for a machine with a client certificate

```rego
# /etc/mcp-gateway/policy/custom/cert_roles.rego
#
# Remote clients presenting the CI runner's client certificate hold the
# "ci" role.
package mcp.authz

import rego.v1

roles contains "ci" if {
	input.principal.cert.subject == "CN=ci-runner,O=Example"
}
```

Define the role `ci` in `data.json` as usual. Certificates are verified
against `http.client_ca_file` before they reach the policy (chapter 5).

#### Example: managers approve their team's requests

Data, in `/etc/mcp-gateway/policy/rbac/managers/data.json` (below
`rbac`, see [Custom data](#custom-data)):

```json
{"alice": "bob", "carol": "bob", "dave": "erin"}
```

```rego
# /etc/mcp-gateway/policy/custom/managers.rego
#
# A principal's manager (data.mcp.rbac.managers) may decide on their approvals
# and is told about them by mail.
package mcp.approvals

import rego.v1

allow if {
	data.mcp.rbac.managers[input.request.principal.sub] == input.approver.name
}

notify contains sprintf("user:%s", [manager]) if {
	manager := data.mcp.rbac.managers[input.request.principal.sub]
}
```

The approver rules of `data.json` still apply in addition; this adds
the manager.

#### Example: masking more in the decision log

```rego
# /etc/mcp-gateway/policy/custom/log.rego
#
# Also keep client certificate details out of OPA's decision log.
package mcp.log

import rego.v1

mask contains "/input/principal/cert"
```

### B. Replacing the shipped logic

To change the decision itself, work on a copy of the shipped logic,
kept in a repository **outside** the directories OPA loads, so that
half-finished edits never go live. Example: offer approvals for one or
eight hours in addition to "once" and "session".

```bash
mkdir ~/mcp-policy && cd ~/mcp-policy && git init -q
git checkout -q -b upstream                       # the shipped logic, unchanged
cp -R /usr/share/mcp-gateway/policy/. .
git add -A && git commit -qm "shipped policy $(rpm -q --qf '%{VERSION}' mcp-gateway)"
git checkout -q -b local                          # your changes
sed -i 's/"scopes": \["once", "session"\],/"scopes": ["once", "session", "1h", "8h"],/' mcp/authz.rego
git commit -qam "approval durations"
```

The change:

```diff
 	"ask": {
 		"channel": ask_channel,
 		"prompt": sprintf("Allow %s: %s %s/%s?", [input.principal.sub, input.action, input.resource.server, input.resource.name]),
-		"scopes": ["once", "session"],
+		"scopes": ["once", "session", "1h", "8h"],
 		"fallback": "oob",
 	},
```

The approval page then offers "For 1h" and "For 8h", and the resulting
grants (`"scope": "duration"`) are accepted by the shipped `granted`
rule until they expire.

Install it (after testing, see [Testing](#testing)):

```bash
install -d /etc/mcp-gateway/policy-logic
rsync -a --delete --exclude .git ~/mcp-policy/ /etc/mcp-gateway/policy-logic/
restorecon -R /etc/mcp-gateway/policy-logic
```

Then make OPA use the copy **instead of** the shipped logic. Loading
both would define every rule twice.

**Directory mode**: a drop-in replacing the first directory:

```ini
# /etc/systemd/system/mcp-opa.service.d/policy.conf
[Service]
ExecStart=
ExecStart=/usr/bin/opa run --server \
    --addr unix:///run/mcp-gateway/opa.sock \
    --unix-socket-perm 0660 \
    --watch \
    --log-format json \
    --set=decision_logs.console=true \
    --set=decision_logs.mask_decision=/mcp/log/mask \
    $OPA_EXTRA_ARGS \
    /etc/mcp-gateway/policy-logic \
    mcp:/etc/mcp-gateway/policy
```

```bash
systemctl daemon-reload && systemctl restart mcp-opa.service
```

**Signed bundle mode**: either build with `-V`:

```bash
mcp-policy-bundle -V /etc/mcp-gateway/policy-logic
```

or put only the changed files at their shipped relative path into
`/etc/mcp-gateway/policy/` (here `/etc/mcp-gateway/policy/mcp/authz.rego`):
the bundle tool lays your files over the shipped ones, so they replace
them, and Cockpit's "Sign and apply" (which always uses the default
directories) keeps working. Do not do this in directory mode, where both
files would be loaded.

After a package update, bring the new shipped logic into `upstream`
and merge it into your changes:

```bash
cd ~/mcp-policy
git checkout -q upstream
cp -R /usr/share/mcp-gateway/policy/. .
git add -A && git commit -qm "shipped policy $(rpm -q --qf '%{VERSION}' mcp-gateway)"
git checkout -q local && git merge upstream       # resolve conflicts, test, install
```

Until you install the merged copy, OPA keeps running your previous copy,
not the updated shipped logic.

### C. Writing a policy from scratch

A complete policy implements every query of [the contract](#the-contract).
A minimal example, in `/etc/mcp-gateway/policy-logic/` (deployed like
approach B):

```rego
# /etc/mcp-gateway/policy-logic/mcp/authz.rego
#
# Members of "mcp-admins" may use everything, members of "dev" may use
# the git server and must get approval for "push"; everything else is
# denied.
package mcp.authz

import rego.v1

default decision := {"effect": "deny", "reason": "not permitted"}

decision := {"effect": "allow"} if {
	"mcp-admins" in input.principal.groups
} else := {"effect": "allow", "reason": "approved"} if {
	needs_approval
	approved
} else := {
	"effect": "ask",
	"ask": {
		"channel": "url",
		"prompt": sprintf("Allow %s to push?", [input.principal.sub]),
		"scopes": ["once", "1h"],
		"fallback": "oob",
	},
} if {
	needs_approval
} else := {"effect": "allow"} if {
	developer_git
}

developer_git if {
	"dev" in input.principal.groups
	input.resource.server == "git"
	input.action in {"tools.call", "prompts.get"}
}

needs_approval if {
	developer_git
	input.action == "tools.call"
	input.resource.name == "push"
}

approved if {
	some g in input.grants
	g.sub == input.principal.sub
	g.server == input.resource.server
	g.tool == input.resource.name
	in_scope(g)
	time.parse_rfc3339_ns(g.expires) > time.now_ns()
}

# A "session" grant counts only in the session it was given for.
in_scope(g) if g.scope in {"once", "duration"}

in_scope(g) if {
	g.scope == "session"
	g.session_id == input.principal.session_id
}
```

```rego
# /etc/mcp-gateway/policy-logic/mcp/filter.rego
package mcp.filter

import rego.v1

use_action := {"tool": "tools.call", "prompt": "prompts.get", "resource": "resources.read", "resource_template": "completion.complete"}

visible contains r if {
	some r in input.resources
	d := data.mcp.authz.decision with input as {
		"principal": input.principal,
		"action": use_action[r.kind],
		"resource": r,
		"grants": [],
		"discovery": true,
	}
	d.effect != "deny"
}
```

```rego
# /etc/mcp-gateway/policy-logic/mcp/approvals.rego
#
# Only members of "mcp-admins" decide on approvals, see and revoke grants
# and see and stop instances; they are also the ones told by mail.
package mcp.approvals

import rego.v1

default allow := false

allow if "mcp-admins" in input.approver.groups

default manage_grant := false

manage_grant if "mcp-admins" in input.approver.groups

default manage_instance := false

manage_instance if "mcp-admins" in input.approver.groups

notify contains "group:mcp-admins"
```

```rego
# /etc/mcp-gateway/policy-logic/mcp/log.rego
package mcp.log

import rego.v1

mask contains "/input/args"

mask contains "/input/request/args"
```

This policy ignores `data.json`, so Cockpit's role editor has no effect
with it. The `default decision` makes sure the decision is never
undefined; the `else` chain makes the precedence explicit.

## Custom data

Put data your rules use into `data.json` files below
`/etc/mcp-gateway/policy/`, preferably **below `rbac/`**
(`/etc/mcp-gateway/policy/rbac/<name>/data.json` → `data.mcp.rbac.<name>`):
the gateway notices policy changes by comparing the loaded Rego modules
and `data.mcp.rbac`, and only then tells agents to list their tools again
and writes a `mcp-policy-change` audit event. Changes to data elsewhere
take effect as well, but agents are not told, so their tool lists may be
stale until they reconnect.

OPA runs without network access; rules cannot fetch data at decision
time (`http.send` fails). Deliver data as files, or in bundles from a
bundle server (chapter 6).

## Testing

Test every custom rule before deploying it. Keep tests **outside**
`/etc/mcp-gateway/policy/` (for example in
`/etc/mcp-gateway/policy-tests/` or in your repository), so OPA does
not load them into the running policy.

```rego
# /etc/mcp-gateway/policy-tests/custom_test.rego
package custom_test

import rego.v1

import data.mcp.approvals
import data.mcp.authz

alice := {
	"sub": "alice", "uid": 1000, "groups": ["dev"], "home": "/home/alice",
	"transport": "unix", "session_id": "s1",
}

write_at(time) := {
	"principal": alice,
	"action": "tools.call",
	"resource": {"server": "fs", "kind": "tool", "name": "write_file"},
	"args": {"path": "/home/alice/notes.txt"},
	"grants": [],
	"context": {"time": time, "transport": "unix"},
}

test_write_on_monday_morning_asks if {
	authz.decision.effect == "ask" with input as write_at("2026-09-28T08:00:00Z")
}

test_write_on_sunday_denied if {
	authz.decision.effect == "deny" with input as write_at("2026-09-27T10:00:00Z")
}

test_write_at_night_denied if {
	authz.decision.effect == "deny" with input as write_at("2026-09-28T20:00:00Z")
}

test_read_on_sunday_allowed if {
	req := object.union(write_at("2026-09-27T10:00:00Z"), {"resource": {"server": "fs", "kind": "tool", "name": "read_file"}})
	authz.decision.effect == "allow" with input as req
}

test_write_stays_listed if {
	visible := data.mcp.filter.visible with input as {
		"principal": alice,
		"resources": [{"server": "fs", "kind": "tool", "name": "write_file"}],
	}
	count(visible) == 1
}

test_destructive_tool_denied if {
	req := object.union(write_at("2026-09-28T08:00:00Z"), {"resource": {
		"server": "git", "kind": "tool", "name": "reset",
		"annotations": {"destructiveHint": true},
	}})
	authz.decision.effect == "deny" with input as req
}

test_manager_may_approve if {
	approvals.allow with input as {
		"request": {"principal": alice, "server": "fs", "name": "write_file", "action": "tools.call"},
		"approver": {"name": "bob", "uid": 1001, "groups": ["users"]},
	}
		with data.mcp.rbac.managers as {"alice": "bob"}
}

test_colleague_may_not_approve if {
	not approvals.allow with input as {
		"request": {"principal": alice, "server": "fs", "name": "write_file", "action": "tools.call"},
		"approver": {"name": "carol", "uid": 1002, "groups": ["users"]},
	}
		with data.mcp.rbac.managers as {"alice": "bob"}
}
```

Run them together with the policy exactly as OPA loads it:

```bash
P="/usr/share/mcp-gateway/policy mcp:/etc/mcp-gateway/policy"   # approach B/C: /etc/mcp-gateway/policy-logic instead of /usr/share/…
opa fmt --list /etc/mcp-gateway/policy /etc/mcp-gateway/policy-tests   # lists files that need formatting
opa check --strict $P                                                  # what mcp-policy-bundle requires
opa test -v $P /etc/mcp-gateway/policy-tests
```

`mcp:` in front of `/etc/mcp-gateway/policy` loads its data files below
`data.mcp`, as `mcp-opa.service` does; without it the role data would be
`data.rbac` and the shipped rules would find none.

`opa check` does not catch rules defined twice with different values
(see approach A); only evaluation does, so test the cases where your
rules apply.

The shipped policy is also linted with [Regal](https://www.openpolicyagent.org/projects/regal)
in CI; its configuration, `.regal/config.yaml` in the source repository,
suits custom policy as well (`regal lint /etc/mcp-gateway/policy`).

### Single decisions

```bash
opa eval -f pretty -d /usr/share/mcp-gateway/policy -d mcp:/etc/mcp-gateway/policy \
    -i input.json 'data.mcp.authz.decision'
opa eval -f pretty … -i input.json --explain=notes 'data.mcp.authz.decision'   # with trace() notes
opa eval … -i input.json --profile 'data.mcp.authz.decision'                   # where the time goes
```

Or ask the running OPA directly (as root), with the input wrapped in
`{"input": …}`:

```bash
jq '{input: .}' input.json | curl -s --unix-socket /run/mcp-gateway/opa.sock \
    -d @- http://opa/v1/data/mcp/authz/decision | jq
```

Real inputs can be taken from OPA's decision log
(`journalctl -u mcp-opa.service -o cat | jq 'select(.msg == "Decision Log")'`),
with arguments masked; the gateway's audit record with the same
`decision_id` tells which call it was.

## Deploying

### Directory mode

```bash
install -D -m0644 office_hours.rego /etc/mcp-gateway/policy/custom/office_hours.rego.new
mv /etc/mcp-gateway/policy/custom/office_hours.rego.new /etc/mcp-gateway/policy/custom/office_hours.rego
restorecon -R /etc/mcp-gateway/policy
opa check --strict /usr/share/mcp-gateway/policy mcp:/etc/mcp-gateway/policy \
  && opa test /usr/share/mcp-gateway/policy mcp:/etc/mcp-gateway/policy /etc/mcp-gateway/policy-tests
journalctl -u mcp-opa.service -n 5 -o cat          # a load error shows up as "Processed file watch event." with "err"
journalctl -u mcp-gateway.service -o cat | grep mcp-policy-change | tail -1
```

OPA loads the file within seconds. A file that does not compile is
rejected and the previous policy stays active; check the OPA journal
after every change, because nothing else tells you. To take a rule out,
remove the file.

Install files under a name OPA ignores (like `.new` above) and rename
them, so OPA never loads a half-written file.

### Signed bundle mode

```bash
mcp-policy-bundle                    # builds from the default directories, checks, signs, restarts OPA
mcp-policy-bundle -V /etc/mcp-gateway/policy-logic    # approach B/C in a separate directory
```

The build fails, and nothing changes, if the policy does not pass
`opa check --strict`. After the restart OPA verifies the signature;
`GET /v1/policy` on the control socket and the Cockpit Policy tab show
the new revision. To roll back, keep the previous `policy.tar.gz` and
copy it back, then `systemctl restart mcp-opa.service`.

### Several gateways

Build and sign bundles in one place (a CI pipeline running `opa test`)
and let every gateway fetch them from a bundle server (chapter 6). The
bundle then contains the logic too, so all gateways run the same
revision, independently of their package versions.

## Pitfalls

- **Undefined is not false.** A rule whose body refers to a missing
  field does not apply. `input.principal.cert.subject == "…"` is simply
  undefined for clients without a certificate; `not input.x` is true
  when `input.x` is missing. Think through what happens for local,
  remote, certificate-less and account-less principals.
- **The filter asks too.** Every `decision` rule is also evaluated for
  listings, with `"discovery": true` and without `args`, `grants` and
  `context`. A denial that depends on those must start with
  `not input.discovery`, or it hides the item.
- **Deny wins in the shipped logic**, even over approvals. Adding a
  `denied` rule cannot be overridden by any grant.
- **Untrusted inputs.** `principal.client`, `context.client_capabilities`
  and `resource.annotations` come from the agent or the MCP server. Use
  them to deny more, never to allow.
- **Time.** Use `input.context.time` (the request's time, testable) or
  `time.now_ns()`. `time.clock` and `time.weekday` take a time zone;
  without one they use UTC.
- **Speed.** The whole decision must finish within `policy.timeout`
  (250 ms) and the filter evaluates one decision per listed item. Avoid
  iterating over large data sets per decision; index data by key
  instead (`data.mcp.rbac.managers[sub]`).
- **Strictness.** `mcp-policy-bundle` requires `opa check --strict`
  (no unused variables or imports, no deprecated built-ins); check with
  `--strict` in directory mode too, so switching to bundles later is
  painless.
- **Reasons are visible.** The `reason` of a decision is sent to the
  agent. Do not put secrets or internal details in it.
- **Upgrades.** Additions (approach A) rely on rule names of the shipped
  logic; copies (approach B) miss upstream fixes until you merge them.
  Re-run your tests after every `zypper update mcp-gateway`.
