# 7. Approvals

When a permission says `"require_approval": true`, the call waits until a
human decides. This chapter explains where that decision is made, how
long it counts, and how approvers learn that something is waiting.

## The flow

1. The agent calls a tool; policy answers **ask**, naming a channel and
   the scopes the approver may choose from.
2. The gateway obtains a decision through the channel (or its fallback)
   and keeps the call waiting, at most `approval_timeout` (120 s).
3. On approval, a **grant** is recorded and policy is asked again with
   it; the call runs if policy now allows it. On denial or timeout, the
   agent gets a tool error ("declined by user", "approval failed").
4. The decision is audited (`mcp-approval`, also in the kernel audit log).

While a call waits, an agent that asked for progress on it (a
`progressToken`) gets a progress notification at once and then every
`approvals.progress_interval` (15 s), with the message "Waiting for
approval of *server*/*tool*". Agents give up on calls that stay silent:
the TypeScript SDK after 60 s by default, unless progress arrives and
the agent let progress extend the timeout. An agent that sends no
`progressToken` gets nothing, and may give up before `approval_timeout`
(120 s); chapter 5 lists how known clients behave.

## Channels

| Channel | Where the decision is made | Trust | Requirements |
|---|---|---|---|
| `form` | a dialog of the **agent's own client** (MCP form elicitation) | low: the agent's client answers, it may be configured to accept automatically | the client supports elicitation |
| `url` (default) | the **approval page** (Cockpit), which the client offers to open (MCP URL elicitation) | high: the approver authenticates to Cockpit; the agent cannot see or influence the page | `approvals.url_template` set, the client supports URL elicitation, the control socket enabled |
| `oob` | the approval page, the **desktop notification** or the **mail** leads there; the agent only gets a log message ("Waiting for approval of fs/write_file at … (id a-…)") | high | the control socket enabled |

The policy names a channel per permission (`approval_channel`); the
shipped policy uses `oob` as fallback. So if the agent cannot do URL
elicitation, or `url_template` is empty, the request appears in the
approval inbox instead. If neither is possible, the call is denied with
"approval via url required but not available".

Use `form` only for low-risk confirmations ("really send this
message?"); a compromised or over-eager agent can answer it itself. Use
`url` or `oob` for anything that matters, and consider removing `self`
from the server's approver rules so that someone else must approve
(chapter 6).

### Setting up the approval page

The approval page is the Cockpit page (chapter 8). Tell the gateway its
public address so it can hand agents a link:

```yaml
approvals:
  url_template: https://gw.example.com:9090/mcp-gateway#/approvals/{id}
```

`{id}` is replaced by the approval id. For remote agents, the host must
be reachable by the person using the agent.

## Scopes and grants

The approver picks how long the approval counts, from the scopes the
policy offered:

| Scope | Grant | Valid for |
|---|---|---|
| `once` ("Only this call") | used by the waiting call only; not stored | 1 minute |
| `session` ("For this session") | stored, bound to the agent's session | until the session ends, at most 8 hours |
| a duration such as `1h` ("For 1h") | stored, not bound to a session | that time, at most 30 days |

A permission offers "once" and "session" unless its `approval_scopes`
says otherwise (chapter 6):

```json
{"server": "zypp", "tool": "*", "require_approval": true, "approval_channel": "oob",
 "approval_scopes": ["once", "1h", "8h"]}
```

"Session" means the agent's MCP connection. Some agents open a new one
for every prompt (Kit does), and a session grant then ends with the
prompt; offer a duration instead, which also survives reconnects and
gateway restarts. Keep durations short for changing tools: the grant
covers every call of that tool by the same principal until it expires
or is revoked.

A grant covers the same principal, server and tool, whatever the
arguments. Permissions with `args` conditions still apply: a grant
for `write_file` does not make a write outside the home directory
approvable.

Grants are kept in `/var/lib/mcp-gateway/grants.json` and survive
restarts. See and revoke them on the Approvals tab in Cockpit or with
the control API; revoking one makes the next call ask again and is
audited (`mcp-grant-revoke`).

A grant is checked when a call starts: a call that started under a
grant finishes even if the grant expires or is revoked meanwhile.

## Who may approve

Approver rules in the policy data decide who may see and decide on a
request (chapter 6). By default: the requesting user themself (`self`)
and users with the `admin` role. `root` may always decide. Someone else's
approval is reported as not found.

## Pending approvals across disconnects and restarts

Pending approvals are written to `/var/lib/mcp-gateway/pending.json`.

- When the call's connection goes away (agent closed, network dropped,
  gateway restarted), the approval **stays pending** until it times out,
  shown as "no call waiting". The scope "session" is no longer offered,
  because that session is gone.
- If it is approved meanwhile with "once", the approval is kept as a
  one-time grant for 15 minutes: the next identical call (same principal,
  tool and arguments) runs without asking again.
- If the agent retries the same call while the approval is pending, the
  retry **takes over** the approval: same id, so an approval page already
  open stays valid.

Remote agents that support stream resumption usually do not lose the
call at all (chapter 5).

## Notifications

Approvers learn about pending approvals from:

- the **Cockpit** Approvals tab, live;
- **desktop notifications** (`mcp-gateway-desktop`);
- **e-mail** (configured in the gateway).

Neither notifications nor mail can approve: they link to the approval
page, where the approver authenticates. Anyone in a desktop session could
click a notification button, and mail links can be forwarded.

### Desktop notifications

The package installs `mcp-gateway-notify` with an XDG autostart entry
(`/etc/xdg/autostart/mcp-gateway-notify.desktop`). In every graphical
session it connects to the control socket as the logged-in user, follows
the approvals that user may decide on, and shows a notification for each
(through the desktop's notification service,
`org.freedesktop.Notifications`). Its action opens the approval page;
the notification disappears when the approval is decided or times out.
It exits quietly for users without access to the control socket.

```
mcp-gateway-notify [--socket PATH] [--url TEMPLATE] [--debug]
```

| Flag | Default |
|---|---|
| `--socket` | `/run/mcp-gateway/control.sock` |
| `--url` | `https://localhost:9090/mcp-gateway#/approvals/{id}` (used when the gateway has no `url_template`) |
| `--debug` | log debug messages |

To disable it for a user: `cp /etc/xdg/autostart/mcp-gateway-notify.desktop
~/.config/autostart/` and add `Hidden=true`.

### E-mail

```yaml
notifications:
  email:
    smtp: localhost:25                 # the local MTA (postfix), or a relay
    from: mcp-gateway@gw.example.com
    to: "{user}@example.com"           # default "{user}": local delivery
```

```bash
setsebool -P mcpgw_can_send_mail on    # let the gateway connect to the mail server
systemctl restart mcp-gateway.service
```

- **Recipients** come from the approver rules of the request's server
  (policy rule `data.mcp.approvals.notify`): `self` (if the principal
  has a local account), `user:` rules, members of `group:` rules, and
  users and group members bound to `role:` rules. Groups are expanded
  with `getent group` (members listed in the group entry; users having
  the group only as their primary group are not included). Each name
  becomes an address through `to`. All recipients get one mail (as
  undisclosed recipients).
- A mail goes out once per new pending approval (not for retries taking
  one over). It names the principal, the call, the self-reported client
  and the time-out, and links to the approval page (`url_template`),
  otherwise it names the approval id in Cockpit.
- Arguments are left out unless `include_args: true`; they may contain
  personal data and mail is rarely end-to-end protected.
- For an authenticated relay:

  ```yaml
      smtp: smtp.example.com:587
      starttls: always
      username: mcp-gateway
      password_file: /etc/mcp-gateway/smtp-password
  ```

  ```bash
  install -m0640 -g mcp-gateway /dev/stdin /etc/mcp-gateway/smtp-password <<<'secret'
  ```

  The password is read at start and sent only over TLS or to localhost.
  Do not put it in `/etc/mcp-gateway/credentials`: that directory is for
  MCP servers and the gateway itself cannot read it.

Delivery failures are logged (`journalctl -u mcp-gateway`) and do not
affect the approval.

## Scripting approvals

The control API (chapter 11) lets scripts see and decide approvals as
the calling user, with the same approver rules:

```bash
S=/run/mcp-gateway/control.sock
curl -s --unix-socket $S http://localhost/v1/approvals | jq
curl -s --unix-socket $S -X POST -d '{"decision":"approve","scope":"once"}' \
     http://localhost/v1/approvals/a-0123456789abcdef0123456789abcdef
curl -s --unix-socket $S http://localhost/v1/grants | jq
curl -s --unix-socket $S -X DELETE http://localhost/v1/grants/g-0123456789abcdef
curl -sN --unix-socket $S http://localhost/v1/events       # live stream
```
