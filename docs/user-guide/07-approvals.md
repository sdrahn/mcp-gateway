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
| `url` (default) | the **approval page** (Cockpit, or the gateway's own page), which the client offers to open (MCP URL elicitation) | high: the approver authenticates to Cockpit, or signs in with the identity provider; the agent cannot see or influence the page | `approvals.url_template` set, or the gateway's page set up; the client supports URL elicitation, the control socket enabled |
| `oob` | the approval page, the **desktop notification** or the **mail** leads there, or the **command line** (`mcp-gateway-admin approvals`, below); the agent only gets a log message ("Waiting for approval of fs/write_file at … (id a-…)"), or, for the agents `approvals.no_wait` names (Kit), a tool error at once that says how to get it decided (below) | high | the control socket enabled |

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

The approval page is the Cockpit page (chapter 8), or the gateway's own
page on its HTTPS listener (below), which needs no Cockpit. For
Cockpit, tell the gateway its public address so it can hand agents a
link:

```yaml
approvals:
  url_template: https://gw.example.com:9090/mcp-gateway#/approvals/{id}
```

`{id}` is replaced by the approval id. For remote agents, the host must
be reachable by the person using the agent.

## The gateway's approval page

With the HTTPS listener for remote agents (chapter 5, "Remote agents (HTTPS)"),
the gateway serves an approval page of its own: `/approvals/` lists the
approvals the signed-in approver may decide and the grants they may
revoke, `/approvals/{id}` shows one approval (the call, for whom, the
agent's client as it names itself, the arguments, the scopes) to approve
or deny. Approvers sign in with the identity provider the gateway
already takes tokens from (OpenID Connect, authorization code with
PKCE). Links in URL elicitations, mail and desktop notifications lead
there once it is set up, unless `approvals.url_template` names another
page (Cockpit).

1. Register a client for the page at the identity provider, with the
   redirect URI `https://<host:port of http.audience>/approvals/callback`
   and the authorization code flow. With **Keycloak**: in the realm of
   `http.issuer`, *Clients → Create client*, client ID
   `mcp-gateway-approvals`, *Standard flow* on, *Valid redirect URIs*
   the URI above; *Client authentication* off for a public client, or on
   for a confidential one (then copy its secret from *Credentials*).
2. Tell the gateway, which checks the client at the provider:

   ```console
   # mcp-gateway-admin setup http --client-id mcp-gateway-approvals --write
   # mcp-gateway-admin setup http --client-id mcp-gateway-approvals \
       --client-secret-file /etc/mcp-gateway/approvals-client-secret --write   # confidential
   # systemctl restart mcp-gateway.service
   ```

   That sets `approvals.page.client_id` (and `client_secret_file`;
   chapter 3); the page is served from the next start. The secret file
   belongs in `/etc/mcp-gateway`, readable by root and the
   `mcp-gateway` group (`chmod 0640`, `chgrp mcp-gateway`).
3. `mcp-gateway-admin doctor` checks it from then on (`approval page`,
   chapter 10).

Who may decide is as for every approval: the approver rules (chapter 6)
match the principal the sign-in makes. With `http.local_user_claim`
that is the local account the ID token names: the rules match it as
that account (`user:alice`, `group:` with the account's groups, `role:`
through its bindings, "self" for its own calls). A sign-in without a
local account matches only the rules written for remote approvers,
`remote-user:<sub>` (the token's subject) and `remote-group:<group>`
(a group of `http.groups_claim`); `user:`, `group:` and `role:` never
match it, so that a subject or token group named like a local account
or group gets none of its rights. A sign-in is never root, also when it
maps to the account root.

```yaml
approvers:
  fs: ["user:jack", "remote-user:6c1f0e2a-…", "remote-group:fs-approvers"]
```

The page keeps the sign-in as a session cookie of its own for
`approvals.page.session_ttl` (1 h; *Sign out* ends it), with the groups
the ID token had: a user disabled or a group removed at the identity
provider keeps the page until then (changed approver rules apply at
once). It never takes
an agent's token (a request with `Authorization: Bearer` is sent to
sign in), and keeps nothing for a browser that has not signed in (the
sign-in in progress is in an encrypted cookie). Decisions need the page's own form: without its CSRF token,
or from another origin, they are refused and nothing is decided. The
page is never shown in a frame, and is not cached. Sign-ins are audited
(`mcp-approver-sign-in`), decisions and revocations with `via=page`
(chapter 11, "Audit records").

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

"Session" means the agent's MCP connection. Some agents open new ones
often (Kit: one per run, and a new one after 5 minutes without calls;
chapter 5), and a session grant then ends early; offer a duration instead, which also survives reconnects and
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

## Agents of MCP 2026-07-28

Agents of MCP 2026-07-28 have no session for a call to wait in. For
them an approval is a *multi round-trip request*: the call is answered
at once with what is needed (an `InputRequiredResult`), and the agent's
SDK calls again with the answer. The agent sees one call.

| Channel | First answer | The agent's retry |
|---|---|---|
| `form` | the approval form as an input request (`approval`) | carries the choice; the call runs, or is denied ("declined by user") |
| `url` | the approval page as a URL-mode input request | waits up to `approvals.retry_wait` (25 s, with progress) for the decision; otherwise it is answered to retry again, and the next retry waits again |
| `oob` | waits up to `approvals.retry_wait` first, then (undecided) no input request, only the state; the request is in the inbox (and the agent gets the log message if it asked for log messages) | as for `url` |

Each round trip ends before the agents' request timeouts, so the
approval may take until `approval_timeout` (120 s) whatever the agent's
timeout. For agents without a request timeout of their own, named in
`agents.no_request_timeout` (Kit, as shipped; chapter 3), a round waits
until the decision instead. A decision made while no retry waits is kept as for a call
that went away (above): the next retry finds it. The scope "session" is
not offered: there is no session.

Signing in to a server (chapter 4) works the same way: the sign-in link
is a URL-mode input request, and retries wait for the sign-in to
complete. An agent that cannot open links gets the link in the tool
error to show, as before.

A server of MCP 2026-07-28 that asks for input (a form, sampling,
roots) has its requests passed on to the agent the same way, each
decided by policy first (`client` permissions, `allow_sensitive`,
pseudonymization of what goes to the model); what policy refuses the
gateway answers itself (a form declined; a refused sampling or roots
request ends the call). At most 8 rounds per call.

What the agent sends back with its retry (the `requestState`) is sealed
by the gateway: the agent can neither read nor change it, it holds only
for the same user, endpoint, tool and arguments, and for 30 minutes. A
restart of the gateway invalidates it; the agent gets "requestState is
not valid for this request" and calls again, which takes over the
pending approval.

## Agents told at once

Some agents show nothing while a call waits (Kit): their user sees an
agent that seems stuck, and the approver may never hear of it. For the
clients `approvals.no_wait` names (`[kit]` as shipped; chapter 3), an
`oob` approval is not waited for. The call is answered at once with a
tool error the model passes on:

```text
approval needed: fs/write_file waits for an approver's decision (approval a-7f3e9c…, open until 14:05 UTC).
Tell the user: an approver runs "mcp-gateway-admin approvals approve a-7f3e9c…" on gw1, or decides at
https://gw1.example.com:9090/mcp-gateway#/approvals/a-7f3e9c…. Then call the tool again with the same
arguments; it runs once approved.
```

(the link only with `approvals.url_template` set). The approval stays
pending for 15 minutes, listed with WAITING `no`, and is announced as
usual (notifications, mail). The agent's next attempt with the same
arguments:

| The approval | The attempt |
|---|---|
| still pending | gets the same tool error, the same id |
| approved | runs (with scope `once`, this attempt only; with a longer scope, the grant's calls) |
| denied | is refused: "declined by an approver"; the attempt after asks again |
| expired | asks again, with a new id |

The tool error is no refusal: the decision is logged as `ask` and
stays the approver's. An agent the key does not name waits as before.
`approvals.no_wait: ["*"]` tells every agent at once, `[]` none. An
agent that waits gains nothing from it: one that shows progress
(Claude Code) or asks its user (`url`, `form`) is better left waiting.

## Deciding from the command line

Where Cockpit is not running or not reachable, decide in a terminal on
the gateway's host, also over SSH. `mcp-gateway-admin approvals` talks to
the control socket as the user who runs it, with the same approver
rules, scopes and audit as Cockpit:

```console
$ mcp-gateway-admin approvals
USER   CALL           CLIENT     SCOPES        SINCE    EXPIRES  WAITING  ID
alice  fs/write_file  kit 0.3.1  once,session  30s ago  in 1m    yes      a-7f3e9c
$ mcp-gateway-admin approvals show a-7f3e9c       # with the call's arguments
$ mcp-gateway-admin approvals approve a-7f3e9c    # asks first; --yes does not
Approve fs/write_file for alice (a-7f3e9c, scope once)? [y/N] y
approved a-7f3e9c (fs/write_file for alice, scope once)
$ mcp-gateway-admin approvals deny a-7f3e9c
$ mcp-gateway-admin approvals watch               # follow them, Ctrl-C ends
```

- The id may be shortened to any prefix that names one approval.
- `approve` grants `once` unless `--scope` names another the approval
  offers (`session`, a duration such as `1h`); without `once` among them
  and with several offered, `--scope` is needed.
- An approval that is not yours to decide reads as unknown ("no such
  approval"), as in Cockpit. Root sees and decides all.
- An approval whose call went away (WAITING `no`) can still be decided:
  the agent's next attempt finds the decision.
- `mcp-gateway-admin grants` lists the grants approvals left, and
  `grants revoke ID` revokes one.
- Decisions and revocations from the command line are audited with
  `via=cli` (Cockpit's with `via=cockpit`; chapter 11, "Audit records").

## Notifications

Approvers learn about pending approvals from:

- the **Cockpit** Approvals tab, live;
- the **command line**: `mcp-gateway-admin approvals watch`;
- the gateway's **own approval page** (above), where links lead once it
  is set up;
- the **agent's user**, for the agents `approvals.no_wait` names ("Agents
  told at once", above): the tool error says what to ask an approver for;
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
systemctl reload mcp-gateway.service    # or wait 10 s: notifications are reloaded
```

- **Recipients** come from the approver rules of the request's server
  (policy rule `data.mcp.approvals.notify`): `self` (if the principal
  has a local account), `user:` rules, members of `group:` rules, and
  users and group members bound to `role:` rules. Groups are expanded
  through NSS: the members listed in the group entry (`getent group`),
  and the users whose primary group it is (`getent passwd`). With SSSD
  or LDAP, which often do not enumerate users (`enumerate = true`), the
  latter are found among the local users who have used the gateway or
  its Cockpit pages (remembered in `/var/lib/mcp-gateway/principals.json`);
  name others as `user:` approvers. `mcp-gateway-admin doctor` warns
  about an approver group in which it finds nobody. Each name
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

  The password is read at start and at every reload (also when the file
  changes), and sent only over TLS or to localhost.
  Do not put it in `/etc/mcp-gateway/credentials`: that directory is for
  MCP servers and the gateway itself cannot read it.

Delivery failures are logged (`journalctl -u mcp-gateway`) and do not
affect the approval.

## Scripting approvals

`mcp-gateway-admin approvals` and `grants` with `--json` (and
`approve --yes`) suit scripts. Underneath is the control API (chapter
11), which sees and decides approvals as the calling user, with the same
approver rules:

```bash
S=/run/mcp-gateway/control.sock
curl -s --unix-socket $S http://localhost/v1/approvals | jq
curl -s --unix-socket $S -X POST -d '{"decision":"approve","scope":"once"}' \
     http://localhost/v1/approvals/a-0123456789abcdef0123456789abcdef
curl -s --unix-socket $S http://localhost/v1/grants | jq
curl -s --unix-socket $S -X DELETE http://localhost/v1/grants/g-0123456789abcdef
curl -sN --unix-socket $S http://localhost/v1/events       # live stream
```
