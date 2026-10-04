# 8. The Cockpit page

`mcp-gateway-cockpit` adds a page to Cockpit, the web console of
openSUSE and SLES. It is the approval page for the `url` and `oob`
channels, and the place to watch servers, maintain role bindings and
read audit records.

```bash
zypper install mcp-gateway-cockpit
systemctl enable --now cockpit.socket
firewall-cmd --permanent --add-service=cockpit && firewall-cmd --reload
```

Open `https://<host>:9090`, log in with your local account and choose
**MCP Gateway** (under *Tools*). Addresses:

| Address | Opens |
|---|---|
| `https://<host>:9090/mcp-gateway` | the page (Approvals tab) |
| `…/mcp-gateway#/approvals/<id>` | one approval, highlighted (the link agents, notifications and mail use) |
| `…/mcp-gateway#/servers`, `#/policy`, `#/audit` | the other tabs |

## Access

The page talks to the gateway's control socket **as the logged-in
user**; the gateway identifies you by the kernel, and policy decides
what you see (chapter 6, approver rules). So:

- you must be a member of the control socket's group (`mcp-users` as
  shipped) to use the page at all;
- you see approvals, grants and instances you may manage: your own
  (rule `self`), or everyone's with the `admin` role;
- editing the role data, signing bundles and reading the journal need
  Cockpit's **administrative access** (the "Limited access" / "Administrative
  access" switch; `sudo` rights).

## Approvals

**Pending approvals** lists the requests you may decide on, live. Each
shows the principal, the call with its arguments, the channel it was
asked through and the time left, with a note if the agent is no longer
waiting (chapter 7). Buttons approve for one of the scopes the policy
offered ("Only this call", "For this session", "For 1h", …) or deny.

Only approve what you expect: check the arguments, not just the tool
name. The agent cannot see or influence this page.

**Grants** lists standing approvals you may manage (call, principal,
scope, expiry, approver); **Revoke** removes one, and the next call asks
again.

## Servers

The registered MCP servers with their SELinux domain, isolation,
network access and account, and the running instances you may manage:
principal, unit name, sessions, start time. For each instance:

- **Show log** shows the last 50 lines of the instance's journal (the
  server's stderr);
- **Stop** ends it (calls in flight fail; the next call starts a new
  instance).

After the configuration changed while the gateway runs (chapter 3,
"Changing the configuration while the gateway runs"; chapter 4,
"Changing definitions while the gateway runs"):

- an instance started from a server's previous definition is marked
  "previous definition: runs until no session uses it"; sessions move to
  an instance of the new definition at their next call;
- a server removed from the configuration is listed as long as
  instances of it run, marked "server removed: stops once its calls end";
- a note above the servers says when `gateway.yaml` or a server
  definition did not load (with the error; the gateway runs with what
  it had) and which keys of `gateway.yaml` take effect only at the next
  start;
- **Reload configuration** runs `systemctl reload mcp-gateway.service`
  (administrative access): the gateway checks the configuration first
  and keeps what it has if a file does not load; the page says so.

## Policy

- **Policy status**: whether OPA loads the policy directories or a
  bundle, and the active bundle revisions.
- **Role bindings**: which users and groups hold which roles; add and
  remove bindings.
- **Roles**: the permissions of each role, read-only.
- **Edit the role data as JSON**: the whole `data.json`, including
  roles and approver rules; **Save** writes it (validated as JSON).

Before any change is saved, the page checks it against the role data's
schema (chapter 6) and asks the gateway **what it changes**: for every
user and group the old or new bindings name, and every tool, prompt and
resource template the MCP servers offer (plus the requests servers send
to the agent), it compares the decision now and after the change. If
any differs, the page lists them ("alice, fs, tool write_file: denied →
needs approval") and saves only after **Save**. Decisions are made
without arguments, as for tool lists: a permission limited to certain
arguments counts as allowing the tool. Servers with `discovery:
instance` are listed as not checked. The comparison is available to
those the default approver rules name besides `self` (with the shipped
data: the `admin` role) and to root; for others the page saves without
it.

In directory mode (the default), OPA picks up saved changes within
seconds and agents are told to list their tools again. In signed bundle
mode, saving changes only the source file; a note says so and, if the
signing key is on this host, offers **Sign and apply**, which runs
`mcp-policy-bundle` and restarts OPA with the new revision. With a
bundle server, changes must be made where the bundles are built.

## Audit

The gateway's audit records from the journal: time, kind (allowed,
denied, event), principal, call and details (reason, grant, decision id,
argument digest or arguments). Filter by kind (denials; allowed;
approvals, revocations and policy changes) and by text (principal,
server, tool…), and choose how many journal lines to read. Reading the
system journal needs administrative access or membership in
`systemd-journal`/`wheel`.

## If the page shows an error

| Message | Cause |
|---|---|
| cannot connect / "not-found" on the control socket | the gateway is not running, the control socket is disabled (`approvals.control_socket: "-"`), or you are not in `mcp-users` (log out and in after adding) |
| "Policy status unavailable" | OPA is not running: `systemctl status mcp-opa.service` |
| saving the role data fails with "access denied" | switch to administrative access |
| audit table empty | no journal access, or no records in the chosen number of lines |
