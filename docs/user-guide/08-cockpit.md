# 8. The Cockpit page

`mcp-gateway-cockpit` adds a page to Cockpit, the web console of
openSUSE and SLES. It is the approval page for the `url` and `oob`
channels, and the place to watch servers and clients, maintain role bindings and
read audit records.

```bash
zypper install mcp-gateway-cockpit
systemctl enable --now cockpit.socket
firewall-cmd --permanent --add-service=cockpit && firewall-cmd --reload
```

Open `https://<host>:9090`, log in with your local account and choose
**MCP Gateway** (at the end of the main list, above *Tools*). Addresses:

| Address | Opens |
|---|---|
| `https://<host>:9090/mcp-gateway` | the page (Approvals tab) |
| `…/mcp-gateway#/approvals/<id>` | one approval, highlighted (the link agents, notifications and mail use) |
| `…/mcp-gateway#/servers`, `#/clients`, `#/tasks`, `#/policy`, `#/audit` | the other tabs |

Each tab shows one thing, so that it fits the window. The Approvals,
Clients and Tasks tabs show a count when there is something to look at:
pending approvals, clients, running tasks.

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

The self-check's counts (`mcp-gateway-admin doctor --no-start`,
chapter 10) are shown above the servers on one line, run when the page
opens and with **Run self-check** next to the heading; the line unfolds
to the warnings and failures with what to do, and is unfolded when a
check failed. It runs as root where you have administrative access;
otherwise the checks that need root are skipped. Servers are not
started; the full check, which starts each server once, is
`mcp-gateway-admin doctor` as root.

The registered MCP servers with their SELinux domain, isolation,
network access and account, and the running instances you may manage:
principal, unit name, sessions, start time. For each instance:

- **Show log** shows the last 50 lines of the instance's journal (the
  server's stderr); for a server under Landlock, a "permission denied"
  in it gets a line naming the rules as the likely cause (chapter 4,
  "Landlock");
- **Stop** ends it (calls in flight fail; the next call starts a new
  instance).

A server each user signs in to (`sign_in`, chapter 4) is marked "each
user signs in", and shows:

- your sign-in, with when you signed in and when the current token
  expires, and **Sign out** (revokes the tokens and stops your
  instances of the server); or that you are not signed in;
- a sign-in waiting for you (your agent cannot open links itself), with
  **Sign in**, which opens the server's sign-in page;
- for administrators (the approver rules, chapter 6), everyone's
  sign-ins with **Revoke**.

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
- **Reload configuration**, next to the heading, runs `systemctl reload mcp-gateway.service`
  (administrative access): the gateway checks the configuration first
  and keeps what it has if a file does not load; the page says so.

## Clients

The tab lists the AI agents and other MCP clients using the gateway
that you may manage (`manage_session`: by default your own; everyone's
for administrators), newest first: the user, the client's name and
version as the client gives them, the MCP version it speaks (marked
"capped by agents.max_version" with the version it asked for when a cap
lowered it, chapter 5, "The version per client"), the endpoint (a server
or all servers), since when and when it was last active. An agent of
2026-07-28 has no session: it is listed for an hour after its last
request, marked "no session", with its open streams and requests.
**End** ends a client as if it had gone: its calls are cancelled at
their servers (a privileged server's call runs to its end), its
session's grants and instances go, and an agent's open stream or
request ends with an error. It keeps nobody out: the client may connect
again, and does (an HTTP client starts a new session). To keep someone
out, change their roles (Policy tab). Ending a client is audited
(`mcp-session-ended`). Without Cockpit, `mcp-gateway-admin clients`
lists and ends clients the same way (chapter 10, "Clients and tasks").

## Tasks

The tab lists the calls agents run as tasks (chapter 5, "Long calls:
tasks") that you may manage (`manage_task`: by default the approver
rules of the server, as for instances: your own; everyone's for
administrators), newest first: the server
and tool, the principal, when it started, and its state (running,
waiting for the agent, completed with whether the agent fetched the
result, failed, cancelled). **Cancel** cancels a running task's call at
the server, as the agent's own cancellation would; the agent then finds
the task cancelled "by <you> (control API)". Finished tasks stay listed
until the agent fetched them and `tasks.retention` passed. Without
Cockpit: `mcp-gateway-admin tasks` (chapter 10, "Clients and tasks").

## Policy

- **Policy status**: whether OPA loads the policy directories or a
  bundle, and the active bundle revisions.
- **Role bindings**: which users and groups hold which roles; add and
  remove bindings. The file in force is named (`data.yaml`, `data.json`,
  or the shipped default). Saving always writes
  `/etc/mcp-gateway/policy/rbac/data.yaml`: a change made here is merged
  into it, and the comments and order of everything else stay as they
  are. Where only `data.json` existed, or the shipped default was in
  force, `data.yaml` is new and in force from then on; the page then
  names `data.json` as ignored (you may remove it; the page does not).
  Role data in JSON is no longer read since 1.7, and the gateway denies
  every request until it is converted (chapter 6): the page shows it,
  says so, and offers **Convert to YAML** (`mcp-gateway-admin policy
  convert`), which writes `data.yaml` with the same data; saving does
  the same.
- **Roles and their permissions** (folded; open it to read them):
  the permissions of each role, read-only.
- **Edit the role data as YAML**: the whole file in force, including
  roles, approver rules and comments; **Save** checks it and writes it to
  `data.yaml` as it is.

The page leaves reading and writing YAML to `mcp-gateway-admin policy
show` and `policy write` (chapter 11), run with administrative access
for saving.

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
