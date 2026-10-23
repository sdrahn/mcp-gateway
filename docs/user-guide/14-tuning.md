# 14. Tuning

The shipped settings suit a typical server with a handful of users. This
chapter is about the others: a small host (a Raspberry Pi), many users,
remote agents over slow links, servers that start slowly. It says what
to measure first, which settings matter for what, and gives starting
points for three kinds of host. Every setting named here is in chapter
3; most apply without a restart (chapter 3, "Changing the configuration
while the gateway runs"), and the ones that do not are marked.

Change settings with `mcp-gateway-admin config set` (chapter 3,
"Settings from the command line"): it checks the whole configuration
before it writes anything, says whether the key is in force or takes
effect at the next start, and `config unset` goes back to the default.

## Measure first

Most trouble shows in the gateway's log or its metrics (root reads
them, chapter 10) before any setting needs to change:

```bash
journalctl -u mcp-gateway.service -b | grep -E 'did not answer initialize|filtering failed|listing failed|limit reached|warm-up'
sudo curl -s --unix-socket /run/mcp-gateway/control.sock http://localhost/v1/metrics |
  grep -E 'opa_query_duration|instance_(starts|failures)|limit_refusals|sessions|instances '
```

| You see | It means | Look at |
|---|---|---|
| "*name* did not answer initialize within 30s (supervisor.start_timeout)" | a server starts more slowly than allowed | [Starting servers](#starting-servers) |
| "filtering failed; hiding everything", `mcp_gateway_policy_failures_total{reason="error"}` rising | OPA did not decide within `policy.timeout` | [Policy decisions](#policy-decisions) |
| `mcp_gateway_opa_query_duration_seconds` near `policy.timeout` | decisions are about to time out | [Policy decisions](#policy-decisions) |
| "listing failed; skipping server", an agent's first `tools/list` timing out | servers start while the agent waits | [Starting servers](#starting-servers) |
| "instance limit reached", "session limit reached", `mcp_gateway_limit_refusals_total` rising | a limit is hit | [Many users](#many-users) |
| `mcp_gateway_instance_starts_total` rising steadily with few users | instances stop when idle and start again | `supervisor.idle_timeout`, below |
| calls that wait for approval fail after about a minute | the agent gives up before the decision | [Approvals and agents' timeouts](#approvals-and-agents-timeouts) |

`mcp-gateway-admin doctor` (chapter 10) starts every server once and
says whether it starts at all. `systemd-cgtop` shows what the servers'
instances (`mcp-*` units) use.

## Starting servers

Every server runs as instances the gateway starts on demand: one per
principal (`isolation: principal`) or per session (`isolation:
session`), and one shared discovery instance per server for the tool,
prompt and resource template lists (chapter 4, "Discovery instances").
Starting is the expensive part: an interpreted server (Python, Node)
can take seconds on a fast host and tens of seconds on a small one.

| Setting | Default | What it does | When to change it |
|---|---|---|---|
| `supervisor.start_timeout` | `30s` | how long a new instance may take to answer `initialize` | raise it when servers fail with "did not answer initialize" |
| `supervisor.idle_timeout` | `15m` | an instance stops this long after its last session ended | raise it when the same instances start again and again; lower it to free memory on a busy host |
| `supervisor.warm_up` | `false` | start the discovery instances when the gateway starts (and those of servers a reload adds or changes), and fill their lists (at the next start) | turn it on when the first listing after a start is slow |

The aggregated endpoint asks its servers at the same time, as many at
once as the host has CPUs, so a listing that starts instances waits for
the slowest server, not for all of them. Beyond the settings:

- **Fewer servers, fewer starts.** Each server on the aggregated
  endpoint is one more start on the first listing. Remove the setup
  packages you do not use (chapter 13), or give an agent one server's
  endpoint (`mcp-connect --server fs`, `https://…/mcp/fs`).
- **Installed, not fetched.** A definition whose `command` runs
  `npx -y …` or `uvx …` resolves, and may download, packages at every
  start. An installed package (an RPM, or a fixed path) starts much
  faster and does not need the network.
- **Per principal, not per session.** `isolation: session` starts an
  instance for every session; keep it for servers that must not share
  state between an agent's sessions.
- **Discovery shared, not per user.** `discovery: instance` lists from
  the user's own instance, so listing starts one for every user; keep it
  for servers whose tools depend on the user (and `sign_in` servers,
  where it is the default).

## Policy decisions

Every request asks OPA (`mcp-opa.service`) for a decision; a listing
asks for the whole list at once. A decision not given within
`policy.timeout` (250 ms) is a denial: the gateway fails closed.

| Setting | Default | What it does | When to change it |
|---|---|---|---|
| `policy.timeout` | `250ms` | how long the gateway waits for a decision | raise it (`1s`) on a small host, or when `mcp_gateway_opa_query_duration_seconds` comes close |
| `policy.watch_interval` | `10s` | how often the gateway checks whether OPA loaded a changed policy (local files are also watched) | raise it with a bundle server, to poll it less |

What makes decisions slow:

- **Large role data**: thousands of bindings or permissions. Bind roles
  to groups rather than to each user (chapter 6).
- **Custom Rego** (chapter 12) that iterates over large data for every
  request. `opa eval --profile` shows where a decision's time goes, with
  a real input from OPA's decision log (chapter 12, "Single decisions").
- **A slow journal**: OPA logs every decision to the journal (arguments
  masked, chapter 9). On an SD card the writes add up; keep the journal
  on an SSD, or size it with `SystemMaxUse=` in `journald.conf`. Keep
  the decision log itself: it is part of the audit trail.

## Many users

Each principal has its own instances (`isolation: principal`), so the
instances running are about the users active within
`supervisor.idle_timeout` times the servers they use. Each instance may
use up to 512 MiB and 64 processes and run 8 hours (fixed, chapter 11);
most use far less (`systemd-cgtop`).

| Setting | Default | What it does |
|---|---|---|
| `limits.instances` | `0` (none) | running instances of all principals together: size it to the host's memory |
| `limits.instances_per_principal` | `32` | running instances of one principal; at the limit, its longest-idle unused instance is stopped first |
| `limits.sessions_per_principal` | `64` | open sessions of one principal; at the limit, its longest-idle HTTP session is ended first |
| `limits.requests_per_principal`, `limits.streams_per_principal` | `64`, `16` | requests in flight and subscription streams of agents of MCP 2026-07-28 |
| `limits.tasks_per_principal`, `tasks.retention`, `tasks.max_result_bytes` | `32`, `1h`, 4 MiB | tasks one principal has, how long a finished task is kept, its largest result |

Set `limits.instances` on any host with more users than it has memory
for their instances: without it, a burst of users starts instances
until the host swaps. At the limit the longest-idle unused instance is
stopped to make room; only when none is idle is a request refused, and
`mcp_gateway_limit_refusals_total{limit="instances"}` counts it. A
shorter `supervisor.idle_timeout` frees memory sooner, at the price of
more starts.

## Remote clients

| Setting | Default | What it does | When to change it |
|---|---|---|---|
| `http.session_idle_timeout` | `30m` | an HTTP session without traffic ends | lower it with many remote users whose agents leave sessions open; raise it for agents that pause long between calls |
| `http.list_ttl` | `1m` | how long agents of MCP 2026-07-28 may use a list before asking again | raise it (`5m`) to cut listing traffic when the servers and roles rarely change |

A response ends when the token of its request expires; the call goes on
and its result is withheld (chapter 5, "Sessions and resumability").
For calls that may outlast a token, agents should ask for a task
(chapter 5, "Long calls: tasks"), or the identity provider should issue
longer-lived tokens.

## Approvals and agents' timeouts

An agent built on the TypeScript SDK gives up on a request after 60
seconds unless progress extends the timeout (chapter 5, "Client
compatibility"). A call waiting for approval must therefore either
report progress or end before the agent gives up.

| Setting | Default | What it does | When to change it |
|---|---|---|---|
| `approval_timeout` | `120s` | how long a call waits for a human decision | keep it below the agents' request timeout if they do not extend it on progress |
| `approvals.progress_interval` | `15s` | how often a waiting call reports progress to an agent that asked for it | lower it when a proxy between agent and gateway cuts idle streams |
| `approvals.retry_wait` | `25s` | how long a round of an agent of MCP 2026-07-28 waits before it is told to retry | keep it below the agents' request timeout |

## Starting points

These are starting points, not limits: measure (above), then adjust.

**A small host** (a Raspberry Pi 4 with 4 to 8 GB, one or a few users):

```bash
mcp-gateway-admin config set supervisor.start_timeout 2m
mcp-gateway-admin config set supervisor.warm_up true
mcp-gateway-admin config set supervisor.idle_timeout 8h
mcp-gateway-admin config set policy.timeout 1s
mcp-gateway-admin config set limits.instances 16
systemctl restart mcp-gateway.service   # warm_up takes effect at the start
```

Keep the servers installed (no `npx`/`uvx`), and the journal off the SD
card if you can.

**A typical server** (a few to a few dozen users): the shipped settings.
Set `limits.instances` to what the memory holds (about 2 per GB as a
first guess), and watch `mcp_gateway_opa_query_duration_seconds` and
`mcp_gateway_limit_refusals_total`.

**Many users** (hundreds, mostly remote):

```bash
mcp-gateway-admin config set limits.instances 200                 # size it to the memory
mcp-gateway-admin config set limits.instances_per_principal 8
mcp-gateway-admin config set supervisor.idle_timeout 5m
mcp-gateway-admin config set http.session_idle_timeout 10m
mcp-gateway-admin config set http.list_ttl 5m
```

Bind roles to groups (chapter 6), keep custom Rego lean (profile it,
above), and keep `discovery: shared` (the default) for every server
whose tools do not depend on the user.
