# Client compatibility tests

Programs that drive MCP client libraries the way agents use them, against
the gateway. `e2e/clients_test.go` (`TestClients`) starts OPA and the
gateway with the demo file server, runs each program once per scenario,
over the local socket (through `mcp-connect`) and over HTTPS, and checks
the JSON the program prints.

| Directory | Library | Stands for |
|---|---|---|
| `ts` | `@modelcontextprotocol/sdk` 1.x (official TypeScript SDK) | Claude Code and most Node-based agents and IDEs; speaks the handshake protocol (MCP 2025-11-25) |
| `ts2` | `@modelcontextprotocol/client` 2.3 (official TypeScript SDK 2) | Node-based agents on MCP 2026-07-28 |
| `py` | `mcp` 2.3 (official Python SDK) | Python agents and frameworks |
| `go` | `github.com/mark3labs/mcp-go` 1.1, set up as Kit sets it up | Kit and other Go agents |

`ts2`, `py` and `go` agree on MCP 2026-07-28 with the gateway (the test
checks it): requests without a session, approvals as multi round-trip
requests the SDK drives itself, log messages only for requests that ask
for them (`log_level`, `SetLevel`, the `logLevel` in `_meta`), list
changes on a `subscriptions/listen` stream the client opens (`listen`,
`ListenAsync`). `ts` keeps the handshake and its session.

The scenarios (described in `ts/client.mjs`): discovery and calls
filtered by policy, an approval out of band that takes longer than the
client's request timeout, an approval in the client's own dialog (form
elicitation), `list_changed` after a policy change, and cancelling a call
that waits for approval.

Versions are pinned (`ts/package-lock.json`, `ts2/package-lock.json`,
`py/requirements.txt`, `go/go.mod`); raise them to test newer releases.

## Running

```bash
(cd test/clients/ts && npm ci) && (cd test/clients/ts2 && npm ci)
python3 -m venv /tmp/mcpvenv && /tmp/mcpvenv/bin/pip install -r test/clients/py/requirements.txt
MCPGW_CLIENTS=ts,ts2,py,go MCPGW_PYTHON=/tmp/mcpvenv/bin/python \
  go test -count=1 -v -run TestClients ./e2e/
```

`MCPGW_CLIENTS` names the clients to run; without it the test is
skipped. `opa` must be on `PATH` (or set `$OPA`). The Go client is a
module of its own, so the gateway does not depend on mcp-go.
