# Client compatibility tests

Programs that drive MCP client libraries the way agents use them, against
the gateway. `e2e/clients_test.go` (`TestClients`) starts OPA and the
gateway with the demo file server, runs each program once per scenario,
over the local socket (through `mcp-connect`) and over HTTPS, and checks
the JSON the program prints.

| Directory | Library | Stands for |
|---|---|---|
| `ts` | `@modelcontextprotocol/sdk` (official TypeScript SDK) | Claude Code and most Node-based agents and IDEs |
| `py` | `mcp` (official Python SDK) | Python agents and frameworks |
| `go` | `github.com/mark3labs/mcp-go`, set up as Kit sets it up | Kit and other Go agents |

The scenarios (described in `ts/client.mjs`): discovery and calls
filtered by policy, an approval out of band that takes longer than the
client's request timeout, an approval in the client's own dialog (form
elicitation), `list_changed` after a policy change, and cancelling a call
that waits for approval.

Versions are pinned (`ts/package-lock.json`, `py/requirements.txt`,
`go/go.mod`); raise them to test newer releases.

## Running

```bash
(cd test/clients/ts && npm ci)
python3 -m venv /tmp/mcpvenv && /tmp/mcpvenv/bin/pip install -r test/clients/py/requirements.txt
MCPGW_CLIENTS=ts,py,go MCPGW_PYTHON=/tmp/mcpvenv/bin/python \
  go test -count=1 -v -run TestClients ./e2e/
```

`MCPGW_CLIENTS` names the clients to run; without it the test is
skipped. `opa` must be on `PATH` (or set `$OPA`). The Go client is a
module of its own, so the gateway does not depend on mcp-go.
