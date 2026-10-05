# SDK test servers (MCP 2026-07-28)

Servers built with the official MCP SDKs, in the protocol revision
2026-07-28, for `e2e/servers_test.go` (`TestModernServers`). The test
starts OPA and the gateway, defines each server twice, run over stdio
(`<sdk>-stdio`) and reached over Streamable HTTP through the connector
(`<sdk>-http`, the server started by the test), and drives them with a
legacy client (MCP 2025-06-18) through `mcp-connect`.

| Directory | Library |
|---|---|
| `go` | `github.com/modelcontextprotocol/go-sdk` |
| `py` | `mcp` (Python SDK) |
| `ts` | `@modelcontextprotocol/server` (TypeScript SDK v2) |

Each offers the same tools:

- `echo`: a plain call;
- `protocol`: the protocol version of the request, from its `_meta`
  (the test expects `2026-07-28`, which proves the gateway spoke the
  modern revision; a legacy request has none);
- `ask_name`: asks for a name with a form, as an `InputRequiredResult`
  (multi round-trip); the gateway asks the client and calls again;
- `region`: its `region` parameter is marked `x-mcp-header`, so over
  HTTP it is mirrored into `Mcp-Param-Region` (Base64 for values that
  are not plain ASCII), which the server checks against the body.

The Go and TypeScript servers refuse legacy requests; the Python SDK
serves both revisions, so there the `protocol` tool is the proof.

Versions are pinned (`go/go.mod`, `py/requirements.txt`,
`ts/package-lock.json`); raise them to test newer releases.

## Running

```bash
(cd test/servers/ts && npm ci)
python3 -m venv /tmp/mcpsrv && /tmp/mcpsrv/bin/pip install -r test/servers/py/requirements.txt
MCPGW_SERVERS=go,py,ts MCPGW_PYTHON=/tmp/mcpsrv/bin/python \
  go test -count=1 -v -run TestModernServers ./e2e/
```

`MCPGW_SERVERS` names the servers to run; without it the test is skipped.
`opa` must be on `PATH` (or set `$OPA`). The Go server is a module of its
own, so the gateway does not depend on the SDK.
