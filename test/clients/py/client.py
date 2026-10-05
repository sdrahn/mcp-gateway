"""Compatibility test client: the official MCP Python SDK against the gateway.

e2e/clients_test.go runs it once per scenario and checks the JSON it prints
on stdout; test/clients/ts/client.mjs describes the scenarios and the
environment (MCPGW_*; SSL_CERT_FILE trusts the gateway's certificate).

    python3 client.py <scenario>
"""

import asyncio
import json
import os
import sys
import traceback

import httpx2
import mcp.types as types
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

env = os.environ
home = env["MCPGW_HOME"]


def server():
    if env["MCPGW_TRANSPORT"] == "http":
        http = httpx2.AsyncClient(headers={"Authorization": "Bearer " + env["MCPGW_TOKEN"]}, verify=env["SSL_CERT_FILE"])
        return streamable_http_client(env["MCPGW_URL"], http_client=http)
    return StdioServerParameters(
        command=env["MCPGW_CONNECT"],
        args=["--socket", env["MCPGW_SOCKET"], "--server", env["MCPGW_SERVER"]],
    )


def text(result):
    return "".join(getattr(c, "text", "") for c in result.content)


def names(items):
    return sorted(i.name for i in items)


def ready():
    print(json.dumps({"ready": True}), flush=True)


async def basic():
    async with Client(server(), client_info=types.Implementation(name="compat-py", version="1")) as client:
        out = {
            "server": client.server_info.name if client.server_info else None,
            "protocolVersion": client.session.protocol_version,
            "tools": names((await client.list_tools()).tools),
        }
        out["read"] = text(await client.call_tool("read_file", {"path": os.path.join(home, "hello.txt")}))
        try:
            r = await client.call_tool("delete_file", {"path": os.path.join(home, "hello.txt")})
            out["denied"] = {"isError": bool(r.is_error), "text": text(r)}
        except Exception as e:  # noqa: BLE001 - a JSON-RPC error is a refusal too
            out["denied"] = {"error": str(e)}
        resources = (await client.list_resources()).resources
        out["resources"] = names(resources)
        hello = next((r for r in resources if r.name == "hello.txt"), None)
        out["resource"] = "".join(c.text for c in (await client.read_resource(str(hello.uri))).contents) if hello else None
        out["prompts"] = names((await client.list_prompts()).prompts)
        return out


async def approval():
    logs, progress = [], []

    async def on_log(params):
        logs.append(params.data if isinstance(params.data, str) else json.dumps(params.data))

    async def on_progress(value, total, message):
        progress.append(value)

    # On MCP 2026-07-28 log messages come only to requests that ask for them.
    async with Client(server(), logging_callback=on_log, log_level="info") as client:
        r = await client.call_tool(
            "write_file",
            {"path": os.path.join(home, "approved.txt"), "content": "ok"},
            progress_callback=on_progress,
        )
        return {"isError": bool(r.is_error), "text": text(r), "logs": logs, "progress": len(progress)}


async def elicit():
    asked = []

    async def on_elicit(context, params):
        asked.append(params.message)
        scope = (getattr(params, "requested_schema", None) or {}).get("properties", {}).get("scope", {})
        return types.ElicitResult(action="accept", content={"scope": scope.get("default") or (scope.get("enum") or ["once"])[0]})

    async with Client(server(), elicitation_callback=on_elicit) as client:
        r = await client.call_tool("write_file", {"path": os.path.join(home, "elicited.txt"), "content": "ok"})
        return {"isError": bool(r.is_error), "text": text(r), "asked": asked}


async def listchanged():
    changed = asyncio.Event()

    async def on_message(message):
        if isinstance(message, types.ToolListChangedNotification):
            changed.set()

    async with Client(server(), message_handler=on_message) as client:
        if client.session.protocol_version in MODERN_PROTOCOL_VERSIONS:
            # MCP 2026-07-28: changes come on a stream the client opens.
            async with client.listen(tools_list_changed=True) as sub:
                before = names((await client.list_tools()).tools)
                ready()
                try:
                    await asyncio.wait_for(anext(sub), 20)
                    changed.set()
                except TimeoutError:
                    pass
        else:
            before = names((await client.list_tools()).tools)
            ready()
            try:
                await asyncio.wait_for(changed.wait(), 20)
            except TimeoutError:
                pass
        after = names((await client.list_tools()).tools)
        return {"before": before, "after": after, "notified": changed.is_set()}


async def cancel():
    async with Client(server()) as client:
        error = None
        try:
            await asyncio.wait_for(
                client.call_tool("write_file", {"path": os.path.join(home, "cancelled.txt"), "content": "no"}), 2
            )
        except TimeoutError as e:
            error = repr(e)
        ready()
        await asyncio.sleep(3)
        return {"cancelled": error is not None, "error": error}


async def main(name):
    scenarios = {"basic": basic, "approval": approval, "elicit": elicit, "listchanged": listchanged, "cancel": cancel}
    if name not in scenarios:
        print(f"unknown scenario {name}", file=sys.stderr)
        return 2
    try:
        print(json.dumps(await scenarios[name]()), flush=True)
        return 0
    except BaseException:  # noqa: BLE001 - report anything, including exception groups
        print(json.dumps({"fatal": traceback.format_exc()}), flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1])))
