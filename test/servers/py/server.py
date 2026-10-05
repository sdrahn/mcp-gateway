"""A test MCP server built with the official Python SDK, for
e2e/servers_test.go: over stdio, or Streamable HTTP (path /mcp) with
--http host:port."""

import argparse
from typing import Annotated

from pydantic import BaseModel, Field

from mcp.server.mcpserver import AcceptedElicitation, Context, Elicit, ElicitationResult, MCPServer, Resolve

server = MCPServer("py-sdk-test", version="1")


@server.tool()
def echo(text: str) -> str:
    """Echo the text."""
    return "py echo: " + text


@server.tool()
def protocol(ctx: Context) -> str:
    """The protocol version of this request."""
    return ctx.protocol_version or ""


class Name(BaseModel):
    name: str


def ask() -> Elicit[Name]:
    return Elicit("Your name?", Name)


@server.tool()
def ask_name(answer: Annotated[ElicitationResult[Name], Resolve(ask)]) -> str:
    """Ask the user for their name (a multi round-trip request)."""
    if isinstance(answer, AcceptedElicitation):
        return "py: hello " + answer.data.name
    return "py: no name (" + answer.action + ")"


@server.tool()
def region(region: Annotated[str, Field(json_schema_extra={"x-mcp-header": "Region"})], query: str = "") -> str:
    """Query a region (mirrored into Mcp-Param-Region)."""
    return f"py region {region}: {query}"


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--http", help="serve Streamable HTTP at host:port instead of stdio")
    args = p.parse_args()
    if args.http:
        host, port = args.http.rsplit(":", 1)
        server.run("streamable-http", host=host, port=int(port), streamable_http_path="/mcp", stateless_http=True)
    else:
        server.run()
