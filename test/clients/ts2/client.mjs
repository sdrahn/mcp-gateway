// Compatibility test client: the TypeScript SDK 2.3 client
// (@modelcontextprotocol/client), which speaks MCP 2026-07-28, used as an
// agent would use it, against the gateway. It implements the scenarios of
// ../ts/client.mjs (the 1.x SDK, which speaks the handshake protocol),
// with the same environment and output.
//
//   node client.mjs <scenario>
//
// The client negotiates the protocol version ("auto": server/discover
// first, the handshake as fallback); against the gateway it agrees on
// 2026-07-28. Approvals are then multi round-trip requests the SDK drives
// itself, log messages come only to requests that ask for them, and list
// changes on a subscriptions/listen stream the client opens.
// MCPGW_CLIENT_NAME, if set, is the name it gives (clientInfo), as in the
// Python and Go clients: one capped by agents.max_version.
import { Client, LOG_LEVEL_META_KEY, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import path from "node:path";

const env = process.env;
const home = env.MCPGW_HOME;
const scenario = process.argv[2];

function transport() {
    if (env.MCPGW_TRANSPORT === "http") {
        return new StreamableHTTPClientTransport(new URL(env.MCPGW_URL), {
            requestInit: { headers: { Authorization: `Bearer ${env.MCPGW_TOKEN}` } },
        });
    }
    return new StdioClientTransport({
        command: env.MCPGW_CONNECT,
        args: ["--socket", env.MCPGW_SOCKET, "--server", env.MCPGW_SERVER],
        stderr: "inherit",
    });
}

async function connect(capabilities = {}) {
    const client = new Client(
        { name: env.MCPGW_CLIENT_NAME || "compat-ts2", version: "1" },
        { capabilities, versionNegotiation: { mode: "auto" } },
    );
    const logs = [];
    client.setNotificationHandler("notifications/message", (n) => {
        logs.push(typeof n.params.data === "string" ? n.params.data : JSON.stringify(n.params.data));
    });
    await client.connect(transport());
    return { client, logs };
}

const text = (r) => (r.content || []).map((c) => c.text || "").join("");
const names = (items) => items.map((i) => i.name).sort();
const ready = () => console.log(JSON.stringify({ ready: true }));

async function basic() {
    const { client } = await connect();
    const out = {
        server: client.getServerVersion()?.name,
        protocolVersion: client.getNegotiatedProtocolVersion(),
        tools: names((await client.listTools()).tools),
    };
    out.read = text(await client.callTool({ name: "read_file", arguments: { path: path.join(home, "hello.txt") } }));
    try {
        const r = await client.callTool({ name: "delete_file", arguments: { path: path.join(home, "hello.txt") } });
        out.denied = { isError: !!r.isError, text: text(r) };
    } catch (e) {
        out.denied = { error: String(e.message || e) };
    }
    const resources = (await client.listResources()).resources;
    out.resources = names(resources);
    const hello = resources.find((r) => r.name === "hello.txt");
    out.resource = hello ? (await client.readResource({ uri: hello.uri })).contents.map((c) => c.text).join("") : null;
    out.prompts = names((await client.listPrompts()).prompts);
    await client.close();
    return out;
}

// A write that needs approval out of band, decided after longer than the
// request timeout: each round trip ends before it.
async function approval() {
    const { client, logs } = await connect();
    let progress = 0;
    const r = await client.callTool(
        {
            name: "write_file",
            arguments: { path: path.join(home, "approved.txt"), content: "ok" },
            _meta: { [LOG_LEVEL_META_KEY]: "info" },
        },
        { onprogress: () => progress++, resetTimeoutOnProgress: true, timeout: Number(env.MCPGW_TIMEOUT_MS) },
    );
    await client.close();
    return { isError: !!r.isError, text: text(r), logs, progress };
}

// Approval through the client's own dialog (form elicitation), accepted.
async function elicit() {
    const { client } = await connect({ elicitation: { form: {} } });
    const asked = [];
    client.setRequestHandler("elicitation/create", (req) => {
        asked.push(req.params.message);
        const scope = req.params.requestedSchema?.properties?.scope;
        return { action: "accept", content: { scope: scope?.default ?? scope?.enum?.[0] ?? "once" } };
    });
    const r = await client.callTool({ name: "write_file", arguments: { path: path.join(home, "elicited.txt"), content: "ok" } });
    await client.close();
    return { isError: !!r.isError, text: text(r), asked };
}

// The tool list changes with the policy: the test changes the role data
// after "ready".
async function listchanged() {
    const { client } = await connect();
    const changed = new Promise((resolve) => {
        client.setNotificationHandler("notifications/tools/list_changed", () => resolve(true));
        setTimeout(() => resolve(false), 20000);
    });
    const sub = await client.listen({ toolsListChanged: true });
    const before = names((await client.listTools()).tools);
    ready();
    const notified = await changed;
    const after = names((await client.listTools({}, { cacheMode: "refresh" })).tools);
    await sub.close();
    await client.close();
    return { before, after, notified };
}

// A call waiting for approval is abandoned by the agent.
async function cancel() {
    const { client } = await connect();
    const ac = new AbortController();
    setTimeout(() => ac.abort("agent gave up"), 2000);
    let error = null;
    try {
        await client.callTool(
            { name: "write_file", arguments: { path: path.join(home, "cancelled.txt"), content: "no" } },
            { signal: ac.signal },
        );
    } catch (e) {
        error = String(e.message || e);
    }
    ready();
    await new Promise((r) => setTimeout(r, 3000));
    await client.close();
    return { cancelled: error !== null, error };
}

const scenarios = { basic, approval, elicit, listchanged, cancel };
if (!scenarios[scenario]) {
    console.error(`unknown scenario ${scenario}`);
    process.exit(2);
}
try {
    console.log(JSON.stringify(await scenarios[scenario]()));
    process.exit(0);
} catch (e) {
    console.log(JSON.stringify({ fatal: String(e.stack || e) }));
    process.exit(1);
}
