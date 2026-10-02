// Compatibility test client: the official MCP TypeScript SDK, used as an
// agent would use it, against the gateway. e2e/clients_test.go runs it
// once per scenario and checks the JSON it prints on stdout; the other
// clients in test/clients implement the same scenarios.
//
//   node client.mjs <scenario>
//
// Environment: MCPGW_TRANSPORT (stdio or http); for stdio MCPGW_CONNECT,
// MCPGW_SOCKET, MCPGW_SERVER; for http MCPGW_URL, MCPGW_TOKEN (and
// NODE_EXTRA_CA_CERTS for the gateway's certificate); MCPGW_HOME, the
// directory the demo server serves.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
    ElicitRequestSchema,
    LoggingMessageNotificationSchema,
    ToolListChangedNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
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
    const client = new Client({ name: "compat-ts", version: "1" }, { capabilities });
    const logs = [];
    client.setNotificationHandler(LoggingMessageNotificationSchema, (n) => {
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

// A write that needs approval out of band: the test approves it on the
// control socket after MCPGW_APPROVE_AFTER seconds, longer than this
// agent's request timeout. The call survives only because the gateway
// reports progress while it waits (the SDK's default timeout is 60 s,
// the gateway's approval timeout 120 s).
async function approval() {
    const { client, logs } = await connect();
    let progress = 0;
    const r = await client.callTool(
        { name: "write_file", arguments: { path: path.join(home, "approved.txt"), content: "ok" } },
        undefined,
        { onprogress: () => progress++, resetTimeoutOnProgress: true, timeout: Number(env.MCPGW_TIMEOUT_MS) },
    );
    await client.close();
    return { isError: !!r.isError, text: text(r), logs, progress };
}

// Approval through the client's own dialog (form elicitation), accepted.
async function elicit() {
    const { client } = await connect({ elicitation: { form: {} } });
    const asked = [];
    client.setRequestHandler(ElicitRequestSchema, (req) => {
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
    const before = names((await client.listTools()).tools);
    const changed = new Promise((resolve) => {
        client.setNotificationHandler(ToolListChangedNotificationSchema, () => resolve(true));
        setTimeout(() => resolve(false), 20000);
    });
    ready();
    const notified = await changed;
    const after = names((await client.listTools()).tools);
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
            undefined,
            { signal: ac.signal },
        );
    } catch (e) {
        error = String(e.message || e);
    }
    ready();
    // Give the gateway a moment to see the cancellation before the
    // connection goes.
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
