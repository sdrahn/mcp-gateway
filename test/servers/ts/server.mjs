// A test MCP server built with the official TypeScript SDK (v2), for
// e2e/servers_test.go: over stdio, or Streamable HTTP (path /mcp) with
// --http host:port. Both serve 2026-07-28 only (legacy: 'reject').
import { createServer } from 'node:http';
import { McpServer, acceptedContent, createMcpHandler, inputRequired, inputResponse } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import * as z from 'zod';

const text = (s) => ({ content: [{ type: 'text', text: s }] });

function newServer() {
    const server = new McpServer({ name: 'ts-sdk-test', version: '1' });
    server.registerTool('echo', { description: 'echo the text', inputSchema: z.object({ text: z.string() }) },
        async ({ text: t }) => text('ts echo: ' + t));
    server.registerTool('protocol', { description: 'the protocol version of this request' },
        async (ctx) => text(ctx.mcpReq.envelope?.['io.modelcontextprotocol/protocolVersion'] ?? ''));
    // Input from the client (multi round-trip): a form asking for a name.
    const nameSchema = z.object({ name: z.string() });
    server.registerTool('ask_name', { description: 'ask the user for their name' }, async (ctx) => {
        const answer = inputResponse(ctx.mcpReq.inputResponses, 'name');
        if (answer.kind === 'missing') {
            return inputRequired({
                inputRequests: { name: inputRequired.elicit({ message: 'Your name?', requestedSchema: nameSchema }) },
                requestState: 'asked'
            });
        }
        const accepted = acceptedContent(ctx.mcpReq.inputResponses, 'name', nameSchema);
        if (!accepted) {
            return text('ts: no name (' + (answer.action ?? answer.kind) + ')');
        }
        return text('ts: hello ' + accepted.name);
    });
    // A parameter mirrored into a header (Mcp-Param-Region over HTTP).
    server.registerTool('region', {
        description: 'query a region',
        inputSchema: z.object({ region: z.string().meta({ 'x-mcp-header': 'Region' }), query: z.string().optional() })
    }, async ({ region, query }) => text(`ts region ${region}: ${query ?? ''}`));
    return server;
}

const i = process.argv.indexOf('--http');
if (i < 0) {
    serveStdio(() => newServer(), { legacy: 'reject' });
} else {
    const [host, port] = [process.argv[i + 1].slice(0, process.argv[i + 1].lastIndexOf(':')), Number(process.argv[i + 1].split(':').pop())];
    const handler = createMcpHandler(() => newServer(), { legacy: 'reject' });
    createServer(async (req, res) => {
        if (new URL(req.url, 'http://x').pathname !== '/mcp') {
            res.writeHead(404).end();
            return;
        }
        // The SDK's handler is web-standard (Request → Response).
        const chunks = [];
        for await (const c of req) chunks.push(c);
        const abort = new AbortController();
        res.on('close', () => abort.abort());
        const request = new Request(`http://${req.headers.host}${req.url}`, {
            method: req.method,
            headers: Object.entries(req.headers).flatMap(([k, v]) => (Array.isArray(v) ? v.map((x) => [k, x]) : [[k, v]])),
            body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks),
            signal: abort.signal
        });
        const response = await handler.fetch(request);
        res.writeHead(response.status, Object.fromEntries(response.headers));
        if (response.body) {
            for await (const c of response.body) res.write(c);
        }
        res.end();
    }).listen(port, host);
}
