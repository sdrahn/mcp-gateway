// Stub of the parts of cockpit.js the pages use, with fixtures. The query
// string selects variants: ?source=server (bundle from a bundle server),
// ?nokey (no signing key on the host).
(function () {
    const query = new URLSearchParams(window.location.search);
    const log = window.__calls = [];
    let rbac = JSON.stringify({
        roles: { admin: { permissions: [{ server: "*", tool: "*" }] },
                 developer: { permissions: [{ server: "fs", tool: "read_*" },
                     { server: "fs", tool: "write_file", require_approval: true, approval_channel: "url", args: { path: "^/home/" } }] } },
        bindings: { users: {}, groups: { wheel: ["admin"], dev: ["developer"] } },
        approvers: { default: ["self", "role:admin"] },
    }, null, 2);
    let instances = [
        { id: "i1", server: "fs", unit: "mcp-fs-i1.service", sub: "alice", uid: 1001, transport: "unix", isolation: "principal",
          started: new Date(Date.now() - 300000).toISOString(), sessions: 1 },
    ];
    const routes = {
        "/v1/whoami": () => ({ name: "carol", uid: 1003 }),
        "/v1/approvals": () => [{ id: "a1", channel: "oob", principal: { sub: "alice", transport: "unix", client: { name: "kit" } },
            action: "tools.call", server: "fs", name: "write_file", args: { path: "/home/alice/x" }, prompt: "Write?",
            scopes: ["once", "session"], expires: new Date(Date.now() + 60000).toISOString() }],
        "/v1/grants": () => [],
        "/v1/servers": () => [{ name: "fs", selinux_type: "mcpsrv_fs_t", isolation: "principal", network: false, run_as: "principal", instances },
                              { name: "git", selinux_type: "", isolation: "principal", network: true, run_as: "principal", instances: [] }],
        "/v1/policy": () => ({ mode: "bundle",
            bundles: query.get("source") === "server" ? { mcp: "r42" } : { "/etc/mcp-gateway/bundle/policy.tar.gz": "r42" } }),
    };
    const listeners = {};
    const location = {
        path: (window.location.hash.replace(/^#\/?/, "") || "").split("/").filter(Boolean),
        go(p) { window.location.hash = "#/" + p.join("/"); },
    };
    window.addEventListener("hashchange", () => {
        location.path = window.location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
        (listeners.locationchanged || []).forEach(f => f());
    });
    const journal = [
        { MESSAGE: JSON.stringify({ time: "2026-09-27T08:00:00Z", level: "INFO", msg: "mcp", audit: true, session: "s1", sub: "alice", action: "tools/call", server: "fs", effect: "deny", name: "delete_file", reason: "denied by policy", decision_id: "d1", args_hmac: "abcdef0123456789abcdef" }) },
        { MESSAGE: JSON.stringify({ time: "2026-09-27T08:01:00Z", level: "INFO", msg: "mcp", audit: true, event: "mcp-approval", ok: true, id: "g-1", principal: "alice", server: "fs", target: "write_file", by: "carol", scope: "once", channel: "oob" }) },
        { MESSAGE: JSON.stringify({ time: "2026-09-27T08:02:00Z", level: "INFO", msg: "listening" }) },
        { MESSAGE: JSON.stringify({ time: "2026-09-27T08:03:00Z", level: "INFO", msg: "mcp", audit: true, sub: "bob", action: "tools/call", server: "fs", effect: "allow", name: "read_file", decision_id: "d2", args: { path: "/x" } }) },
    ].map(e => JSON.stringify(e)).join("\n") + "\n";
    window.cockpit = {
        location,
        addEventListener(ev, f) { (listeners[ev] = listeners[ev] || []).push(f); },
        http() {
            return {
                get(path) { log.push(["GET", path]); return Promise.resolve(JSON.stringify(routes[path]())); },
                post(path, body) { log.push(["POST", path, body]); return Promise.resolve(""); },
                request(opts) {
                    log.push([opts.method, opts.path]);
                    if (opts.method === "DELETE" && opts.path.startsWith("/v1/instances/")) instances = [];
                    return Promise.resolve("");
                },
            };
        },
        spawn(args, opts) {
            log.push(["spawn", args.join(" "), opts.superuser]);
            if (args.includes("mcp-gateway.service")) return Promise.resolve(journal);
            if (args[0] === "test") {
                return query.has("nokey") ? Promise.reject(new Error("exit 1")) : Promise.resolve("");
            }
            if (args[0] === "mcp-policy-bundle") {
                return Promise.resolve("wrote /etc/mcp-gateway/bundle/policy.tar.gz (revision " + args[2] + ")\n");
            }
            return Promise.resolve("2026-09-27T08:00:00 host mcp-fs[1]: started\n");
        },
        file(path, opts) {
            return {
                read() { log.push(["read", path, opts.superuser]); return Promise.resolve(rbac); },
                replace(content) { log.push(["replace", path, content]); rbac = content; return Promise.resolve(); },
            };
        },
    };
})();
