// Stub of the parts of cockpit.js the pages use, with fixtures. The query
// string selects variants: ?source=server (bundle from a bundle server),
// ?nokey (no signing key on the host), ?reload (a failed reload and keys
// that need a restart; systemctl reload fails).
(function () {
    const query = new URLSearchParams(window.location.search);
    const log = window.__calls = [];
    let rbac = JSON.stringify({
        roles: { admin: { permissions: [{ server: "*", tool: "*" }] },
                 developer: { permissions: [{ server: "fs", tool: "read_*" },
                     { server: "fs", tool: "write_file", require_approval: true, approval_channel: "url", args: { path: "^/home/" } }] } },
        bindings: { users: {}, groups: { wheel: ["admin"], dev: ["developer"] } },
        approvers: { default: ["self", "role:admin"] },
        scopes: { "mcp:read": { roles: ["developer"] }, "mcp:admin": { unlimited: true },
                  "mcp:git": { permissions: [{ server: "git", tool: "*" }] } },
    }, null, 2);
    let instances = [
        { id: "i1", server: "fs", unit: "mcp-fs-i1.service", sub: "alice", uid: 1001, transport: "unix", isolation: "principal",
          started: new Date(Date.now() - 300000).toISOString(), sessions: 1 },
        { id: "i0", server: "fs", unit: "mcp-fs-i0.service", sub: "bob", uid: 1002, transport: "unix", isolation: "principal",
          started: new Date(Date.now() - 900000).toISOString(), sessions: 1, definition: "previous" },
    ];
    let signIns = [
        { server: "tickets", principal: { sub: "carol", uid: 1003, transport: "unix" }, since: new Date(Date.now() - 3600000).toISOString(),
          expiry: new Date(Date.now() + 1800000).toISOString(), scope: "mcp.read", refreshable: true },
        { server: "tickets", principal: { sub: "alice", uid: 1001, transport: "unix" }, since: new Date(Date.now() - 7200000).toISOString(),
          refreshable: false },
    ];
    const routes = {
        "/v1/whoami": () => ({ name: "carol", uid: 1003 }),
        "/v1/status": () => query.has("reload")
            ? { restart_pending: false, config_error: "/etc/mcp-gateway/gateway.yaml: yaml: line 3: did not find expected key",
                restart_needed: ["socket_group"] }
            : { restart_pending: query.has("restart") },
        "/v1/approvals": () => [{ id: "a1", channel: "oob", principal: { sub: "alice", transport: "unix", client: { name: "kit" } },
            action: "tools.call", server: "fs", name: "write_file", args: { path: "/home/alice/x" }, prompt: "Write?",
            scopes: ["once", "session"], expires: new Date(Date.now() + 60000).toISOString(), waiting: true },
            { id: "a2", channel: "oob", principal: { sub: "alice", transport: "unix" }, action: "tools.call", server: "fs",
              name: "delete_file", args: {}, scopes: ["once"], expires: new Date(Date.now() + 60000).toISOString(), waiting: false }],
        "/v1/grants": () => [],
        "/v1/servers": () => [{ name: "fs", selinux_type: "mcpsrv_fs_t", isolation: "principal", network: false, run_as: "principal", instances },
                              { name: "git", selinux_type: "", isolation: "principal", network: true, run_as: "principal", instances: [] },
                              { name: "zypp", selinux_type: "mcpsrv_zypp_t", isolation: "principal", network: true, run_as: "root", privileged: true,
                                instances: [{ id: "i2", server: "zypp", unit: "mcp-zypp-i2.service", sub: "alice", uid: 1001, transport: "unix",
                                              isolation: "principal", started: new Date().toISOString(), sessions: 0, privileged: true, busy: true }] },
                              { name: "tickets", selinux_type: "mcpsrv_http_t", isolation: "principal", network: true, run_as: "dynamic",
                                sign_in: true, instances: [] },
                              { name: "web", removed: true, instances: [{ id: "i3", server: "web", unit: "mcp-web-i3.service", sub: "alice", uid: 1001,
                                  transport: "unix", isolation: "principal", started: new Date().toISOString(), sessions: 0, busy: true,
                                  definition: "removed" }] }],
        "/v1/sign-ins": () => ({ sign_ins: signIns,
            pending: [{ server: "tickets", url: "https://as.example.com/authorize?state=s1", expires: new Date(Date.now() + 600000).toISOString() }] }),
        "/v1/policy": () => ({ mode: "bundle",
            bundles: query.get("source") === "server" ? { mcp: "r42" } : { "/etc/mcp-gateway/bundle/policy.tar.gz": "r42" },
            shipped_roles: { "systemd-reader": { setup: "systemd", description: "read the system state",
                permissions: [{ server: "systemd", tool: "list_units" }] } } }),
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
                post(path, body) {
                    log.push(["POST", path, body]);
                    if (path === "/v1/policy/whatif") {
                        // Binding alice changes her access; anything else changes nothing.
                        const changes = JSON.parse(body).bindings.users.alice
                            ? [{ principal: "user:alice", server: "fs", kind: "tool", name: "write_file", before: "deny", after: "ask" }]
                            : [];
                        return Promise.resolve(JSON.stringify({ changes, principals: 3, resources: 12, unchecked: { db: "per-user discovery" } }));
                    }
                    return Promise.resolve("");
                },
                request(opts) {
                    log.push([opts.method, opts.path]);
                    if (opts.method === "DELETE" && opts.path.startsWith("/v1/sign-ins/")) {
                        const sub = new URLSearchParams(opts.path.split("?")[1] || "").get("principal") || "carol";
                        signIns = signIns.filter(e => e.principal.sub !== sub);
                        // alice's authorization server revokes, carol's does not.
                        return Promise.resolve(JSON.stringify({ signed_out: 1, revoked: sub === "alice" ? 1 : 0 }));
                    }
                    if (opts.method === "DELETE" && opts.path.startsWith("/v1/instances/")) {
                        instances = instances.filter(i => opts.path !== "/v1/instances/" + i.id);
                    }
                    return Promise.resolve("");
                },
            };
        },
        spawn(args, opts) {
            log.push(["spawn", args.join(" "), opts.superuser]);
            if (args[0] === "systemctl") {
                return query.has("reload")
                    ? Promise.reject(new Error("Job for mcp-gateway.service failed because the control process exited with error code."))
                    : Promise.resolve("");
            }
            if (args[0] === "mcp-gateway-admin") {
                return Promise.resolve(JSON.stringify([
                    { check: "configuration", id: "configuration", status: "ok", summary: "3 servers" },
                    { check: "principals", id: "principals", status: "warn",
                      summary: "1 of 4 members of mcp-users hold no role: they may connect but see no server",
                      details: ["carol", "bind them to a role (Cockpit's Roles tab, or bindings in data.json), or remove them from mcp-users"] },
                    { check: "SELinux", id: "selinux-denials", status: "skip", summary: "reading the audit log needs root" },
                ]));
            }
            if (args[0] === "mcp-gateway") {
                // --check-policy-data: a misspelt field is the one problem it knows.
                const result = data => data.includes("require_aproval")
                    ? Promise.reject(new Error("/roles/developer/permissions/0: additional properties 'require_aproval' not allowed\n" +
                                               "level=ERROR msg=\"role data invalid\""))
                    : Promise.resolve("");
                return { input: result };
            }
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
