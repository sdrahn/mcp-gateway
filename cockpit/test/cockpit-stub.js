// Stub of the parts of cockpit.js the pages use, with fixtures. The query
// string selects variants: ?source=server (bundle from a bundle server),
// ?nokey (no signing key on the host), ?reload (a failed reload and keys
// that need a restart; systemctl reload fails), ?default (no role data in
// /etc: the shipped default in force), ?yaml (data.yaml in force).
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
    let tasks = [
        { id: "t1", server: "zypp", tool: "confirm_install", sub: "alice", uid: 1001, transport: "unix", status: "working",
          created: new Date(Date.now() - 1200000).toISOString(), updated: new Date().toISOString(), delivered: false },
        { id: "t2", server: "fs", tool: "read_file", sub: "carol", uid: 1003, transport: "http", iss: "https://idp.example.com",
          status: "completed", created: new Date(Date.now() - 600000).toISOString(), updated: new Date().toISOString(),
          ended: new Date(Date.now() - 540000).toISOString(), delivered: false },
    ];
    let sessions = [
        { id: "s1", kind: "session", sub: "alice", uid: 1001, transport: "unix", endpoint: "all", servers: ["fs", "git"],
          client: { name: "kit", version: "0.121.1" }, requested: "2025-11-25", protocol: "2025-06-18", capped: "2025-06-18",
          started: new Date(Date.now() - 1800000).toISOString(), last_active: new Date(Date.now() - 60000).toISOString(), instances: ["i1"] },
        { id: "agent-1", kind: "agent", sub: "carol", uid: 1003, transport: "http", iss: "https://idp.example.com", endpoint: "fs",
          servers: ["fs"], client: { name: "claude-code", version: "2.1" }, requested: "2026-07-28", protocol: "2026-07-28",
          started: new Date(Date.now() - 600000).toISOString(), last_active: new Date().toISOString(), streams: 1 },
        { id: "agent-2", kind: "agent", sub: "carol", uid: 1003, transport: "unix", endpoint: "fs", servers: ["fs"],
          client: { name: "old-agent" }, requested: "2026-07-28", protocol: "2026-07-28",
          started: new Date(Date.now() - 3000000).toISOString(), last_active: new Date(Date.now() - 2400000).toISOString() },
    ];
    let signIns = [
        { server: "tickets", principal: { sub: "carol", uid: 1003, transport: "unix" }, since: new Date(Date.now() - 3600000).toISOString(),
          expiry: new Date(Date.now() + 1800000).toISOString(), scope: "mcp.read", refreshable: true },
        { server: "tickets", principal: { sub: "alice", uid: 1001, transport: "unix" }, since: new Date(Date.now() - 7200000).toISOString(),
          refreshable: false },
    ];
    const routes = {
        "/v1/whoami": () => ({ name: "carol", uid: 1003 }),
        "/v1/tasks": () => tasks,
        "/v1/sessions": () => sessions,
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
        "/v1/servers": () => [{ name: "fs", selinux_type: "mcpsrv_fs_t", isolation: "principal", network: false, run_as: "principal",
                                landlock: true, instances },
                              { name: "git", selinux_type: "", isolation: "principal", network: true, run_as: "principal", instances: [] },
                              { name: "zypp", selinux_type: "mcpsrv_zypp_t", isolation: "principal", network: true, run_as: "root", privileged: true,
                                instances: [{ id: "i2", server: "zypp", unit: "mcp-zypp-i2.service", sub: "alice", uid: 1001, transport: "unix",
                                              isolation: "principal", started: new Date().toISOString(), sessions: 0, privileged: true, busy: true }] },
                              { name: "tickets", selinux_type: "mcpsrv_http_t", isolation: "principal", network: true, run_as: "dynamic",
                                sign_in: true, instances: [] },
                              { name: "tukit", selinux_type: "mcpsrv_tukit_t", isolation: "principal", network: false, run_as: "root",
                                capabilities: ["CAP_SYS_ADMIN"], instances: [] },
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
                    // a2 is the user's own request that only "self" allows: the
                    // gateway asks for the password (roadmap step 40).
                    if (path === "/v1/approvals/a2" && body.includes('"approve"')) {
                        return Promise.reject({ status: 403, message: JSON.stringify({ code: "password_required",
                            error: "approving your own request needs your password" }) });
                    }
                    const cancel = path.match(/^\/v1\/tasks\/([^/]+)\/cancel$/);
                    if (cancel) {
                        tasks = tasks.map(t => t.id === cancel[1]
                            ? { ...t, status: "cancelled", status_message: "cancelled by carol (control API)", ended: new Date().toISOString() }
                            : t);
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
                    if (opts.method === "DELETE" && opts.path.startsWith("/v1/sessions/")) {
                        sessions = sessions.filter(s => opts.path !== "/v1/sessions/" + s.id);
                    }
                    if (opts.method === "DELETE" && opts.path.startsWith("/v1/instances/")) {
                        instances = instances.filter(i => opts.path !== "/v1/instances/" + i.id);
                    }
                    return Promise.resolve("");
                },
            };
        },
        spawn(args, opts) {
            log.push(["spawn", args.join(" "), opts.superuser, opts.pty]);
            if (args[0] === "mcp-gateway-admin" && args[1] === "approvals") return ttyApprove();
            if (args[0] === "systemctl") {
                return query.has("reload")
                    ? Promise.reject(new Error("Job for mcp-gateway.service failed because the control process exited with error code."))
                    : Promise.resolve("");
            }
            if (args[0] === "mcp-gateway-admin" && args[1] === "policy") return policy(args.slice(2));
            if (args[0] === "mcp-gateway-admin") {
                return Promise.resolve(JSON.stringify([
                    { check: "configuration", id: "configuration", status: "ok", summary: "3 servers" },
                    { check: "principals", id: "principals", status: "warn",
                      summary: "1 of 4 members of mcp-users hold no role: they may connect but see no server",
                      details: ["carol", "bind them to a role (Cockpit's Roles tab, or bindings in data.json), or remove them from mcp-users"] },
                    { check: "SELinux", id: "selinux-denials", status: "skip", summary: "reading the audit log needs root" },
                ]));
            }
            if (args.includes("mcp-gateway.service")) return Promise.resolve(journal);
            if (args[0] === "test") {
                return query.has("nokey") ? Promise.reject(new Error("exit 1")) : Promise.resolve("");
            }
            if (args[0] === "mcp-policy-bundle") {
                return Promise.resolve("wrote /etc/mcp-gateway/bundle/policy.tar.gz (revision " + args[2] + ")\n");
            }
            return Promise.resolve("2026-09-27T08:00:00 host mcp-fs[1]: started\n" +
                                   "2026-09-27T08:00:01 host mcp-fs[1]: /srv/x: permission denied\n");
        },
        // mcp-gateway-admin policy show / write (see policy below).
        file(path, opts) {
            const etc = "/etc/mcp-gateway/policy/rbac/";
            return {
                read() {
                    log.push(["read", path, (opts || {}).superuser]);
                    if (path === etc + "data.yaml") return Promise.resolve(query.has("yaml") ? "roles: {}\n" : null);
                    if (path === etc + "data.json" && query.has("default")) return Promise.resolve(null);
                    return Promise.resolve(rbac); // data.json, or as rendered (/run/mcp-opa/rbac/data.json)
                },
                replace(content) { log.push(["replace", path, content]); rbac = content; return Promise.resolve(); },
            };
        },
    };
    // The role data in force: data.json (stub default), the shipped default
    // (?default) or data.yaml (?yaml), as "mcp-gateway-admin policy show"
    // gives it; "policy write" refuses a misspelt field (the one schema
    // problem it knows) and YAML it cannot read (comment lines aside, the
    // stub reads JSON, which is YAML too).
    const etc = "/etc/mcp-gateway/policy/rbac/";
    let origin = query.has("default") ? "default" : query.has("yaml") ? "yaml" : "json";
    let yamlText = origin === "yaml" ? "# who may do what: ticket 7\n" + rbac + "\n" : null;
    let ignored = [];
    // ttyApprove is "mcp-gateway-admin approvals approve" in a pty: polkit's
    // text agent prompts, "secret" is the password, another one prompts
    // again (the page then closes the process).
    function ttyApprove() {
        let streamer = () => {};
        let settle;
        const done = new Promise((resolve, reject) => { settle = { resolve, reject }; });
        const p = {
            stream(f) { streamer = f; setTimeout(() => f("==== AUTHENTICATING FOR io.github.sdrahn.mcp-gateway.decide-own ====\nPassword: "), 10); return p; },
            input(x) {
                log.push(["pty-input", x === "secret\n" ? "right" : "wrong"]);
                if (x === "secret\n") setTimeout(() => { streamer("\n==== AUTHENTICATION COMPLETE ====\napproved a2\n"); settle.resolve(""); }, 10);
                else setTimeout(() => streamer("\nSorry, try again.\nPassword: "), 10);
                return p;
            },
            close(problem) { log.push(["pty-close", problem]); settle.reject(new Error(problem)); },
            then(ok, fail) { return done.then(ok, fail); },
            catch(fail) { return done.catch(fail); },
        };
        return p;
    }
    // proc is a cockpit.spawn process: input(), then(ok, fail(ex, stdout)).
    function proc(run) {
        let input = "";
        const p = {
            input(x) { input = x; return p; },
            then(ok, fail) {
                return Promise.resolve().then(() => {
                    const r = run(input);
                    return r.ok ? ok(r.out) : fail(new Error(r.err || "exit status 1"), r.out);
                });
            },
        };
        return p;
    }
    function policy(args) {
        return proc(input => {
            if (args[0] === "show") {
                const file = origin === "default" ? "/usr/share/mcp-gateway/rbac/data.yaml" : etc + (origin === "yaml" ? "data.yaml" : "data.json");
                return { ok: true, out: JSON.stringify({ file, origin, ignored, data: JSON.parse(rbac),
                                                         yaml: yamlText || "# converted\n" + rbac + "\n" }) };
            }
            if (args[0] === "convert") {
                log.push(["policy-convert", args.join(" ")]);
                if (origin !== "json" || args[1] !== etc + "data.json") return { ok: false, err: args[1] + " is YAML already" };
                ignored = [etc + "data.json"];
                yamlText = "# Role data, converted from data.json\n" + rbac + "\n";
                origin = "yaml";
                return { ok: true, out: "wrote " + etc + "data.yaml\n" };
            }
            const yaml = args.includes("--yaml"), dry = args.includes("--dry-run");
            log.push([dry ? "policy-check" : "policy-write", args.join(" "), input]);
            const res = { file: etc + "data.yaml", written: false, problems: [] };
            let data;
            try {
                data = JSON.parse(yaml ? input.split("\n").filter(l => !l.startsWith("#")).join("\n") : input);
            } catch (ex) {
                res.problems = ["not valid YAML: " + ex.message];
                return { ok: false, out: JSON.stringify(res) };
            }
            if (input.includes("require_aproval")) {
                res.problems = ["/roles/developer/permissions/0: additional properties 'require_aproval' not allowed"];
                return { ok: false, out: JSON.stringify(res) };
            }
            res.data = data;
            if (!dry) {
                if (origin === "json") ignored = [etc + "data.json"];
                yamlText = yaml ? input : "# who may do what: ticket 7\n" + JSON.stringify(data, null, 2) + "\n";
                rbac = JSON.stringify(data);
                origin = "yaml";
                res.written = true;
                res.ignored = ignored;
            }
            return { ok: true, out: JSON.stringify(res) };
        });
    }
})();
