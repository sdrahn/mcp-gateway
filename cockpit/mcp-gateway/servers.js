/* Servers tab: the registry and the backend instances the user may see,
 * with stop and the instance's journal; for servers each user signs in to
 * (sign_in), the user's sign-in (with Sign out, and the link of a sign-in
 * waiting for them) and, for administrators, everyone's (with Revoke);
 * the state of the last reload of
 * the configuration (gateway.yaml, servers.d) and a button to reload it;
 * the self-check's summary (mcp-gateway-admin doctor).
 */
"use strict";

/* Instance ids whose log is expanded, and the last log text, surviving
 * refreshes. */
const openLogs = new Set();
const logText = new Map();

async function stopInstance(inst, button) {
    if (!window.confirm("Stop " + inst.server + " for " + inst.sub + "? Calls in flight fail.")) return;
    button.disabled = true;
    try {
        await api.request({ method: "DELETE", path: "/v1/instances/" + encodeURIComponent(inst.id), body: "" });
        showError(null);
    } catch (ex) {
        showError(ex && ex.status === 404 ? "The instance is gone already." : describeFailure(ex));
    }
    tabs.servers.refresh();
}

async function instanceLog(inst, box) {
    box.textContent = logText.get(inst.id) || "Loading…";
    let text;
    try {
        const out = await cockpit.spawn(["journalctl", "--unit", inst.unit, "--lines", "50", "--no-pager",
                                         "--output", "short-iso"],
                                        { superuser: "try", err: "message" });
        text = out.trim() || "No journal entries for " + inst.unit + ".";
    } catch (ex) {
        text = "Reading the journal failed: " + (ex.message || ex.problem || ex);
    }
    logText.set(inst.id, text);
    box.textContent = text;
}

function instanceRow(inst) {
    const stop = el("button", { class: "danger" }, "Stop");
    stop.addEventListener("click", () => stopInstance(inst, stop));
    // A privileged instance is not stopped while a call runs (it may be
    // installing packages).
    if (inst.privileged && inst.busy) {
        stop.disabled = true;
        stop.title = "A call is running; the instance stops when it ends.";
    }
    const log = el("pre", { class: "log" });
    log.hidden = !openLogs.has(inst.id);
    const logButton = el("button", { class: "secondary" }, log.hidden ? "Show log" : "Hide log");
    logButton.addEventListener("click", () => {
        log.hidden = !log.hidden;
        logButton.textContent = log.hidden ? "Show log" : "Hide log";
        if (log.hidden) {
            openLogs.delete(inst.id);
        } else {
            openLogs.add(inst.id);
            instanceLog(inst, log);
        }
    });
    if (!log.hidden) instanceLog(inst, log);
    const definition = {
        previous: "previous definition: runs until no session uses it",
        removed: "server removed: stops once its calls end",
    }[inst.definition];
    const who = inst.sub + (inst.iss ? " (" + inst.iss + ")" : "") + " via " + inst.transport +
        (inst.session_id ? ", session " + inst.session_id.slice(0, 8) : "");
    let use = inst.sessions > 0 ? inst.sessions + (inst.sessions === 1 ? " session" : " sessions") : "idle";
    if (inst.busy) use += ", call running";
    return el("div", { class: "instance" },
              el("div", { class: "instance-head" },
                 el("span", null, who),
                 el("span", { class: "muted" }, inst.unit),
                 el("span", { class: "muted" }, "started " + relative(inst.started) + ", " + use),
                 definition ? el("span", { class: "tag" }, definition) : null,
                 el("span", { class: "actions" }, logButton, stop)),
              log);
}

async function signOut(entry, button) {
    const own = currentUser && entry.principal.uid === currentUser.uid;
    const what = own ? "Sign out of " + entry.server + "?" :
        "Revoke " + entry.principal.sub + "'s sign-in to " + entry.server + "?";
    if (!window.confirm(what + " Their instances of it stop; their agent asks them to sign in again.")) return;
    button.disabled = true;
    let path = "/v1/sign-ins/" + encodeURIComponent(entry.server);
    if (!own) {
        const q = new URLSearchParams({ principal: entry.principal.sub, transport: entry.principal.transport });
        if (entry.principal.iss) q.set("iss", entry.principal.iss);
        path += "?" + q.toString();
    }
    try {
        const out = JSON.parse(await api.request({ method: "DELETE", path, body: "" }) || "{}");
        // Tokens the authorization server did not revoke stay valid there
        // until they expire.
        showError(out.revoked < out.signed_out
            ? "Signed out. The authorization server of " + entry.server + " offers no revocation, or did not answer: " +
              "the tokens are deleted here but stay valid there until they expire."
            : null);
    } catch (ex) {
        showError(ex && ex.status === 404 ? "The sign-in is gone already." : describeFailure(ex));
    }
    tabs.servers.refresh();
}

/* signInRows shows a server's sign-ins: the user's own first. */
function signInRows(server, signIns) {
    const rows = [];
    for (const p of signIns.pending.filter(p => p.server === server.name)) {
        rows.push(el("div", { class: "instance" },
                     el("div", { class: "instance-head" },
                        el("strong", null, "Sign-in waiting for you"),
                        el("span", { class: "muted" }, "expires " + relative(p.expires)),
                        el("span", { class: "actions" },
                           el("a", { href: p.url, target: "_blank", rel: "noopener noreferrer", class: "button" }, "Sign in")))));
    }
    const entries = signIns.sign_ins.filter(e => e.server === server.name);
    const mine = entries.some(e => currentUser && e.principal.uid === currentUser.uid);
    if (!mine) {
        rows.push(el("div", { class: "muted" },
                     "You are not signed in to " + server.name + ". Your agent asks you to sign in when you use one of its tools."));
    }
    for (const e of entries) {
        const own = currentUser && e.principal.uid === currentUser.uid;
        const button = el("button", { class: "danger" }, own ? "Sign out" : "Revoke");
        button.addEventListener("click", () => signOut(e, button));
        let when = "signed in " + relative(e.since);
        if (e.expiry) when += ", token " + (new Date(e.expiry) > Date.now() ? "expires " : "expired ") + relative(e.expiry);
        if (e.refreshable) when += " (renewed as needed)";
        rows.push(el("div", { class: "instance" },
                     el("div", { class: "instance-head" },
                        el("span", null, (own ? "You (" + e.principal.sub + ")" : e.principal.sub) +
                           (e.principal.iss ? " (" + e.principal.iss + ")" : "") + " via " + e.principal.transport),
                        el("span", { class: "muted" }, when + (e.scope ? " · scope " + e.scope : "")),
                        el("span", { class: "actions" }, button))));
    }
    return rows;
}

function renderServers(servers, signIns) {
    const box = document.getElementById("servers");
    box.replaceChildren();
    if (servers.length === 0) {
        box.append(el("p", { class: "muted" }, "No MCP servers are registered."));
        return;
    }
    for (const s of servers) {
        let facts = [s.selinux_type || "mcpsrv_generic_t", "isolation: " + s.isolation,
            s.network ? "network" : "no network", "runs as " + s.run_as];
        if (s.privileged) facts.push("privileged: no sandbox, every call by policy and approval");
        if (s.sign_in) facts.push("each user signs in");
        if (s.removed) facts = ["removed from the configuration; its instances stop once their calls end"];
        const card = el("div", { class: "card" },
                        el("h3", null, s.name),
                        el("div", { class: "muted" }, facts.join(" · ")));
        if (s.sign_in) card.append(...signInRows(s, signIns));
        if (s.instances.length === 0) {
            card.append(el("div", { class: "muted" }, "No running instances you may manage."));
        }
        for (const inst of s.instances) card.append(instanceRow(inst));
        box.append(card);
    }
}

/* renderReloadStatus shows what the last reload of the configuration
 * left: a file that did not load, keys that need a restart. */
function renderReloadStatus(status) {
    const box = document.getElementById("reload-status");
    const lines = [];
    if (status.config_error) {
        lines.push(el("div", null, el("strong", null, "gateway.yaml was not reloaded; "),
                      "the gateway runs with the configuration it had: ", el("code", null, status.config_error)));
    }
    if (status.servers_error) {
        lines.push(el("div", null, el("strong", null, "The server definitions were not reloaded; "),
                      "the gateway serves the previous ones: ", el("code", null, status.servers_error)));
    }
    if (status.restart_needed && status.restart_needed.length > 0) {
        lines.push(el("div", null, el("strong", null, "Restart needed: "),
                      "gateway.yaml changes keys that take effect at the next start (" +
                      status.restart_needed.join(", ") + "). ", el("code", null, "systemctl restart mcp-gateway.service"),
                      " ends all sessions."));
    }
    box.replaceChildren(...lines);
    box.hidden = lines.length === 0;
}

/* reload runs systemctl reload (administrative access): it checks the
 * configuration first and fails on a file that does not load. */
async function reload(button) {
    const result = document.getElementById("reload-result");
    button.disabled = true;
    result.textContent = "Reloading…";
    try {
        await cockpit.spawn(["systemctl", "reload", "mcp-gateway.service"], { superuser: "require", err: "message" });
        result.textContent = "Reloaded.";
    } catch (ex) {
        result.textContent = "";
        showError("Reloading failed: " + (ex.message || ex.problem || ex) +
                  " (mcp-gateway --check shows the problem; reloading needs administrative access).");
    } finally {
        button.disabled = false;
    }
    tabs.servers.refresh();
}

/* doctorOutput runs the doctor and returns its output, also when it
 * exits 1 (a check failed) or 3: cockpit.spawn rejects then, and hands
 * the output to catch as its second argument. */
function doctorOutput() {
    return new Promise((resolve, reject) => {
        cockpit.spawn(["mcp-gateway-admin", "doctor", "--no-start", "--json"], { superuser: "try", err: "message" })
                .then(resolve)
                .catch((ex, data) => (data ? resolve(data) : reject(ex)));
    });
}

/* selfCheck runs mcp-gateway-admin doctor without starting servers (as
 * root where the user may, else the checks that need root are skipped)
 * and shows the counts, and the warnings and failures with what to do. */
async function selfCheck(button) {
    const box = document.getElementById("self-check");
    button.disabled = true;
    box.textContent = "Checking…";
    try {
        const results = JSON.parse(await doctorOutput());
        const n = { ok: 0, warn: 0, fail: 0, skip: 0 };
        for (const r of results) n[r.status] = (n[r.status] || 0) + 1;
        const summary = "Self-check: " + n.ok + " ok, " + n.warn + (n.warn === 1 ? " warning, " : " warnings, ") +
                        n.fail + " failed, " + n.skip + " skipped.";
        const bad = results.filter(r => r.status === "warn" || r.status === "fail");
        if (bad.length === 0) {
            box.replaceChildren(el("span", null, summary + " Nothing to do."));
            return;
        }
        const list = el("ul", null, ...bad.map(r => el("li", null,
            el("strong", null, r.status.toUpperCase() + " " + r.check + ": "), r.summary,
            ...(r.details || []).map(d => el("div", { class: "muted" }, d)))));
        box.replaceChildren(el("details", { open: "" }, el("summary", null, summary), list,
            el("div", { class: "muted" }, "All results: mcp-gateway-admin doctor (as root); chapter 10 of the user guide.")));
    } catch (ex) {
        box.textContent = "The self-check did not run: " + (ex.message || ex.problem || ex);
    } finally {
        button.disabled = false;
    }
}

tabs.servers = {
    intervalMs: 5000,
    init() {
        const button = document.getElementById("reload");
        button.addEventListener("click", () => reload(button));
        const check = document.getElementById("self-check-run");
        check.addEventListener("click", () => selfCheck(check));
        selfCheck(check);
    },
    async refresh() {
        const [servers, status, signIns] = await Promise.all([getJSON("/v1/servers"), getJSON("/v1/status"),
            getJSON("/v1/sign-ins").catch(() => ({ sign_ins: [], pending: [] }))]);
        renderServers(servers, signIns);
        renderReloadStatus(status);
    },
};
