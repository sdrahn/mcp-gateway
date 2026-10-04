/* Servers tab: the registry and the backend instances the user may see,
 * with stop and the instance's journal; the state of the last reload of
 * the configuration (gateway.yaml, servers.d) and a button to reload it.
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

function renderServers(servers) {
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
        if (s.removed) facts = ["removed from the configuration; its instances stop once their calls end"];
        const card = el("div", { class: "card" },
                        el("h3", null, s.name),
                        el("div", { class: "muted" }, facts.join(" · ")));
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

tabs.servers = {
    intervalMs: 5000,
    init() {
        const button = document.getElementById("reload");
        button.addEventListener("click", () => reload(button));
    },
    async refresh() {
        const [servers, status] = await Promise.all([getJSON("/v1/servers"), getJSON("/v1/status")]);
        renderServers(servers);
        renderReloadStatus(status);
    },
};
