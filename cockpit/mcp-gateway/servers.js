/* Servers tab: the registry and the backend instances the user may see,
 * with stop and the instance's journal.
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
    const who = inst.sub + (inst.iss ? " (" + inst.iss + ")" : "") + " via " + inst.transport +
        (inst.session_id ? ", session " + inst.session_id.slice(0, 8) : "");
    let use = inst.sessions > 0 ? inst.sessions + (inst.sessions === 1 ? " session" : " sessions") : "idle";
    if (inst.busy) use += ", call running";
    return el("div", { class: "instance" },
              el("div", { class: "instance-head" },
                 el("span", null, who),
                 el("span", { class: "muted" }, inst.unit),
                 el("span", { class: "muted" }, "started " + relative(inst.started) + ", " + use),
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
        const facts = [s.selinux_type || "mcpsrv_generic_t", "isolation: " + s.isolation,
            s.network ? "network" : "no network", "runs as " + s.run_as];
        if (s.privileged) facts.push("privileged: no sandbox, every call by policy and approval");
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

tabs.servers = {
    intervalMs: 5000,
    async refresh() {
        renderServers(await getJSON("/v1/servers"));
    },
};
