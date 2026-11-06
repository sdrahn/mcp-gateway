/* Clients tab: the AI agents and other MCP clients using the gateway that
 * the user may see (GET /v1/sessions), with the MCP version each speaks,
 * and End (DELETE /v1/sessions/{id}).
 */
"use strict";

/* clientProtocol describes the MCP version a client speaks: the one it
 * got, and the cap (agents.max_version) that lowered it from the one it
 * asked for. */
function clientProtocol(c) {
    if (c.capped) return c.protocol + " (capped by agents.max_version; asked for " + c.requested + ")";
    if (c.kind === "agent") return c.protocol + " (no session)";
    return c.protocol;
}

/* clientActivity describes when a client was last active: an agent of
 * 2026-07-28 with its open streams and requests. */
function clientActivity(c) {
    const open = [];
    if (c.streams) open.push(c.streams + (c.streams === 1 ? " stream" : " streams") + " open");
    if (c.requests) open.push(c.requests + (c.requests === 1 ? " request" : " requests") + " in flight");
    return open.length > 0 ? open.join(", ") : relative(c.last_active);
}

async function endClient(c, button) {
    const name = (c.client && c.client.name) || "the client";
    if (!window.confirm("End " + name + " of " + c.sub + "? Its calls are cancelled; it may connect again.")) return;
    button.disabled = true;
    try {
        await api.request({ method: "DELETE", path: "/v1/sessions/" + encodeURIComponent(c.id), body: "" });
        showError(null);
    } catch (ex) {
        showError(ex && ex.status === 404 ? "The client is gone already." : describeFailure(ex));
    }
    tabs.clients.refresh();
}

function renderClients(clients) {
    const body = document.querySelector("#clients tbody");
    body.replaceChildren();
    if (clients.length === 0) {
        body.append(el("tr", null, el("td", { colspan: "7", class: "muted" }, "No clients you may manage.")));
        return;
    }
    for (const c of clients) {
        const end = el("button", { class: "danger" }, "End");
        end.addEventListener("click", () => endClient(c, end));
        // An agent is listed for an hour after its last request; with
        // nothing open there is nothing to end.
        if (c.kind === "agent" && !c.streams && !c.requests) {
            end.disabled = true;
            end.title = "Nothing open: the agent's next request is served as any other.";
        }
        const client = c.client && c.client.name ? c.client.name + (c.client.version ? " " + c.client.version : "") : "(no name given)";
        body.append(el("tr", null,
                       el("td", null, c.sub + (c.iss ? " (" + c.iss + ")" : "") + " via " + c.transport),
                       el("td", null, client),
                       el("td", null, clientProtocol(c)),
                       el("td", null, c.endpoint === "all" ? "all servers" : c.endpoint),
                       el("td", null, relative(c.started)),
                       el("td", null, clientActivity(c)),
                       el("td", null, end)));
    }
}

/* clockText is a time as the browser's locale writes it. */
function clockText(t) {
    return new Date(t).toLocaleString();
}

/* historyWindow is the time frame the form asks for: [since, until], as
 * Date objects; null with a custom range not filled in. */
function historyWindow(form) {
    const w = form.elements.window.value;
    if (w !== "custom") {
        const until = new Date();
        return [new Date(until - Number(w) * 1000), until];
    }
    const since = form.elements.since.value, until = form.elements.until.value;
    if (!since) return null;
    return [new Date(since), until ? new Date(until) : new Date()];
}

function endText(c) {
    if (!c.ended) return "connected";
    switch (c.end) {
    case "ended": return "ended" + (c.ended_by ? " by " + c.ended_by : "");
    case "not seen": return "not seen for an hour";
    case "gateway stopped": return "gateway stopped";
    default: return c.end || "";
    }
}

function renderHistory(records, text) {
    const body = document.querySelector("#client-history tbody");
    body.replaceChildren();
    const needle = (text || "").trim().toLowerCase();
    const shown = records.filter(c => !needle || [c.sub, c.iss, c.client && c.client.name, c.endpoint]
        .some(v => v && v.toLowerCase().includes(needle)));
    if (shown.length === 0) {
        body.append(el("tr", null, el("td", { colspan: "8", class: "muted" }, "No clients you may manage in this time frame.")));
        return;
    }
    for (const c of shown) {
        const client = c.client && c.client.name ? c.client.name + (c.client.version ? " " + c.client.version : "") : "(no name given)";
        body.append(el("tr", { class: c.ended ? "" : "live" },
                       el("td", null, c.sub + (c.iss ? " (" + c.iss + ")" : "") + " via " + c.transport),
                       el("td", null, client),
                       el("td", null, c.protocol + (c.kind === "agent" ? " (no session)" : "")),
                       el("td", null, c.endpoint === "all" ? "all servers" : c.endpoint),
                       el("td", { title: c.started }, clockText(c.started)),
                       el("td", { title: c.ended || c.last_active }, c.ended ? clockText(c.ended) : "now (active " + relative(c.last_active) + ")"),
                       el("td", null, String(c.calls || 0)),
                       el("td", null, endText(c))));
    }
}

/* lastHistory is the history last fetched, filtered anew as the filter
 * text changes. */
let lastHistory = [];

async function refreshHistory() {
    const form = document.getElementById("history-filter");
    const w = historyWindow(form);
    if (!w) {
        // A custom range without its start: filter what is shown.
        renderHistory(lastHistory, form.elements.text.value);
        return;
    }
    const q = "?since=" + encodeURIComponent(w[0].toISOString().replace(/\.\d+Z$/, "Z")) +
              "&until=" + encodeURIComponent(w[1].toISOString().replace(/\.\d+Z$/, "Z"));
    try {
        lastHistory = await getJSON("/v1/sessions/history" + q);
        renderHistory(lastHistory, form.elements.text.value);
    } catch (ex) {
        lastHistory = [];
        renderHistory([], "");
        showError(ex && ex.status === 404 ? "This mcp-gateway keeps no history of clients (it came with 1.15)." : describeFailure(ex));
    }
}

(function () {
    const form = document.getElementById("history-filter");
    form.addEventListener("submit", ev => { ev.preventDefault(); refreshHistory(); });
    form.elements.window.addEventListener("change", () => {
        document.getElementById("history-range").hidden = form.elements.window.value !== "custom";
        if (form.elements.window.value !== "custom") refreshHistory();
    });
})();

tabs.clients = {
    intervalMs: 5000,
    async refresh() {
        const clients = await getJSON("/v1/sessions").catch(() => []);
        renderClients(clients);
        setTabCount("clients", clients.length);
        // The history with the tab, at most once a minute (a time frame
        // of hours changes slowly).
        if (!this.historyAt || Date.now() - this.historyAt > 60000) {
            this.historyAt = Date.now();
            await refreshHistory();
        }
    },
};
