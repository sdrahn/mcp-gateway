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

tabs.clients = {
    intervalMs: 5000,
    async refresh() {
        const clients = await getJSON("/v1/sessions").catch(() => []);
        renderClients(clients);
        setTabCount("clients", clients.length);
    },
};
