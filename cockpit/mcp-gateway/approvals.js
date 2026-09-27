/* MCP Gateway approvals page for Cockpit.
 *
 * Talks to the gateway's control API on its unix socket through
 * cockpit.http, i.e. as the logged-in Cockpit user: the gateway identifies
 * the caller by the socket's peer credentials and shows only what that
 * user may decide on (their own requests, or everyone's for the admin
 * group). URL-mode approval links point here: #/approvals/<id>.
 */
"use strict";

const SOCKET = "/run/mcp-gateway/control.sock";
const REFRESH_MS = 2000;

const api = cockpit.http({ unix: SOCKET });

const SCOPE_TITLES = { once: "Only this call", session: "For this session" };

function scopeTitle(s) {
    return SCOPE_TITLES[s] || "For " + s;
}

function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
        if (k === "class") e.className = v;
        else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v);
    }
    for (const c of children) {
        if (c !== null && c !== undefined) e.append(c instanceof Node ? c : String(c));
    }
    return e;
}

function relative(date) {
    const s = Math.round((new Date(date) - Date.now()) / 1000);
    if (s <= 0) return "now";
    if (s < 120) return "in " + s + " s";
    if (s < 7200) return "in " + Math.round(s / 60) + " min";
    if (s < 172800) return "in " + Math.round(s / 3600) + " h";
    return "in " + Math.round(s / 86400) + " days";
}

function principalText(p) {
    let t = p.sub;
    if (p.iss) t += " (" + p.iss + ")";
    t += " via " + p.transport;
    if (p.client && p.client.name) t += ", client " + p.client.name + (p.client.version ? " " + p.client.version : "");
    return t;
}

function showError(msg) {
    const box = document.getElementById("error");
    box.hidden = !msg;
    box.textContent = msg || "";
}

function describeFailure(ex) {
    if (ex && ex.problem === "not-found") {
        return "mcp-gateway is not running (" + SOCKET + " not found).";
    }
    if (ex && ex.problem === "access-denied") {
        return "No access to " + SOCKET + ". Ask an administrator to add you to the gateway's socket group.";
    }
    return "Talking to mcp-gateway failed: " + (ex && (ex.message || ex.problem) || ex);
}

async function getJSON(path) {
    return JSON.parse(await api.get(path));
}

async function decide(id, decision, scope, buttons) {
    buttons.forEach(b => { b.disabled = true });
    try {
        await api.post("/v1/approvals/" + encodeURIComponent(id),
                       JSON.stringify({ decision, scope }),
                       { "Content-Type": "application/json" });
        showError(null);
    } catch (ex) {
        showError(ex && ex.status === 404
            ? "This request is no longer pending (decided elsewhere, or timed out)."
            : describeFailure(ex));
    }
    refresh();
}

async function revoke(id, button) {
    button.disabled = true;
    try {
        await api.request({ method: "DELETE", path: "/v1/grants/" + encodeURIComponent(id), body: "" });
        showError(null);
    } catch (ex) {
        showError(describeFailure(ex));
    }
    refresh();
}

function highlighted() {
    const path = cockpit.location.path;
    return path[0] === "approvals" ? path[1] : null;
}

function renderApprovals(pending) {
    const box = document.getElementById("approvals");
    const focus = highlighted();
    box.replaceChildren();
    if (pending.length === 0) {
        box.append(el("p", { class: "muted" },
                      focus ? "Request " + focus + " is not pending (anymore)." : "Nothing to decide."));
        return;
    }
    for (const p of pending) {
        const buttons = [];
        const actions = el("div", { class: "actions" });
        for (const scope of p.scopes) {
            const b = el("button", { onclick: () => decide(p.id, "approve", scope, buttons) },
                         "Approve: " + scopeTitle(scope));
            buttons.push(b);
            actions.append(b);
        }
        const deny = el("button", { class: "danger", onclick: () => decide(p.id, "deny", "", buttons) }, "Deny");
        buttons.push(deny);
        actions.append(deny);

        const card = el("div", { class: "card" + (p.id === focus ? " highlight" : ""), id: "approval-" + p.id },
            el("h3", null, p.server + " / " + p.name),
            p.prompt ? el("div", null, p.prompt) : null,
            el("dl", null,
               el("dt", null, "Principal"), el("dd", null, principalText(p.principal)),
               el("dt", null, "Action"), el("dd", null, p.action),
               el("dt", null, "Arguments"), el("dd", null, el("pre", null, JSON.stringify(p.args || {}, null, 2))),
               el("dt", null, "Asked via"), el("dd", null, p.channel),
               el("dt", null, "Times out"), el("dd", null, relative(p.expires))),
            actions);
        box.append(card);
    }
    if (focus) {
        const card = document.getElementById("approval-" + focus);
        if (card && !card.dataset.scrolled) {
            card.dataset.scrolled = "1";
            card.scrollIntoView({ block: "center" });
        }
    }
}

function renderGrants(grants) {
    const body = document.querySelector("#grants tbody");
    body.replaceChildren();
    if (grants.length === 0) {
        body.append(el("tr", null, el("td", { colspan: "6", class: "muted" }, "No grants.")));
        return;
    }
    for (const g of grants) {
        const b = el("button", { class: "secondary" }, "Revoke");
        b.addEventListener("click", () => revoke(g.id, b));
        const scope = g.scope === "session" ? "session " + (g.session_id || "").slice(0, 8) : g.scope;
        body.append(el("tr", null,
                       el("td", null, g.server + " / " + g.tool),
                       el("td", null, g.sub + (g.iss ? " (" + g.iss + ")" : "")),
                       el("td", null, scope),
                       el("td", null, relative(g.expires)),
                       el("td", null, g.approved_by + " via " + g.channel),
                       el("td", null, b)));
    }
}

let refreshing = false;

async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
        const [pending, grants] = await Promise.all([getJSON("/v1/approvals"), getJSON("/v1/grants")]);
        renderApprovals(pending);
        renderGrants(grants);
        showError(null);
    } catch (ex) {
        showError(describeFailure(ex));
    } finally {
        refreshing = false;
    }
}

async function init() {
    try {
        const me = await getJSON("/v1/whoami");
        document.getElementById("whoami").textContent = "Deciding as " + me.name;
    } catch (ex) {
        showError(describeFailure(ex));
    }
    cockpit.addEventListener("locationchanged", refresh);
    refresh();
    setInterval(refresh, REFRESH_MS);
}

init();
