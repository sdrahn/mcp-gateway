/* Approvals tab: pending approvals the user may decide on, and grants.
 * URL-mode approval links point here: #/approvals/<id>.
 */
"use strict";

const SCOPE_TITLES = { once: "Only this call", session: "For this session" };

function scopeTitle(s) {
    return SCOPE_TITLES[s] || "For " + s;
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
    tabs.approvals.refresh();
}

async function revoke(id, button) {
    button.disabled = true;
    try {
        await api.request({ method: "DELETE", path: "/v1/grants/" + encodeURIComponent(id), body: "" });
        showError(null);
    } catch (ex) {
        showError(describeFailure(ex));
    }
    tabs.approvals.refresh();
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

tabs.approvals = {
    intervalMs: 2000,
    async refresh() {
        const [pending, grants] = await Promise.all([getJSON("/v1/approvals"), getJSON("/v1/grants")]);
        renderApprovals(pending);
        renderGrants(grants);
    },
};
