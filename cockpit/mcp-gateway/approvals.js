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
                       JSON.stringify({ decision, scope, via: "cockpit" }),
                       { "Content-Type": "application/json" });
        showError(null);
    } catch (ex) {
        if (refusalCode(ex) === "password_required") {
            askPassword(id, scope);
        } else {
            showError(ex && ex.status === 404
                ? "This request is no longer pending (decided elsewhere, or timed out)."
                : describeFailure(ex));
        }
    }
    tabs.approvals.refresh();
}

/* refusalCode is the code of the gateway's refusal (its JSON body), if any. */
function refusalCode(ex) {
    try {
        return ex && ex.status === 403 ? JSON.parse(ex.body).code : null;
    } catch {
        return null;
    }
}

/* askPassword asks for the user's password to approve their own request:
 * only the approver rule "self" lets them, and every process of theirs
 * reaches the gateway as they do, their agent too, so the gateway asks
 * polkit, which asks for the password (roadmap step 40). Cockpit has no
 * polkit agent for it: the approval goes through mcp-gateway-admin in a
 * terminal of its own (a pty), whose polkit text agent asks, and this
 * form answers once. */
function askPassword(id, scope) {
    const form = document.getElementById("own-password");
    const input = el("input", { type: "password", autocomplete: "current-password", "aria-label": "Your password" });
    const status = el("div", { class: "muted" });
    const submit = el("button", { type: "submit" }, "Approve");
    const cancel = el("button", { type: "button", class: "secondary", onclick: () => { form.hidden = true } }, "Cancel");
    form.replaceChildren(
        el("h3", null, "Your password, to approve your own request"),
        el("p", null, "Approving " + id + " (" + scopeTitle(scope) + ") for your agent needs your password: " +
           "the agent could approve it otherwise, as it runs as you."),
        input, el("div", { class: "actions" }, submit, cancel), status);
    form.onsubmit = async ev => {
        ev.preventDefault();
        submit.disabled = true;
        status.textContent = "Approving…";
        try {
            await approveWithPassword(id, scope, input.value);
            form.hidden = true;
            showError(null);
        } catch (msg) {
            status.textContent = String(msg);
            submit.disabled = false;
        }
        input.value = "";
        tabs.approvals.refresh();
    };
    form.hidden = false;
    input.focus();
}

/* approveWithPassword runs the approval in a pty and types the password
 * at polkit's prompt, once: a second prompt means it was wrong. The
 * prompt is PAM's, in the C locale whatever the session's language; the
 * password goes after a moment, as the agent turns echo off after the
 * prompt and that may discard what was typed before. */
function approveWithPassword(id, scope, password) {
    return new Promise((resolve, reject) => {
        let out = "";
        let prompts = 0;
        const proc = cockpit.spawn(["mcp-gateway-admin", "approvals", "approve", id, "--scope", scope, "--yes"],
                                   { pty: true, err: "out", environ: ["LC_ALL=C"] });
        proc.stream(data => {
            out += data;
            const n = (out.match(/Password:/g) || []).length;
            if (n > prompts) {
                prompts = n;
                if (prompts === 1) {
                    setTimeout(() => proc.input(password + "\n", true), 200);
                } else {
                    proc.close("terminated");
                }
            }
        });
        proc.then(() => resolve())
            .catch(() => reject(prompts > 1
                ? "The password was not accepted."
                : (out.split("\n").filter(l => l.startsWith("mcp-gateway-admin:")).pop() || "Approving failed.")
                    .replace(/^mcp-gateway-admin: /, "")));
    });
}

async function revoke(id, button) {
    button.disabled = true;
    try {
        await api.request({ method: "DELETE", path: "/v1/grants/" + encodeURIComponent(id) + "?via=cockpit", body: "" });
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
            p.waiting === false
                ? el("div", { class: "note" }, "The agent is no longer waiting (it disconnected, or the gateway " +
                     "restarted). Approving lets its next attempt through.")
                : null,
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
        setTabCount("approvals", pending.length);
    },
};
