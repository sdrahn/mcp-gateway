/* Policy tab: what OPA has loaded, and the role data (roles, bindings,
 * approver rules) in /etc/mcp-gateway/policy/rbac/data.json, edited with
 * administrative access. OPA picks changes up by itself (--watch); with a
 * signed bundle file they take effect once the bundle is rebuilt, which
 * the page does with mcp-policy-bundle if the signing key is on this host.
 */
"use strict";

let rbac = null; // parsed role data as last read or saved
// "directories", "bundle-file" (our bundle file), or "bundle-server"
let policySource = "directories";
let signingKey = false; // the signing key exists on this host
let unsigned = false; // role data saved since the active bundle was built

function rbacFile() {
    return cockpit.file(RBAC_FILE, { superuser: "try" });
}

/* validateRBAC returns the problems that would make the role data unusable. */
function validateRBAC(d) {
    const problems = [];
    const isObj = v => v !== null && typeof v === "object" && !Array.isArray(v);
    if (!isObj(d)) return ["The role data must be a JSON object."];
    if (!isObj(d.roles)) problems.push("\"roles\" must be an object.");
    const roles = isObj(d.roles) ? d.roles : {};
    for (const [name, role] of Object.entries(roles)) {
        if (!isObj(role) || !Array.isArray(role.permissions)) {
            problems.push("Role \"" + name + "\" needs a \"permissions\" list.");
            continue;
        }
        role.permissions.forEach((p, i) => {
            if (!isObj(p) || typeof p.server !== "string") {
                problems.push("Permission " + (i + 1) + " of role \"" + name + "\" needs a \"server\" glob.");
            }
        });
    }
    const b = d.bindings === undefined ? {} : d.bindings;
    if (!isObj(b)) problems.push("\"bindings\" must be an object.");
    for (const kind of ["users", "groups"]) {
        const m = isObj(b) && b[kind] !== undefined ? b[kind] : {};
        if (!isObj(m)) {
            problems.push("\"bindings." + kind + "\" must be an object.");
            continue;
        }
        for (const [who, list] of Object.entries(m)) {
            if (!Array.isArray(list)) {
                problems.push("Binding of " + kind.slice(0, -1) + " \"" + who + "\" must be a list of roles.");
                continue;
            }
            for (const r of list) {
                if (!(r in roles)) problems.push(kind.slice(0, -1) + " \"" + who + "\" is bound to unknown role \"" + r + "\".");
            }
        }
    }
    return problems;
}

async function saveRBAC(data) {
    const problems = validateRBAC(data);
    if (problems.length > 0) {
        showError("Not saved: " + problems.join(" "));
        return false;
    }
    try {
        await rbacFile().replace(JSON.stringify(data, null, 2) + "\n");
    } catch (ex) {
        showError(ex && ex.problem === "access-denied"
            ? "Saving needs administrative access (turn it on in Cockpit's top bar)."
            : "Saving failed: " + ((ex && (ex.message || ex.problem)) || ex));
        return false;
    }
    rbac = data;
    showError(null);
    if (policySource === "bundle-file") unsigned = true;
    renderBundleNote();
    renderRBAC();
    return true;
}

function renderBundleNote() {
    const note = document.getElementById("bundle-note");
    const text = document.getElementById("bundle-note-text");
    const actions = document.getElementById("bundle-sign-actions");
    note.hidden = policySource === "directories";
    actions.hidden = true;
    if (policySource === "bundle-server") {
        text.textContent = "The policy comes from a bundle server: changes saved here do not apply " +
            "until the bundle published there includes them.";
    } else if (signingKey) {
        text.textContent = unsigned
            ? "Saved changes are not active yet: sign a new bundle to apply them."
            : "The policy is loaded from a signed bundle. After changing the role data, sign a new " +
              "bundle to apply it (this restarts the policy engine; requests are denied for a moment).";
        actions.hidden = false;
    } else {
        text.textContent = "The policy is loaded from a signed bundle: changes saved here take effect " +
            "once the bundle is rebuilt with mcp-policy-bundle. To sign from here, create a signing " +
            "key on this host with \"mcp-policy-bundle -G\".";
    }
}

/* signRevision names the bundle revision after the user and time, which the
 * gateway's policy change audit events record. */
function signRevision() {
    const who = currentUser ? currentUser.name.replace(/[^A-Za-z0-9_.-]/g, "_") : "unknown";
    return "cockpit-" + who + "-" + new Date().toISOString().replace(/[-:]|\.\d+/g, "");
}

async function signBundle() {
    const button = document.getElementById("bundle-sign");
    const output = document.getElementById("bundle-sign-output");
    button.disabled = true;
    output.hidden = false;
    output.textContent = "Signing…";
    try {
        output.textContent = (await cockpit.spawn(["mcp-policy-bundle", "-r", signRevision()],
                                                  { superuser: "require", err: "out" })).trim();
        unsigned = false;
        showError(null);
        renderBundleNote();
        // OPA restarts with the new bundle; give it a moment.
        setTimeout(() => tabs.policy.refresh().catch(() => {}), 1500);
    } catch (ex) {
        output.textContent = ((ex && ex.message) || "").trim();
        showError(ex && ex.problem === "access-denied"
            ? "Signing needs administrative access (turn it on in Cockpit's top bar)."
            : "Signing the bundle failed; see the output below.");
    } finally {
        button.disabled = false;
    }
}

function copyRBAC() {
    return JSON.parse(JSON.stringify(rbac));
}

function permissionText(p) {
    let target = "";
    for (const f of ["tool", "prompt", "resource", "client"]) {
        if (p[f] !== undefined) target = f + " " + p[f];
    }
    const flags = [];
    if (p.effect === "deny") flags.push("deny");
    if (p.require_approval) flags.push("approval" + (p.approval_channel ? " via " + p.approval_channel : ""));
    if (p.args) flags.push("argument constraints");
    if (p.obligations) flags.push("obligations: " + Object.keys(p.obligations).join(", "));
    if (p.require_client_cert) flags.push("client certificate");
    if (p.allow_sensitive) flags.push("sensitive elicitations");
    return "server " + p.server + ": " + (target || "(no target)") + (flags.length ? " — " + flags.join(", ") : "");
}

function renderRBAC() {
    const roles = rbac.roles || {};
    const bindings = rbac.bindings || {};

    const select = document.querySelector("#binding-add select[name=role]");
    select.replaceChildren(...Object.keys(roles).sort().map(r => el("option", { value: r }, r)));

    const body = document.querySelector("#bindings tbody");
    body.replaceChildren();
    let rows = 0;
    for (const kind of ["users", "groups"]) {
        for (const [who, list] of Object.entries(bindings[kind] || {}).sort()) {
            rows++;
            const chips = el("span", { class: "chips" });
            for (const role of list) {
                const x = el("button", { class: "chip", title: "Remove role " + role, "aria-label": "Remove role " + role + " from " + who }, role + " ×");
                x.addEventListener("click", () => {
                    const d = copyRBAC();
                    d.bindings[kind][who] = list.filter(r => r !== role);
                    if (d.bindings[kind][who].length === 0) delete d.bindings[kind][who];
                    saveRBAC(d);
                });
                chips.append(x);
            }
            const remove = el("button", { class: "danger" }, "Remove");
            remove.addEventListener("click", () => {
                const d = copyRBAC();
                delete d.bindings[kind][who];
                saveRBAC(d);
            });
            body.append(el("tr", null,
                           el("td", null, kind === "users" ? "User" : "Group"),
                           el("td", null, who),
                           el("td", null, chips),
                           el("td", null, remove)));
        }
    }
    if (rows === 0) body.append(el("tr", null, el("td", { colspan: "4", class: "muted" }, "No bindings.")));

    const box = document.getElementById("roles");
    box.replaceChildren();
    for (const [name, role] of Object.entries(roles).sort()) {
        box.append(el("div", { class: "card" },
                      el("h3", null, name),
                      el("ul", { class: "permissions" },
                         ...(role.permissions || []).map(p => el("li", null, permissionText(p))))));
    }
    const approvers = rbac.approvers || { default: ["self"] };
    box.append(el("div", { class: "card" },
                  el("h3", null, "Approvers"),
                  el("ul", { class: "permissions" },
                     ...Object.entries(approvers).sort().map(([server, rules]) =>
                         el("li", null, (server === "default" ? "default" : "server " + server) + ": " + rules.join(", "))))));

    document.getElementById("rbac-json").value = JSON.stringify(rbac, null, 2);
}

tabs.policy = {
    intervalMs: 0,
    init() {
        document.getElementById("rbac-path").textContent = RBAC_FILE;
        document.getElementById("binding-add").addEventListener("submit", ev => {
            ev.preventDefault();
            const f = ev.target;
            const name = f.elements["name"].value.trim();
            const role = f.elements["role"].value;
            if (!name || !role || !rbac) return;
            const d = copyRBAC();
            d.bindings = d.bindings || {};
            d.bindings[f.elements["kind"].value] = d.bindings[f.elements["kind"].value] || {};
            const list = d.bindings[f.elements["kind"].value][name] || [];
            if (!list.includes(role)) list.push(role);
            d.bindings[f.elements["kind"].value][name] = list;
            saveRBAC(d).then(ok => { if (ok) f.elements["name"].value = "" });
        });
        document.getElementById("rbac-save").addEventListener("click", () => {
            let d;
            try {
                d = JSON.parse(document.getElementById("rbac-json").value);
            } catch (ex) {
                showError("Not saved: the text is not valid JSON (" + ex.message + ").");
                return;
            }
            saveRBAC(d);
        });
        document.getElementById("bundle-sign").addEventListener("click", signBundle);
        document.getElementById("rbac-reset").addEventListener("click", () => {
            if (rbac) document.getElementById("rbac-json").value = JSON.stringify(rbac, null, 2);
        });
    },
    async refresh() {
        const status = document.getElementById("policy-status");
        try {
            const st = await getJSON("/v1/policy");
            const bundles = st.bundles || {};
            const revs = Object.entries(bundles).map(([n, r]) => n + " (revision " + (r || "none") + ")");
            status.textContent = st.mode === "bundle"
                ? "Loaded from signed bundle " + revs.join(", ") + "."
                : "Loaded from the policy directories (/usr/share/mcp-gateway/policy, /etc/mcp-gateway/policy).";
            policySource = st.mode !== "bundle" ? "directories" : BUNDLE_FILE in bundles ? "bundle-file" : "bundle-server";
            signingKey = false;
            if (policySource === "bundle-file") {
                try {
                    await cockpit.spawn(["test", "-e", SIGNING_KEY], { err: "ignore" });
                    signingKey = true;
                } catch (ex) {
                    // no key on this host
                }
            }
            renderBundleNote();
        } catch (ex) {
            status.textContent = "Policy status unavailable: " + describeFailure(ex);
        }
        const text = await rbacFile().read();
        try {
            rbac = JSON.parse(text || "{}");
        } catch (ex) {
            const err = new Error("bad role data");
            err.userMessage = RBAC_FILE + " is not valid JSON (" + ex.message + "); fix it below.";
            document.getElementById("rbac-json").value = text;
            document.getElementById("rbac-raw").open = true;
            throw err;
        }
        renderRBAC();
    },
};
