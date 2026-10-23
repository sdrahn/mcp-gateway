/* Policy tab: what OPA has loaded, and the role data (roles, bindings,
 * approver rules, token scope ceilings) in force, edited with
 * administrative access and saved to /etc/mcp-gateway/policy/rbac/data.yaml.
 * The page leaves YAML to "mcp-gateway-admin policy show" (the role data
 * in force as JSON, and its YAML text) and "policy write" (checks it and
 * writes data.yaml, keeping its comments). OPA picks changes up by itself (--watch); with a
 * signed bundle file they take effect once the bundle is rebuilt, which
 * the page does with mcp-policy-bundle if the signing key is on this host.
 */
"use strict";

let rbac = null; // parsed role data as last read or saved
// roles shipped by server setup packages (GET /v1/policy): name →
// { setup, description, permissions }; bindings may name them, the role
// data may replace them.
let shippedRoles = {};
// "directories", "bundle-file" (our bundle file), or "bundle-server"
let policySource = "directories";
let signingKey = false; // the signing key exists on this host
let unsigned = false; // role data saved since the active bundle was built
// The role data in force as "policy show" gave it: { file, origin
// ("yaml", "json" or "default"), ignored, data, yaml, error }.
let rbacShown = null;

/* policyRun runs "mcp-gateway-admin policy ARGS" with input; it resolves
 * to { ok, out (its JSON output, or null), ex }. "policy write" prints its
 * result also when it refuses the data (exit status 1). */
function policyRun(args, input, superuser) {
    return new Promise(resolve => {
        const parse = text => { try { return JSON.parse(text) } catch (e) { return null } };
        const proc = cockpit.spawn(["mcp-gateway-admin", "policy", ...args], { superuser, err: "message" });
        if (input !== undefined) proc.input(input);
        proc.then(out => resolve({ ok: true, out: parse(out) }),
                  (ex, out) => resolve({ ok: false, ex, out: parse(out) }));
    });
}

function failureText(r) {
    if (r.ex && r.ex.problem === "access-denied") return "Saving needs administrative access (turn it on in Cockpit's top bar).";
    return ((r.ex && (r.ex.message || r.ex.problem)) || "no answer").trim();
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
                if (!(r in roles) && !(r in shippedRoles)) problems.push(kind.slice(0, -1) + " \"" + who + "\" is bound to unknown role \"" + r + "\".");
            }
        }
    }
    if (d.scopes !== undefined && !isObj(d.scopes)) problems.push("\"scopes\" must be an object.");
    for (const [scope, c] of Object.entries(isObj(d.scopes) ? d.scopes : {})) {
        for (const r of (isObj(c) && Array.isArray(c.roles)) ? c.roles : []) {
            if (!(r in roles) && !(r in shippedRoles)) problems.push("Scope \"" + scope + "\" names unknown role \"" + r + "\".");
        }
    }
    return problems;
}

/* previewChanges asks the gateway which decisions the role data would
 * change (POST /v1/policy/whatif); null if it cannot tell (not running,
 * or the user may not review policy changes). */
async function previewChanges(data) {
    try {
        return JSON.parse(await api.post("/v1/policy/whatif", JSON.stringify(data)));
    } catch (ex) {
        return null;
    }
}

const EFFECT_TEXT = { allow: "allowed", ask: "needs approval", deny: "denied" };
const KIND_TEXT = { tool: "tool", prompt: "prompt", resource_template: "resource template", client: "request to the agent" };

/* showPreview lists the changes and saves on confirmation. */
function showPreview(preview, data, yaml) {
    const n = preview.changes.length;
    document.getElementById("whatif-text").textContent =
        "This change alters " + n + " decision" + (n === 1 ? "" : "s") + " (without arguments; " +
        preview.principals + " users and groups, " + preview.resources + " tools, prompts and requests checked):";
    document.querySelector("#whatif-changes tbody").replaceChildren(...preview.changes.map(c =>
        el("tr", null,
           el("td", null, c.principal.replace(/^user:/, "").replace(/^group:/, "group ")),
           el("td", null, c.server),
           el("td", null, (KIND_TEXT[c.kind] || c.kind) + " " + c.name),
           el("td", null, EFFECT_TEXT[c.before] || c.before),
           el("td", null, EFFECT_TEXT[c.after] || c.after))));
    const unchecked = Object.entries(preview.unchecked || {});
    const note = document.getElementById("whatif-unchecked");
    note.hidden = unchecked.length === 0;
    note.textContent = "Not checked: " + unchecked.map(([s, why]) => s + " (" + why + ")").join("; ") + ".";
    const box = document.getElementById("whatif");
    box.hidden = false;
    box.scrollIntoView({ block: "nearest" });
    const save = document.getElementById("whatif-save");
    const cancel = document.getElementById("whatif-cancel");
    save.onclick = () => { box.hidden = true; saveRBAC(data, true, yaml) };
    cancel.onclick = () => { box.hidden = true; renderRBAC() };
}

/* saveRBAC checks the role data (data, or the raw editor's YAML text) and,
 * unless confirmed, shows which decisions it would change before writing
 * it to data.yaml: changes made on the page are merged into the file,
 * keeping its comments; YAML from the raw editor is written as it is. */
async function saveRBAC(data, confirmed, yaml) {
    const args = yaml === undefined ? [] : ["--yaml"];
    const input = yaml === undefined ? JSON.stringify(data) : yaml;
    let problems = data ? validateRBAC(data) : [];
    if (problems.length === 0) {
        // The schema (unknown fields, wrong values, regular expressions)
        // and, for YAML, the syntax; data as the command read it.
        const check = await policyRun(["write", "--dry-run", ...args], input, "try");
        if (!check.out) {
            showError("Not saved: checking the role data failed: " + failureText(check));
            return false;
        }
        problems = check.out.problems || [];
        if (problems.length === 0) {
            data = check.out.data;
            problems = validateRBAC(data);
        }
    }
    if (problems.length > 0) {
        showError("Not saved: " + problems.join(" "));
        return false;
    }
    if (!confirmed) {
        const preview = await previewChanges(data);
        if (preview && preview.changes.length > 0) {
            showError(null);
            showPreview(preview, data, yaml);
            return false;
        }
    }
    const r = await policyRun(["write", ...args], input, "require");
    if (!r.ok || !r.out || !r.out.written) {
        const p = (r.out && r.out.problems) || [];
        showError(p.length ? "Not saved: " + p.join(" ") : "Saving failed: " + failureText(r));
        return false;
    }
    await loadRBAC();
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
    const roleNames = [...new Set([...Object.keys(roles), ...Object.keys(shippedRoles)])].sort();
    select.replaceChildren(...roleNames.map(r => el("option", { value: r }, r)));

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
        const note = name in shippedRoles ? " (replaces the role of setup " + shippedRoles[name].setup + ")" : "";
        box.append(el("div", { class: "card" },
                      el("h3", null, name + note),
                      el("ul", { class: "permissions" },
                         ...(role.permissions || []).map(p => el("li", null, permissionText(p))))));
    }
    for (const [name, role] of Object.entries(shippedRoles).sort()) {
        if (name in roles) continue;
        box.append(el("div", { class: "card" },
                      el("h3", null, name),
                      el("div", { class: "muted" }, "Shipped with the " + role.setup + " server setup" +
                         (role.description ? ": " + role.description : "") + ". Define a role of this name to replace it."),
                      el("ul", { class: "permissions" },
                         ...(role.permissions || []).map(p => el("li", null, permissionText(p))))));
    }
    const approvers = rbac.approvers || { default: ["self"] };
    box.append(el("div", { class: "card" },
                  el("h3", null, "Approvers"),
                  el("ul", { class: "permissions" },
                     ...Object.entries(approvers).sort().map(([server, rules]) =>
                         el("li", null, (server === "default" ? "default" : "server " + server) + ": " + rules.join(", "))))));

    box.append(scopesCard(rbac.scopes));

    document.getElementById("rbac-yaml").value = rbacShown ? rbacShown.yaml : "";
}

/* scopesCard shows the token scope ceilings (user guide chapter 6, "Token
 * scopes"): what a token with each scope may do at most over HTTPS; the
 * roles decide within that. */
function scopesCard(scopes) {
    const entries = Object.entries(scopes || {}).sort(([a], [b]) => (a === "default") - (b === "default") || a.localeCompare(b));
    if (entries.length === 0) {
        return el("div", { class: "card" },
                  el("h3", null, "Token scopes"),
                  el("div", { class: "muted" }, "No ceilings: the scopes of remote users' tokens do not narrow their roles. " +
                     "Add a \"scopes\" map to the role data to limit what a token may do (user guide, chapter 6)."));
    }
    const items = entries.map(([scope, c]) => {
        const name = scope === "default" ? "default (tokens with none of these scopes)" : scope;
        if (c.unlimited) return el("li", null, name + ": unlimited (the roles decide)");
        const parts = [];
        if ((c.roles || []).length) parts.push("roles " + c.roles.join(", "));
        const perms = (c.permissions || []).map(permissionText);
        return el("li", null, name + ": " + (parts.concat(perms).join("; ") || "nothing"));
    });
    const notes = ["A request needs the roles and the ceiling of one of the token's scopes; outside it, it is denied " +
                   "(never asked), and over HTTPS answered with an insufficient_scope challenge. Local users are not limited."];
    if (!("default" in (scopes || {}))) notes.push("Without \"default\", tokens with none of these scopes are not limited.");
    return el("div", { class: "card" },
              el("h3", null, "Token scopes"),
              el("ul", { class: "permissions" }, ...items),
              ...notes.map(n => el("div", { class: "muted" }, n)));
}

/* renderOrigin says where the role data shown comes from, and where
 * saving puts it. */
function renderOrigin() {
    const st = rbacShown;
    document.getElementById("rbac-path").textContent = st.file;
    const note = document.getElementById("rbac-origin");
    const notes = [];
    if (st.origin === "default") {
        notes.push("No role data in " + RBAC_DIR + ": the shipped default is in force. Saving writes " + RBAC_YAML +
                   ", which then replaces the default as a whole.");
    } else if (st.origin === "json") {
        notes.push(st.file + " is JSON, which is no longer read since 1.7: until it is converted, the gateway denies every request. " +
                   "Converting it, or saving, writes " + RBAC_YAML + " (YAML, with the same data), which is in force from then on; " +
                   st.file + " stays as it is, ignored, until you remove it.");
    }
    for (const f of st.ignored || []) notes.push(f + " is ignored: " + st.file + " is in force. You may remove it.");
    note.hidden = notes.length === 0;
    document.getElementById("rbac-origin-text").textContent = notes.join(" ");
    document.getElementById("rbac-convert-actions").hidden = st.origin !== "json" || !!st.error;
}

/* convertRBAC converts the role data in force from JSON to data.yaml
 * ("policy convert"), which is in force from then on. */
async function convertRBAC() {
    const r = await policyRun(["convert", rbacShown.file], undefined, "require");
    if (!r.ok) {
        showError("Converting failed: " + failureText(r));
        return;
    }
    showError(null);
    await loadRBAC();
}

/* loadRBAC reads the role data in force. Data that does not parse is put
 * into the raw editor to fix. */
async function loadRBAC() {
    const r = await policyRun(["show"], undefined, "try");
    if (!r.ok || !r.out) {
        const err = new Error("role data unreadable");
        err.userMessage = "Reading the role data failed: " + failureText(r);
        throw err;
    }
    rbacShown = r.out;
    renderOrigin();
    if (rbacShown.error) {
        rbac = null;
        document.getElementById("rbac-yaml").value = rbacShown.yaml || "";
        document.getElementById("rbac-raw").open = true;
        const err = new Error("bad role data");
        err.userMessage = rbacShown.file + " does not parse (" + rbacShown.error + "); fix it below.";
        throw err;
    }
    rbac = rbacShown.data || {};
    renderRBAC();
}

tabs.policy = {
    intervalMs: 0,
    init() {
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
            saveRBAC(null, false, document.getElementById("rbac-yaml").value);
        });
        document.getElementById("bundle-sign").addEventListener("click", signBundle);
        document.getElementById("rbac-convert").addEventListener("click", () => {
            convertRBAC().catch(ex => showError(ex.userMessage || String(ex)));
        });
        document.getElementById("rbac-reset").addEventListener("click", () => {
            if (rbacShown) document.getElementById("rbac-yaml").value = rbacShown.yaml || "";
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
            shippedRoles = st.shipped_roles || {};
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
        await loadRBAC();
    },
};
