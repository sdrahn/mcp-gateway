/* Audit tab: the gateway's audit records from the journal. Each is a JSON
 * line with "audit": true in the MESSAGE of mcp-gateway.service: an
 * enforcement decision ("effect") or a security event ("event").
 */
"use strict";

async function auditRecords(lines) {
    const out = await cockpit.spawn(["journalctl", "--unit", "mcp-gateway.service", "--output", "json",
                                     "--output-fields", "MESSAGE", "--lines", String(lines), "--no-pager"],
                                    { superuser: "try", err: "out" });
    const records = [];
    let other = "";
    for (const line of out.split("\n")) {
        if (!line.trim()) continue;
        let entry;
        try {
            entry = JSON.parse(line);
        } catch (ex) {
            other += line + "\n"; // e.g. a hint about missing journal access
            continue;
        }
        let msg = entry.MESSAGE;
        if (Array.isArray(msg)) msg = new TextDecoder().decode(new Uint8Array(msg));
        if (typeof msg !== "string" || !msg.startsWith("{")) continue;
        try {
            const r = JSON.parse(msg);
            if (r.audit === true) records.push(r);
        } catch (ex) {
            // not a JSON log line
        }
    }
    return { records: records.reverse(), other };
}

function recordKind(r) {
    if (r.event) return "event";
    return r.effect || "";
}

function recordMatches(r, effect, text) {
    if (effect && recordKind(r) !== effect) return false;
    if (!text) return true;
    return JSON.stringify(r).toLowerCase().includes(text.toLowerCase());
}

function recordRow(r) {
    const kind = recordKind(r);
    const label = r.event ? r.event + (r.ok === false ? " (failed)" : "") : r.effect;
    const call = r.event
        ? [r.server, r.target || r.name].filter(Boolean).join(" / ")
        : [r.server, r.name].filter(Boolean).join(" / ") + (r.action ? " (" + r.action + ")" : "");
    const details = [];
    for (const [k, title] of [["reason", "reason"], ["grant", "grant"], ["id", "id"], ["by", "by"],
        ["scope", "scope"], ["channel", "via"], ["revision", "revision"], ["instance", "instance"],
        ["decision_id", "decision"], ["values", "pseudonymized"], ["reidentified", "re-identified"]]) {
        if (r[k]) details.push(title + ": " + r[k]);
    }
    if (r.args !== undefined) details.push("args: " + JSON.stringify(r.args));
    else if (r.args_hmac) details.push("args digest: " + r.args_hmac.slice(0, 16) + "…");
    return el("tr", { class: "record-" + kind },
              el("td", { title: r.time }, r.time ? new Date(r.time).toLocaleString() : ""),
              el("td", null, el("span", { class: "badge badge-" + kind }, label)),
              el("td", null, r.sub || r.principal || ""),
              el("td", null, call),
              el("td", { class: "details" }, details.join(" · ")));
}

tabs.audit = {
    intervalMs: 0,
    init() {
        const form = document.getElementById("audit-filter");
        form.addEventListener("submit", ev => {
            ev.preventDefault();
            tabs.audit.refresh().catch(ex => showError("Reading the journal failed: " + (ex.message || ex.problem || ex)));
        });
        for (const f of [form.elements["effect"], form.elements["text"]]) {
            f.addEventListener("input", () => { if (this.last) this.render() });
        }
    },
    last: null,
    render() {
        const form = document.getElementById("audit-filter");
        const body = document.querySelector("#audit tbody");
        const shown = this.last.records.filter(r => recordMatches(r, form.elements["effect"].value, form.elements["text"].value.trim()));
        body.replaceChildren(...shown.map(recordRow));
        if (shown.length === 0) {
            const why = this.last.records.length === 0 && this.last.other.trim()
                ? this.last.other.trim()
                : "No matching records.";
            body.append(el("tr", null, el("td", { colspan: "5", class: "muted" }, why)));
        }
    },
    async refresh() {
        const form = document.getElementById("audit-filter");
        this.last = await auditRecords(form.elements["lines"].value);
        this.render();
    },
};
