/* Tab switching and periodic refresh. The tab is the first element of the
 * location path (#/servers, ...); #/approvals/<id> highlights a request.
 */
"use strict";

let current = null;
let timer = null;
let busy = false;

async function refreshCurrent() {
    const tab = tabs[current];
    if (!tab || busy) return;
    busy = true;
    try {
        await tab.refresh();
        showError(null);
    } catch (ex) {
        showError(ex && ex.userMessage ? ex.userMessage : describeFailure(ex));
    } finally {
        busy = false;
    }
}

function show() {
    const name = tabs[cockpit.location.path[0]] ? cockpit.location.path[0] : "approvals";
    if (name !== current) {
        current = name;
        showError(null);
        for (const t of Object.keys(tabs)) {
            document.getElementById("tab-" + t).hidden = t !== name;
        }
        for (const b of document.querySelectorAll("#tabs button")) {
            b.setAttribute("aria-selected", String(b.dataset.tab === name));
        }
        clearInterval(timer);
        timer = tabs[name].intervalMs ? setInterval(refreshCurrent, tabs[name].intervalMs) : null;
    }
    refreshCurrent();
}

async function init() {
    for (const b of document.querySelectorAll("#tabs button")) {
        b.addEventListener("click", () => cockpit.location.go([b.dataset.tab]));
    }
    for (const t of Object.values(tabs)) {
        if (t.init) t.init();
    }
    try {
        currentUser = await getJSON("/v1/whoami");
        document.getElementById("whoami").textContent = "Signed in as " + currentUser.name;
        const status = await getJSON("/v1/status");
        document.getElementById("restart-note").hidden = !status.restart_pending;
    } catch (ex) {
        showError(describeFailure(ex));
    }
    cockpit.addEventListener("locationchanged", show);
    show();
}

init();
