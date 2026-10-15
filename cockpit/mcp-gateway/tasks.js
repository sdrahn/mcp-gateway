/* Tasks tab: the calls agents run as tasks that the user may see
 * (GET /v1/tasks), with their state, and Cancel for a running one.
 */
"use strict";

/* taskState describes a task's state for people. */
function taskState(t) {
    switch (t.status) {
    case "working": return "running";
    case "input_required": return "waiting for the agent (an approval or a question)";
    case "completed": return "completed " + relative(t.ended) + (t.delivered ? ", result fetched" : ", result not fetched yet");
    case "failed": return "failed " + relative(t.ended) + (t.status_message ? ": " + t.status_message : "");
    case "cancelled": return (t.status_message || "cancelled") + " " + relative(t.ended);
    }
    return t.status;
}

async function cancelTask(t, button) {
    if (!window.confirm("Cancel " + t.server + " / " + t.tool + " of " + t.sub + "? The call is cancelled at the server.")) return;
    button.disabled = true;
    try {
        await api.post("/v1/tasks/" + encodeURIComponent(t.id) + "/cancel", "", {});
        showError(null);
    } catch (ex) {
        showError(ex && (ex.status === 409 || ex.status === 404) ? "The task has ended already." : describeFailure(ex));
    }
    tabs.tasks.refresh();
}

function renderTasks(tasks) {
    const body = document.querySelector("#tasks tbody");
    body.replaceChildren();
    if (tasks.length === 0) {
        body.append(el("tr", null, el("td", { colspan: "5", class: "muted" }, "No tasks you may manage.")));
        return;
    }
    for (const t of tasks) {
        let action = null;
        if (t.status === "working" || t.status === "input_required") {
            action = el("button", { class: "danger" }, "Cancel");
            action.addEventListener("click", () => cancelTask(t, action));
        }
        body.append(el("tr", null,
                       el("td", null, t.server + " / " + t.tool),
                       el("td", null, principalText(t)),
                       el("td", null, relative(t.created)),
                       el("td", null, taskState(t)),
                       el("td", null, action)));
    }
}

/* running counts the tasks whose call is still going. */
function running(tasks) {
    return tasks.filter(t => t.status === "working" || t.status === "input_required").length;
}

tabs.tasks = {
    intervalMs: 5000,
    async refresh() {
        const tasks = await getJSON("/v1/tasks").catch(() => []);
        renderTasks(tasks);
        setTabCount("tasks", running(tasks));
    },
};
