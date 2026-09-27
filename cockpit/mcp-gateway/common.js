/* MCP Gateway pages for Cockpit: shared helpers.
 *
 * The pages talk to the gateway's control API on its unix socket through
 * cockpit.http, i.e. as the logged-in Cockpit user: the gateway identifies
 * the caller by the socket's peer credentials and shows only what policy
 * lets that user see and do.
 */
"use strict";

const SOCKET = "/run/mcp-gateway/control.sock";
const RBAC_FILE = "/etc/mcp-gateway/policy/rbac/data.json";

const api = cockpit.http({ unix: SOCKET });

/* Tabs register here: { refresh(), intervalMs } (see main.js). */
const tabs = {};

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

/* relative describes a time relative to now ("in 5 min", "3 h ago"). */
function relative(date) {
    let s = Math.round((new Date(date) - Date.now()) / 1000);
    const past = s < 0;
    s = Math.abs(s);
    let t;
    if (s < 2) return "now";
    if (s < 120) t = s + " s";
    else if (s < 7200) t = Math.round(s / 60) + " min";
    else if (s < 172800) t = Math.round(s / 3600) + " h";
    else t = Math.round(s / 86400) + " days";
    return past ? t + " ago" : "in " + t;
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
    return "Talking to mcp-gateway failed: " + ((ex && (ex.message || ex.problem)) || ex);
}

async function getJSON(path) {
    return JSON.parse(await api.get(path));
}
