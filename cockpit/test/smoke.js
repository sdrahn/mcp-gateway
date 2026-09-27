/* Smoke test of the Cockpit pages in a headless browser, against a stub
 * of cockpit.js with fixtures (cockpit-stub.js). Needs playwright-core and
 * a Chromium or Chrome binary:
 *
 *   npm install --no-save playwright-core
 *   CHROME=/usr/bin/google-chrome node cockpit/test/smoke.js
 */
"use strict";
const { chromium } = require("playwright-core");
const fs = require("fs");
const os = require("os");
const path = require("path");

// The pages load ../base1/cockpit.js; lay them out as Cockpit does.
function site() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-cockpit-"));
    fs.mkdirSync(path.join(root, "base1"));
    fs.copyFileSync(path.join(__dirname, "cockpit-stub.js"), path.join(root, "base1", "cockpit.js"));
    fs.cpSync(path.join(__dirname, "..", "mcp-gateway"), path.join(root, "mcp-gateway"), { recursive: true });
    return root;
}

(async () => {
    const root = site();
    const browser = await chromium.launch({ executablePath: process.env.CHROME || "/usr/bin/google-chrome" });
    const page = await browser.newPage();
    const errors = [];
    page.on("pageerror", e => errors.push(e.message));
    page.on("console", m => { if (m.type() === "error") errors.push(m.text()); });
    page.on("dialog", d => d.accept());
    const url = "file://" + path.join(root, "mcp-gateway", "index.html");
    const check = (cond, what) => { if (!cond) { console.log("FAIL: " + what); process.exitCode = 1; } else console.log("ok: " + what); };

    await page.goto(url + "#/approvals/a1");
    await page.waitForSelector("#approval-a1");
    check(await page.isVisible("#tab-approvals"), "approvals tab shown");
    check((await page.textContent("#whoami")).includes("carol"), "whoami");
    check(await page.$eval("#approval-a1", e => e.classList.contains("highlight")), "linked approval highlighted");
    await page.click("#approval-a1 button:has-text('Only this call')");
    await page.waitForTimeout(200);
    check((await page.evaluate(() => __calls)).some(c => c[0] === "POST" && c[1] === "/v1/approvals/a1" && c[2].includes('"approve"')), "approve posts decision");

    await page.click("#tabs button[data-tab=servers]");
    await page.waitForSelector("#servers .instance");
    check(!(await page.isVisible("#tab-approvals")) && await page.isVisible("#tab-servers"), "servers tab switch");
    const serversText = await page.textContent("#servers");
    check(serversText.includes("mcpsrv_fs_t") && serversText.includes("mcp-fs-i1.service") && serversText.includes("1 session"), "servers and instance shown");
    check(serversText.includes("No running instances you may manage"), "server without instances");
    await page.click("#servers button:has-text('Show log')");
    await page.waitForFunction(() => document.querySelector("pre.log").textContent.includes("started"));
    check(true, "instance log shown");
    await page.click("#servers button:has-text('Stop')");
    await page.waitForFunction(() => !document.querySelector("#servers .instance"));
    check((await page.evaluate(() => __calls)).some(c => c[0] === "DELETE" && c[1] === "/v1/instances/i1"), "stop instance");

    await page.goto(url + "#/policy");
    await page.waitForSelector("#bindings tbody tr td");
    check((await page.textContent("#policy-status")).includes("r42"), "bundle revision shown");
    check(await page.isVisible("#bundle-note"), "bundle note shown");
    const bindings = await page.textContent("#bindings");
    check(bindings.includes("wheel") && bindings.includes("admin") && bindings.includes("dev"), "bindings listed");
    check((await page.textContent("#roles")).includes("approval via url"), "permission flags");
    await page.fill("#binding-add input[name=name]", "alice");
    await page.selectOption("#binding-add select[name=role]", "developer");
    await page.click("#binding-add button[type=submit]");
    await page.waitForFunction(() => document.querySelector("#bindings").textContent.includes("alice"));
    let saved = (await page.evaluate(() => __calls)).filter(c => c[0] === "replace").pop();
    check(saved && JSON.parse(saved[2]).bindings.users.alice[0] === "developer", "binding saved to file");
    await page.click("#bindings button[aria-label='Remove role developer from alice']");
    await page.waitForFunction(() => !document.querySelector("#bindings").textContent.includes("alice"));
    saved = (await page.evaluate(() => __calls)).filter(c => c[0] === "replace").pop();
    check(!("alice" in JSON.parse(saved[2]).bindings.users), "binding removed");
    // Invalid raw JSON is refused.
    await page.click("#rbac-raw summary");
    const before = (await page.evaluate(() => __calls)).filter(c => c[0] === "replace").length;
    await page.fill("#rbac-json", JSON.stringify({ roles: {}, bindings: { users: { x: ["nope"] } } }));
    await page.click("#rbac-save");
    await page.waitForTimeout(200);
    check((await page.textContent("#error")).includes("unknown role"), "validation error shown");
    check((await page.evaluate(() => __calls)).filter(c => c[0] === "replace").length === before, "invalid data not saved");

    // Signing from the page: the key is on the host (stub default).
    check(await page.isVisible("#bundle-sign"), "sign button with a local key");
    check((await page.textContent("#bundle-note-text")).includes("not active yet"), "unsigned changes noted");
    await page.click("#bundle-sign");
    await page.waitForFunction(() => document.querySelector("#bundle-sign-output").textContent.includes("wrote"));
    const sign = (await page.evaluate(() => __calls)).find(c => c[0] === "spawn" && c[1].startsWith("mcp-policy-bundle"));
    check(sign && sign[2] === "require" && /^mcp-policy-bundle -r cockpit-carol-\d{8}T\d{6}Z$/.test(sign[1]),
          "signs as administrator with a named revision: " + (sign && sign[1]));
    check(!(await page.textContent("#bundle-note-text")).includes("not active yet"), "signed changes no longer noted");

    const policyPage = url.replace("index.html", "index.html?source=server");
    await page.goto(policyPage + "#/policy");
    await page.waitForSelector("#bindings tbody tr td");
    await page.waitForFunction(() => document.querySelector("#bundle-note-text").textContent !== "");
    check(!(await page.isVisible("#bundle-sign")) && (await page.textContent("#bundle-note-text")).includes("bundle server"),
          "no signing for bundles from a bundle server");
    await page.goto(url.replace("index.html", "index.html?nokey") + "#/policy");
    await page.waitForSelector("#bindings tbody tr td");
    await page.waitForFunction(() => document.querySelector("#bundle-note-text").textContent !== "");
    check(!(await page.isVisible("#bundle-sign")) && (await page.textContent("#bundle-note-text")).includes("-G"),
          "without a key: hint to create one");

    await page.goto(url + "#/audit");
    await page.click("#audit-filter button[type=submit]");
    await page.waitForSelector("#audit tbody tr td");
    let rows = await page.$$eval("#audit tbody tr", trs => trs.map(t => t.textContent));
    check(rows.length === 3, "three audit records (non-audit line skipped): " + rows.length);
    check(rows[0].includes("read_file") && rows[0].includes("/x"), "newest first, full args shown");
    await page.selectOption("#audit-filter select[name=effect]", "deny");
    rows = await page.$$eval("#audit tbody tr", trs => trs.map(t => t.textContent));
    check(rows.length === 1 && rows[0].includes("denied by policy") && rows[0].includes("abcdef0123456789"), "deny filter");
    await page.selectOption("#audit-filter select[name=effect]", "event");
    rows = await page.$$eval("#audit tbody tr", trs => trs.map(t => t.textContent));
    check(rows.length === 1 && rows[0].includes("mcp-approval") && rows[0].includes("carol"), "event filter");
    await page.selectOption("#audit-filter select[name=effect]", "");
    await page.fill("#audit-filter input[name=text]", "bob");
    rows = await page.$$eval("#audit tbody tr", trs => trs.map(t => t.textContent));
    check(rows.length === 1 && rows[0].includes("bob"), "text filter");

    // Narrow screens: no horizontal scrolling.
    await page.setViewportSize({ width: 390, height: 800 });
    for (const tab of ["approvals", "servers", "policy", "audit"]) {
        await page.goto(url + "#/" + tab);
        await page.waitForTimeout(200);
        const wide = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
        check(!wide, tab + " fits a narrow screen");
    }

    check(errors.length === 0, "no page errors " + JSON.stringify(errors));
    await browser.close();
    fs.rmSync(root, { recursive: true, force: true });
})().catch(e => { console.error(e); process.exit(1); });
