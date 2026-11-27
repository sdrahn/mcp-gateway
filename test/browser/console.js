/* Goes through the gateway's console in a headless browser, as an
 * operator would: /console/ sends it to the identity provider and back,
 * each tab of the navigation is opened, PRINCIPAL's instance is stopped
 * on the Servers tab, and role data is tried in the Policy tab's what-if.
 * Prints what the browser sent with each form (its Origin header) and
 * the pages that came back, one line each ("<what>: <the page's text>").
 * Needs playwright-core (or playwright) and Chromium:
 *
 *   CHROME=/usr/bin/google-chrome node test/browser/console.js ORIGIN ROLE-DATA PRINCIPAL
 *
 * e2e's TestConsoleBrowser runs it.
 */
"use strict";
let pw;
try {
    pw = require("playwright-core");
} catch {
    pw = require("playwright");
}

const text = async page => (await page.innerText("body")).replace(/\s+/g, " ");

(async () => {
    const origin = process.argv[2];
    const roleData = process.argv[3];
    const opts = process.env.CHROME ? { executablePath: process.env.CHROME } : {};
    const browser = await pw.chromium.launch(opts);
    try {
        // The test's gateway and identity provider have self-signed
        // certificates.
        const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
        const page = await ctx.newPage();
        page.on("request", req => {
            if (req.method() === "POST") {
                console.log("post " + new URL(req.url()).pathname + " origin=" + (req.headers()["origin"] || "-"));
            }
        });
        await page.goto(origin + "/console/");
        console.log("overview " + new URL(page.url()).pathname + ": " + (await text(page)));
        const tabs = {
            Servers: "/console/servers", Sessions: "/console/sessions", Tasks: "/console/tasks",
            "Sign-ins": "/console/sign-ins", Policy: "/console/policy", Doctor: "/console/doctor",
            Gateway: "/console/",
        };
        const open = async tab => {
            await Promise.all([
                page.waitForURL(u => new URL(u).pathname === tabs[tab]),
                page.click(`nav.tabs a:text-is("${tab}")`),
            ]);
        };
        for (const tab of Object.keys(tabs)) {
            await open(tab);
            console.log("tab " + tab + " " + new URL(page.url()).pathname + ": " + (await text(page)));
        }
        await open("Servers");
        // The form's answer sends the browser back to the same path: wait
        // for that page, not for the URL.
        // The agent's instance (the row of its principal, argv[4]), not
        // the gateway's own discovery instance.
        const stop = `tr:has-text("${process.argv[4]}") form[action^="/console/instances/"]`;
        console.log("stop: " + (await page.getAttribute(stop, "action")));
        await Promise.all([
            page.waitForResponse(r => r.request().method() === "GET" && new URL(r.url()).pathname === "/console/servers"),
            page.click(stop + " button"),
        ]);
        // The old page has no note: the new one says what was done.
        await page.waitForSelector('p.note:has-text("Done:")');
        console.log("stopped: " + (await text(page)));
        await open("Policy");
        await page.fill('textarea[name="data"]', roleData);
        await Promise.all([
            page.waitForURL(u => new URL(u).pathname === "/console/policy/whatif"),
            page.click('form[action="/console/policy/whatif"] button'),
        ]);
        console.log("what-if: " + (await text(page)));
    } finally {
        await browser.close();
    }
})().catch(e => {
    console.error(e);
    process.exit(1);
});
