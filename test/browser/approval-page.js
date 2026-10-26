/* Approves a pending approval on the gateway's approval page in a headless
 * browser, as an approver would: the page sends it to the identity
 * provider and back, then the Approve button is pressed, then Sign out.
 * Prints what the browser sent with the form (its Origin header) and the
 * pages that came back. Needs playwright-core (or playwright) and Chromium:
 *
 *   CHROME=/usr/bin/google-chrome node test/browser/approval-page.js URL
 *
 * e2e's TestApprovalPageBrowser runs it (MCPGW_CHROME).
 */
"use strict";
let pw;
try {
    pw = require("playwright-core");
} catch {
    pw = require("playwright");
}

(async () => {
    const url = process.argv[2];
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
        await page.goto(url);
        await page.click('button[name="decision"][value="approve"]');
        await page.waitForLoadState("load");
        console.log("page: " + (await page.innerText("body")).replace(/\s+/g, " "));
        // Signing out goes through the identity provider's sign-out and
        // back; the page then asks to sign in again.
        await Promise.all([
            page.waitForURL(u => new URL(u).pathname === "/approvals/signed-out"),
            page.click('form[action="/approvals/logout"] button'),
        ]);
        console.log("signed out: " + (await page.innerText("body")).replace(/\s+/g, " "));
        await page.goto(new URL("/approvals/", url).href);
        console.log("again: " + (await page.innerText("body")).replace(/\s+/g, " "));
    } finally {
        await browser.close();
    }
})().catch(e => {
    console.error(e);
    process.exit(1);
});
