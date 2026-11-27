/* Screenshots of the Cockpit pages and the console for the README
 * (docs/images), in a headless browser: the Cockpit pages against the
 * stub of cockpit.js with its fixtures (cockpit/test), the console's
 * pages as the gateway renders them with demo data
 * (internal/approvalpage/screenshots_test.go). make screenshots runs it:
 *
 *   node tools/screenshots/shoot.js CONSOLE_HTML_DIR OUT_DIR
 *
 * Needs playwright (or playwright-core) and Chromium; CHROME names the
 * browser's binary if playwright has none of its own.
 */
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");

let chromium;
try {
    ({ chromium } = require("playwright"));
} catch (e) {
    ({ chromium } = require("playwright-core"));
}

const [consoleDir, outDir] = process.argv.slice(2);
if (!consoleDir || !outDir) {
    console.error("usage: shoot.js CONSOLE_HTML_DIR OUT_DIR");
    process.exit(2);
}
const width = 1200;

// The Cockpit pages load ../base1/cockpit.js; lay them out as Cockpit
// does, with the stub (as cockpit/test/smoke.js).
function cockpitSite() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "mcpgw-shots-"));
    const repo = path.join(__dirname, "..", "..");
    fs.mkdirSync(path.join(root, "base1"));
    fs.copyFileSync(path.join(repo, "cockpit", "test", "cockpit-stub.js"), path.join(root, "base1", "cockpit.js"));
    fs.cpSync(path.join(repo, "cockpit", "mcp-gateway"), path.join(root, "mcp-gateway"), { recursive: true });
    return root;
}

(async () => {
    const opts = process.env.CHROME ? { executablePath: process.env.CHROME } : {};
    const browser = await chromium.launch(opts);
    const page = await browser.newPage({ viewport: { width, height: 800 }, colorScheme: "light" });
    const shot = async name => {
        await page.screenshot({ path: path.join(outDir, name + ".png"), fullPage: true });
        console.log("wrote " + path.join(outDir, name + ".png"));
    };

    // Cockpit: each tab of the page.
    const root = cockpitSite();
    const index = "file://" + path.join(root, "mcp-gateway", "index.html");
    for (const [tab, name] of [["approvals", "cockpit-approvals"], ["servers", "cockpit-servers"],
        ["clients", "cockpit-clients"]]) {
        await page.goto(index + "?demo#/" + tab);
        await page.waitForSelector("#tab-" + tab + ":not([hidden])");
        await page.waitForTimeout(300);
        await shot(name);
    }
    fs.rmSync(root, { recursive: true, force: true });

    // The console, as the gateway serves it.
    for (const f of fs.readdirSync(consoleDir).filter(f => f.endsWith(".html")).sort()) {
        await page.goto("file://" + path.join(path.resolve(consoleDir), f));
        await shot(f.replace(/\.html$/, ""));
    }
    await browser.close();
})().catch(e => {
    console.error(e);
    process.exit(1);
});
