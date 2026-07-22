const { test, expect } = require("@playwright/test");
const { startFixtureServer, loadFixture } = require("./harness");

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

let server;
test.beforeAll(async () => { server = await startFixtureServer(); });
test.afterAll(async () => { await server.close(); });

/**
 * Each entry: a fixture reproducing one real editor architecture.
 * typeInto() knows how to focus + enter text for that editor kind.
 */
const EDITORS = [
  {
    name: "textarea (Perplexity/DeepSeek style)",
    file: "textarea.html",
    selector: "#prompt",
    async typeInto(page, text) {
      await page.click("#prompt");
      await page.fill("#prompt", text);
    },
    sendButton: "#send",
  },
  {
    name: "ProseMirror (Claude/ChatGPT style)",
    file: "prosemirror.html",
    selector: "#prompt-textarea",
    async typeInto(page, text) {
      await page.click("#prompt-textarea");
      await page.keyboard.insertText(text);
    },
    sendButton: '[data-testid="send-button"]',
  },
  {
    name: "Quill lazy-loaded (Gemini style)",
    file: "quill.html",
    selector: ".ql-editor",
    async typeInto(page, text) {
      await page.waitForSelector(".ql-editor"); // created ~400ms after load
      await page.click(".ql-editor");
      await page.keyboard.insertText(text);
    },
    sendButton: ".send-button",
  },
];

for (const ed of EDITORS) {
  test.describe(ed.name, () => {
    test("blurs a detected secret while typing", async ({ page }) => {
      await loadFixture(page, server.url(ed.file));
      await ed.typeInto(page, `use ${AWS_KEY} to deploy`);
      // Overlay box appears for the finding.
      await expect(page.locator(".sap-blur.sap-block")).toHaveCount(1, { timeout: 3000 });
    });

    test("intercepts Enter and blocks the send", async ({ page }) => {
      await loadFixture(page, server.url(ed.file));
      await ed.typeInto(page, `use ${AWS_KEY} to deploy`);
      await page.locator(ed.selector).press("Enter");
      // Modal appears...
      await expect(page.locator("#sap-modal")).toBeVisible({ timeout: 3000 });
      await expect(page.locator(".sap-modal-head")).toContainText("sensitive data detected");
      // ...and the site's send handler never fired.
      await expect(page.locator("#sent-log")).toHaveAttribute("data-sent", "0");
    });

    test("intercepts the send button click", async ({ page }) => {
      await loadFixture(page, server.url(ed.file));
      await ed.typeInto(page, `use ${AWS_KEY} to deploy`);
      await page.click(ed.sendButton);
      await expect(page.locator("#sap-modal")).toBeVisible({ timeout: 3000 });
      await expect(page.locator("#sent-log")).toHaveAttribute("data-sent", "0");
    });

    test("clean text sends without interception", async ({ page }) => {
      await loadFixture(page, server.url(ed.file));
      await ed.typeInto(page, "what is the capital of France?");
      await page.locator(ed.selector).press("Enter");
      await expect(page.locator("#sap-modal")).toHaveCount(0);
      await expect(page.locator("#sent-log")).toHaveAttribute("data-sent", "1");
    });

    test("'Redact for me' strips the secret from the editor", async ({ page }) => {
      await loadFixture(page, server.url(ed.file));
      await ed.typeInto(page, `use ${AWS_KEY} to deploy`);
      await page.locator(ed.selector).press("Enter");
      await page.click(".sap-btn-secondary"); // Redact for me
      const value = await page.locator(ed.selector).evaluate(
        (el) => (el.tagName === "TEXTAREA" ? el.value : el.innerText)
      );
      expect(value).not.toContain(AWS_KEY);
      expect(value).toContain("REDACTED");
    });
  });
}

test.describe("closed shadow root (attachShadow patch)", () => {
  test("main-world patch opens the root so the editor is discoverable", async ({ page }) => {
    await loadFixture(page, server.url("shadow-closed.html"), { mainWorldInject: true });
    // The patch should have converted the closed root to open.
    const mode = await page.evaluate(() => window.__shadowMode);
    expect(mode).toBe("open");
    // And the editor inside is scannable.
    const ed = page.locator(".ql-editor");
    await ed.click();
    await page.keyboard.insertText(`use ${AWS_KEY} now`);
    await expect(page.locator(".sap-blur.sap-block")).toHaveCount(1, { timeout: 3000 });
  });
});
