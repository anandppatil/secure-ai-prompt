/**
 * Shared Playwright harness.
 *
 * The fixtures aren't on the extension's host-permission list, so instead of
 * loading the packaged extension we inject the real src/ scripts into each
 * fixture page and stub the handful of chrome.* APIs they call. This exercises
 * the genuine detection + DOM + interception logic — the fragile part — without
 * depending on live AI sites.
 */
const fs = require("fs");
const path = require("path");
const http = require("http");

const ROOT = path.resolve(__dirname, "..", "..");
const FIXTURES = path.join(__dirname, "..", "fixtures");

const detectorsSrc = fs.readFileSync(path.join(ROOT, "src", "detectors.js"), "utf8");
const injectSrc = fs.readFileSync(path.join(ROOT, "src", "inject.js"), "utf8");
const contentSrc = fs.readFileSync(path.join(ROOT, "src", "content.js"), "utf8");
const contentCss = fs.readFileSync(path.join(ROOT, "src", "content.css"), "utf8");

// Minimal chrome.* stub covering exactly what content.js touches.
const CHROME_STUB = `
  window.chrome = {
    storage: {
      sync:    { get: (d, cb) => cb(typeof d === 'object' && !Array.isArray(d) ? d : {}) },
      managed: { get: (d, cb) => cb({}) },
      local:   { get: (d, cb) => cb(typeof d === 'object' ? d : {}), set: () => {} },
      onChanged: { addListener: () => {} },
    },
    runtime: {
      sendMessage: () => {},
      lastError: null,
    },
  };
`;

/** Start a tiny static server for the fixtures dir. Returns { url, close }. */
function startFixtureServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const name = decodeURIComponent(req.url.split("?")[0]).replace(/^\//, "");
      const file = path.join(FIXTURES, name);
      if (!file.startsWith(FIXTURES) || !fs.existsSync(file)) {
        res.writeHead(404); res.end("not found"); return;
      }
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(fs.readFileSync(file));
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        url: (f) => `http://127.0.0.1:${port}/${f}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

/**
 * Load a fixture with the extension logic injected.
 * mainWorldInject=true runs inject.js at document_start-equivalent timing
 * (before the page's own script) — needed for the closed-shadow-root fixture.
 */
async function loadFixture(page, url, { mainWorldInject = false } = {}) {
  // inject.js must run before page scripts to patch attachShadow in time.
  if (mainWorldInject) {
    await page.addInitScript({ content: injectSrc });
  }
  // chrome stub + detectors must exist before content.js runs.
  await page.addInitScript({ content: CHROME_STUB });
  await page.addInitScript({ content: detectorsSrc });

  await page.goto(url);

  // Inject the CSS and content script after the DOM is present.
  await page.addStyleTag({ content: contentCss });
  await page.addScriptTag({ content: contentSrc });
}

module.exports = { startFixtureServer, loadFixture };
