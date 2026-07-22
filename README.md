# Secure AI Prompt — Enterprise Guardrail

A Manifest V3 Chrome extension that scans everything typed into web-based AI tools (ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek, Grok) **locally in the browser**. When it detects an API key, credential, internal hostname, private IP, connection string, payment card, or confidential code block, it blurs the value inline and intercepts the send action with a warning — before anything leaves the machine.

**Zero network calls. Zero telemetry. The extension requests only the `storage` permission.** This is the core sales argument to a CISO: the DLP layer itself cannot leak, because it has no way to phone home.

## Project layout

```
secure-ai-prompt/
├── manifest.json           MV3 manifest, host permissions per AI tool
├── managed_schema.json     Enterprise policy schema (Chrome managed storage)
├── icons/                  16/48/128 px toolbar icons
└── src/
    ├── detectors.js        Pure detection engine (regex + Luhn + Shannon entropy)
    ├── content.js          Editor watcher, blur overlay, send interception, modal
    ├── content.css         Overlay/modal styles (all sap- prefixed)
    ├── background.js       Badge counts + local audit log (counts only, never values)
    ├── popup.html/js       Status, stats, on/off toggle
    └── options.html/js     Mode, detector toggles, custom rules, allowlist
```

## How detection works

1. `content.js` discovers the prompt editor via per-site selectors (ChatGPT's `#prompt-textarea`, Claude's ProseMirror, Gemini's `rich-textarea`, plus generic `contenteditable[role=textbox]` and `textarea` fallbacks) and re-discovers on DOM mutation, so SPA navigation is handled.
2. On every input (debounced 200 ms) the full text is run through `SecurePromptDetect.scan()`:
   - **~25 named detectors**: AWS/GCP/Azure creds, OpenAI/Anthropic/GitHub/GitLab/Slack/Stripe/SendGrid/Twilio/npm tokens, PEM private keys, JWTs, DB connection strings, URLs with embedded credentials, password assignments, RFC1918 IPs, `.corp`/`.internal` hostnames, UNC share paths, Kubernetes Secret manifests, Luhn-validated card numbers.
   - **Entropy fallback**: 32+ char tokens with Shannon entropy ≥ 4.2 are flagged even if no named pattern matches — this catches company-specific secret formats.
   - **Code heuristic**: multi-line blocks with high code-punctuation density are flagged when they carry confidentiality markers (or always, in strict mode).
   - Overlapping findings are deduplicated; `block` severity beats `warn`.
3. Matches get a positioned **blur overlay** (backdrop-filter boxes computed from DOM Ranges for contenteditable, or a mirror-div for textareas).
4. Enter-to-send and send-button clicks are intercepted at **capture phase** before the site's own handlers. A synchronous rescan runs at interception time so paste-and-instantly-send can't race the debounce.
5. The modal offers **Edit message**, **Redact for me** (replaces each match with `[REDACTED:TYPE]`), and — if policy allows — **Send anyway**, which is recorded in the local audit log.

Enterprise policy (Chrome managed storage) always wins over user settings: IT can force `mode: "block"`, remove the override button, push company-specific regexes (project codenames, ticket formats), and lock the on/off switch.

---

## Complete process, start to end

### Phase 1 — Local development (day 1)

1. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select this folder.
2. Open chatgpt.com or claude.ai, paste a fake secret into the composer, e.g.:
   - `AKIAIOSFODNN7EXAMPLE`
   - `sk-ant-api03-fake1234567890abcdefghij`
   - `postgres://admin:hunter2@db.internal:5432/app`
3. Confirm: value blurs inline → pressing Enter or Send opens the warning modal → "Redact for me" swaps the value → badge shows the finding count.
4. After each code change, hit the reload icon on the extension card and refresh the AI tab.

**Debugging tips**
- Content script logs: the page's own DevTools console.
- Service worker logs: `chrome://extensions` → the extension card → "service worker" link.
- If a site redesign breaks editor discovery, add its new selector to `SITE_EDITOR_SELECTORS` — that's the only site-specific code.

### Phase 2 — Testing checklist (day 2–3)

- [ ] Each detector fires (drive `src/detectors.js` in Node — it's DOM-free and unit-testable: `node -e "global.self=global; require('./src/detectors.js'); console.log(SecurePromptDetect.scan('AKIAIOSFODNN7EXAMPLE',{}))"`)
- [ ] False-positive pass: paste ordinary prose, public code, UUIDs, docs — nothing should blur
- [ ] Placeholder pass: `password=${DB_PASSWORD}`, `sk-ant-EXAMPLE` in allowlist → clean
- [ ] Enter with Shift (newline) is never intercepted
- [ ] IME composition (`isComposing`) doesn't trigger interception mid-Japanese/Chinese input
- [ ] Redaction preserves the rest of the message on both textarea and ProseMirror editors
- [ ] Overlay tracks correctly while scrolling a long prompt, and disappears when text is cleared
- [ ] "Send anyway" allows exactly one acknowledged send, then re-arms on the next edit
- [ ] Toggle off in popup → protection stops immediately on the open tab
- [ ] Policy test (see Phase 5): managed `mode: "block"` removes the override button

### Phase 3 — Packaging (day 3)

```bash
cd secure-ai-prompt
zip -r ../secure-ai-prompt-v0.1.0.zip . -x "*.git*" -x "*.DS_Store"
```

Keep `manifest.json` `version` in lockstep with a git tag. Chrome Web Store rejects re-uploads of the same version number.

### Phase 4 — Chrome Web Store publication (week 1–2)

1. Register a developer account at the Chrome Web Store Developer Dashboard (one-time $5 fee). For an enterprise product, register with a company Google account, not a personal one.
2. Upload the zip. Fill in the listing: name, 132-char summary, detailed description, category (Productivity → Workflow), 1280×800 screenshots (show the blur + the warning modal — that IS the product), and a 440×280 promo tile.
3. **Privacy tab — this determines review speed.** Declare:
   - Single purpose: "Scans text entered into AI chat tools locally and warns before sensitive data is submitted."
   - Permission justifications: `storage` (user settings + local counters); each host permission ("the extension must read the prompt editor on this AI site to scan it").
   - Data usage: check **"does not collect user data"** — true here, and your biggest differentiator. You'll certify compliance with the Limited Use policy.
4. Add a hosted privacy policy URL (required). One page: what's scanned (locally), what's stored (settings + counts in Chrome storage), what's transmitted (nothing).
5. Choose visibility: **Unlisted** is ideal for enterprise sales — the extension is installable by anyone with the link (and force-installable by policy) but doesn't appear in search, so you control distribution to paying customers.
6. Submit for review. Extensions with narrow host permissions and no remote code typically clear review in a few days; broad `<all_urls>` requests take longer, which is why this manifest lists specific AI domains.

### Phase 5 — Enterprise deployment (the actual business)

This is why the extension has `managed_schema.json`. IT departments deploy it two ways:

**Google Admin console (managed Chrome browsers/ChromeOS)**
1. Admin console → Devices → Chrome → Apps & extensions → Users & browsers.
2. Add by extension ID (from your Web Store listing) → set to **Force install**.
3. In the extension's entry, paste the policy JSON (this maps to managed storage):

```json
{
  "enabled": { "Value": true },
  "mode": { "Value": "block" },
  "allowSendAnyway": { "Value": false },
  "customPatterns": {
    "Value": [
      { "label": "Project codename", "pattern": "\\bPROJECT-(ZEUS|ATLAS)\\b", "severity": "block" },
      { "label": "Internal ticket", "pattern": "\\bACME-INT-\\d+\\b", "severity": "warn" }
    ]
  }
}
```

**Windows Group Policy / registry** (for orgs not using Chrome Browser Cloud Management)
- Force-install: `HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist` → `"1" = "<extension-id>;https://clients2.google.com/service/update2/crx"`
- Policy: `HKLM\Software\Policies\Google\Chrome\3rdparty\extensions\<extension-id>\policy` with the same keys as above.
- macOS equivalent: a configuration profile setting `com.google.Chrome.extensions.<extension-id>`.

Users see the extension appear automatically, the popup shows "managed by your organization," and the enforced settings are greyed out. Edge supports the identical mechanism (`ExtensionInstallForcelist` under the Edge policy tree) since it's Chromium — one codebase covers both browsers most enterprises run.

### Phase 6 — Monetization reality check

A browser extension can't securely enforce a license client-side (anything in JS can be patched), and per Chrome Web Store policy you shouldn't try to gate it with obfuscated checks. The model that actually works for this product:

- **Sell the contract, not DRM.** Unlisted listing + annual per-seat agreement. The force-install list *is* your seat count; true-up annually like every other enterprise software vendor.
- **Free tier / paid tier split**: individual users get the extension free from a public listing (bottom-up adoption inside companies is your sales channel); enterprises pay for the managed-policy features, custom pattern packs, priority support, and — the big one — a future **reporting backend**.
- **The v2 upsell**: an optional, self-hosted reporting endpoint that receives the audit events (action + detector ID + site, never the matched values) so CISOs get a dashboard of near-misses per department. Keep it opt-in and policy-configured, and keep the scanning itself local — that's the trust story. Add it as a `reportingUrl` key in the managed schema when you build it.

### Phase 7 — Maintenance

- The only fragile surface is `SITE_EDITOR_SELECTORS` / `SEND_BUTTON_SELECTORS` — AI vendors redesign often. Keep a canary checklist and test the top 3 sites weekly; the generic `contenteditable[role=textbox]` fallback usually survives redesigns even when the specific selector dies.
- New secret formats: add to the `DETECTORS` array in `detectors.js`; keep an eye on the patterns used by gitleaks/trufflehog for inspiration on new token shapes.
- Version bumps auto-update within ~5 hours for all force-installed users — no IT action needed.

## Testing

Two layers, both run by `npm test`:

**Unit tests** (`test/detectors.test.js`, Node's built-in runner) exercise the detection engine directly — every detector has a positive case, plus false-positive guards (env-var placeholders, UUIDs, ordinary prose), Luhn validation, allowlist suppression, custom-pattern handling, entropy detection, and redaction. Fast and deterministic; no browser. Run alone with `npm run test:unit`.

**End-to-end tests** (`test/e2e/`, Playwright) are the important ones for durability. Each AI vendor renders its composer differently and redesigns it every few months, so the suite ships a fixture per editor **architecture** rather than per site:
- `textarea.html` — plain textarea (Perplexity, DeepSeek)
- `prosemirror.html` — contenteditable with the Enter handler registered on the editor element in capture phase (Claude, ChatGPT) — reproduces the registration-order race
- `quill.html` — `rich-textarea > ql-container > ql-editor`, created ~400ms after load (Gemini) — reproduces lazy editor creation
- `shadow-closed.html` — editor inside a closed shadow root — verifies the `attachShadow` patch

Each fixture records whether its own send handler fired, so the tests prove interception actually *blocked* the send rather than merely showing a dialog. The suite asserts, for every architecture: secret gets blurred while typing, Enter is intercepted and send is blocked, send-button click is intercepted, clean text passes through untouched, and "Redact for me" strips the secret from the editor.

The harness (`test/e2e/harness.js`) injects the real `src/` scripts into each fixture with a minimal `chrome.*` stub, so it tests genuine detection + DOM + interception logic without depending on live sites. Run alone with `npm run test:e2e`.

**Why this matters for the sale.** A DLP vendor who can show a green CI matrix across every editor architecture, re-run on every commit, is in a different credibility bracket than one who says "trust me, I tested it." The Gemini editor breaking mid-development is exactly the regression this suite catches in one second instead of a manual pass across eight sites. CI config is in `.github/workflows/test.yml`.

## Known limitations (be upfront in enterprise sales calls)

- File uploads and pasted images are not scanned (v1 is text only — image OCR is a meaningful v2 feature).
- Users can bypass by using a non-managed browser or the AI vendor's desktop app; position this as one layer alongside network DLP, not a replacement.
- Regex DLP has irreducible false positives/negatives; the entropy detector narrows but doesn't close the gap.
- Sites rendering the composer inside a closed shadow root would need a per-site adapter (none of the current 8 targets do).
