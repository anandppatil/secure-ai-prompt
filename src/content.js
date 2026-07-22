/**
 * Secure AI Prompt — content script.
 * Watches the AI tool's prompt editor, scans locally as the user types,
 * blurs detected secrets with a positioned overlay, and intercepts send.
 * Zero network calls. All state stays in this tab + chrome.storage.
 */
(function () {
  "use strict";

  const Detect = self.SecurePromptDetect;
  if (!Detect) return;

  // --------------------------------------------------------------------------
  // Settings (defaults → sync storage → managed/enterprise storage wins)
  // --------------------------------------------------------------------------
  const settings = {
    enabled: true,
    mode: "warn",            // "warn" (can override) | "block" (cannot send with block-severity findings)
    allowSendAnyway: true,   // enterprise can set false
    blurEnabled: true,
    detectCode: true,
    flagAllCode: false,
    entropy: true,
    disabledDetectors: [],
    customPatterns: [],
    allowlist: [],
  };

  let ready = false;

  function loadSettings() {
    return new Promise((resolve) => {
      chrome.storage.sync.get(null, (userCfg) => {
        Object.assign(settings, sanitize(userCfg));
        chrome.storage.managed.get(null, (managedCfg) => {
          if (!chrome.runtime.lastError && managedCfg) {
            Object.assign(settings, sanitize(managedCfg)); // enterprise policy wins
          }
          ready = true;
          resolve();
        });
      });
    });
  }

  function sanitize(cfg) {
    const out = {};
    if (!cfg) return out;
    for (const k of Object.keys(settings)) {
      if (cfg[k] !== undefined) out[k] = cfg[k];
    }
    return out;
  }

  chrome.storage.onChanged.addListener(() => loadSettings().then(rescanAll));

  // --------------------------------------------------------------------------
  // Editor discovery — site adapters + generic fallback
  // --------------------------------------------------------------------------
  const SITE_EDITOR_SELECTORS = [
    "div#prompt-textarea[contenteditable='true']",       // ChatGPT
    "div.ProseMirror[contenteditable='true']",           // Claude, ChatGPT (new)
    "rich-textarea .ql-editor[contenteditable='true']",  // Gemini (confirmed: ql-container > ql-editor)
    "rich-textarea div[contenteditable='true']",         // Gemini fallback
    "div.ql-editor[contenteditable='true']",             // Quill editor, any host
    "textarea#copilot-chat-textarea",                    // Copilot
    "textarea[placeholder]",                             // Perplexity, DeepSeek, generic
    "div[contenteditable='true'][role='textbox']",       // generic
    "div[contenteditable='true']",                       // last-resort fallback (safe: extension only runs on AI domains)
  ];

  const SEND_BUTTON_SELECTORS = [
    "button[data-testid='send-button']",
    "button[aria-label*='Send' i]",
    "button[aria-label*='Submit' i]",
    "button.send-button",                    // Gemini
    "button[mattooltip*='Send' i]",          // Gemini (Angular Material tooltip)
    "button[type='submit']",
  ];

  const tracked = new WeakSet();

  const observedShadowRoots = new WeakSet();

  function discoverEditors(root) {
    if (!root.querySelectorAll) return;
    for (const sel of SITE_EDITOR_SELECTORS) {
      root.querySelectorAll(sel).forEach(attach);
    }
    // Pierce open shadow roots — Gemini's <rich-textarea> renders the editable
    // div inside a shadow tree that querySelectorAll cannot reach from outside.
    for (const el of root.querySelectorAll("*")) {
      if (el.shadowRoot) {
        if (!observedShadowRoots.has(el.shadowRoot)) {
          observedShadowRoots.add(el.shadowRoot);
          try {
            observer.observe(el.shadowRoot, { childList: true, subtree: true });
          } catch (_) {}
        }
        discoverEditors(el.shadowRoot);
      }
    }
  }

  const observer = new MutationObserver((muts) => {
    for (const mut of muts) {
      for (const node of mut.addedNodes) {
        if (node.nodeType !== 1) continue;
        // The inserted node may BE the editor (querySelectorAll only finds descendants)
        for (const sel of SITE_EDITOR_SELECTORS) {
          if (node.matches && node.matches(sel)) attach(node);
        }
        discoverEditors(node);
      }
    }
  });

  // Belt-and-braces: SPA frameworks sometimes swap editors in ways that dodge
  // the observer (e.g. reattached nodes). A cheap periodic rescan guarantees
  // recovery within 1.5s. attach() is idempotent via the WeakSet.
  setInterval(() => { if (settings.enabled) discoverEditors(document); }, 1500);

  // Focus-based discovery: whatever the user actually types into gets attached,
  // even if no CSS selector named it. composedPath()[0] pierces shadow retarget.
  document.addEventListener("focusin", (e) => {
    if (!settings.enabled) return;
    const t = (e.composedPath && e.composedPath()[0]) || e.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.tagName === "TEXTAREA" || t.isContentEditable) {
      // Attach to the top-most contenteditable ancestor (Quill's .ql-editor),
      // not a nested formatting span.
      let editable = t;
      let p = t.parentElement;
      while (p && p.isContentEditable) { editable = p; p = p.parentElement; }
      attach(editable);
    }
  }, true);

  // --------------------------------------------------------------------------
  // Per-editor state
  // --------------------------------------------------------------------------
  const editorState = new Map(); // element -> { findings, overlay, acknowledged, lastText }

  function attach(el) {
    if (tracked.has(el)) return;
    if (!(el instanceof HTMLElement)) return;
    tracked.add(el);
    console.debug("[Secure AI Prompt] attached to editor:", el.tagName, el.className && String(el.className).slice(0, 60), el.getRootNode() instanceof ShadowRoot ? "(in shadow root)" : "");
    editorState.set(el, { findings: [], overlay: null, acknowledged: false, lastText: "" });

    const onInput = debounce(() => scanEditor(el), 200);
    el.addEventListener("input", onInput);
    el.addEventListener("scroll", () => positionOverlay(el), { passive: true });

    scanEditor(el);
  }

  // Intercept Enter-to-send at the DOCUMENT level in capture phase. This is
  // critical: capture listeners on the target element itself fire in
  // registration order against the site's own handlers (ProseMirror on
  // claude.ai registers first and wins). A document-level capture listener
  // always fires before any element-level handler, regardless of order.
  document.addEventListener("keydown", (e) => {
    if (!settings.enabled) return;
    if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
    // composedPath()[0] is the true innermost target; e.target is retargeted
    // to the shadow host when the editor lives inside a shadow root (Gemini).
    const realTarget = e.composedPath ? e.composedPath()[0] : e.target;
    const editor = findTrackedEditor(realTarget);
    if (editor && maybeIntercept(editor)) {
      e.preventDefault();
      e.stopImmediatePropagation();
      e.stopPropagation();
    }
  }, true);

  function findTrackedEditor(node) {
    if (!node) return null;
    for (const [el] of editorState) {
      if (el === node || (el.contains && el.contains(node))) return el;
    }
    return null;
  }

  // Intercept clicks on send buttons anywhere in the document (capture phase).
  document.addEventListener("click", (e) => {
    if (!settings.enabled) return;
    const sendSel = SEND_BUTTON_SELECTORS.join(",");
    const path = e.composedPath ? e.composedPath() : [e.target];
    let btn = null;
    for (const n of path) {
      if (n instanceof Element && n.matches && n.matches(sendSel)) { btn = n; break; }
      if (n === document) break;
    }
    if (!btn) return;
    const editor = nearestEditor(btn);
    if (editor && maybeIntercept(editor)) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);

  function nearestEditor(btn) {
    // Prefer an editor in the same form/composer container; else any tracked one with findings.
    let scope = btn.closest("form, [class*='composer'], [class*='input']") || document;
    for (const [el] of editorState) {
      if (scope.contains(el)) return el;
    }
    for (const [el, st] of editorState) {
      if (st.findings.length) return el;
    }
    return null;
  }

  // --------------------------------------------------------------------------
  // Scanning
  // --------------------------------------------------------------------------
  function editorText(el) {
    return el.tagName === "TEXTAREA" ? el.value : el.innerText || "";
  }

  function scanEditor(el) {
    if (!ready || !settings.enabled) return;
    const st = editorState.get(el);
    if (!st) return;
    const text = editorText(el);
    if (text === st.lastText) return;
    st.lastText = text;
    st.acknowledged = false;

    st.findings = Detect.scan(text, settings);
    updateBadge();
    renderOverlay(el);
  }

  function rescanAll() {
    for (const [el, st] of editorState) {
      st.lastText = "";
      scanEditor(el);
    }
  }

  function updateBadge() {
    let n = 0;
    for (const [, st] of editorState) n += st.findings.length;
    try {
      chrome.runtime.sendMessage({ type: "findings-count", count: n });
    } catch (_) { /* extension reloaded */ }
  }

  // --------------------------------------------------------------------------
  // Blur overlay — positioned boxes over each finding's client rects
  // --------------------------------------------------------------------------
  function renderOverlay(el) {
    const st = editorState.get(el);
    if (!st) return;
    if (st.overlay) { st.overlay.remove(); st.overlay = null; }
    if (!settings.blurEnabled || !st.findings.length) return;

    const overlay = document.createElement("div");
    overlay.className = "sap-overlay";
    document.documentElement.appendChild(overlay);
    st.overlay = overlay;
    positionOverlay(el);
  }

  function positionOverlay(el) {
    const st = editorState.get(el);
    if (!st || !st.overlay) return;
    st.overlay.textContent = "";
    const rects = findingRects(el, st.findings);
    const hostRect = el.getBoundingClientRect();
    for (const { rect, severity, label } of rects) {
      // Clip to editor viewport so scrolled-away matches don't float over the page
      if (rect.bottom < hostRect.top || rect.top > hostRect.bottom) continue;
      const box = document.createElement("div");
      box.className = "sap-blur sap-" + severity;
      box.title = "Secure AI Prompt: " + label;
      box.style.left = rect.left + "px";
      box.style.top = rect.top + "px";
      box.style.width = Math.max(rect.width, 8) + "px";
      box.style.height = rect.height + "px";
      st.overlay.appendChild(box);
    }
  }

  window.addEventListener("scroll", () => { for (const [el] of editorState) positionOverlay(el); }, { passive: true, capture: true });
  window.addEventListener("resize", () => { for (const [el] of editorState) positionOverlay(el); }, { passive: true });

  function findingRects(el, findings) {
    const out = [];
    if (el.tagName === "TEXTAREA") {
      // Mirror technique for textarea
      const mirror = getMirror(el);
      mirror.textContent = "";
      const text = el.value;
      let cursor = 0;
      const spans = [];
      for (const f of findings) {
        mirror.appendChild(document.createTextNode(text.slice(cursor, f.start)));
        const s = document.createElement("span");
        s.textContent = text.slice(f.start, f.end);
        mirror.appendChild(s);
        spans.push({ s, f });
        cursor = f.end;
      }
      mirror.appendChild(document.createTextNode(text.slice(cursor)));
      const taRect = el.getBoundingClientRect();
      const mRect = mirror.getBoundingClientRect();
      for (const { s, f } of spans) {
        for (const r of s.getClientRects()) {
          out.push({
            rect: new DOMRect(
              r.left - mRect.left + taRect.left - el.scrollLeft,
              r.top - mRect.top + taRect.top - el.scrollTop,
              r.width, r.height
            ),
            severity: f.severity, label: f.label,
          });
        }
      }
    } else {
      // contenteditable: walk text nodes and build Ranges at flat-text offsets
      const map = buildTextNodeMap(el);
      for (const f of findings) {
        const range = rangeFromOffsets(map, f.start, f.end);
        if (!range) continue;
        for (const r of range.getClientRects()) {
          out.push({ rect: r, severity: f.severity, label: f.label });
        }
      }
    }
    return out;
  }

  function buildTextNodeMap(root) {
    // innerText normalizes newlines per block; approximate with a walker that
    // inserts "\n" between block-level boundaries, matching editorText() closely
    // enough for highlight purposes.
    const map = [];
    let offset = 0;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;
    let prevBlock = null;
    while ((node = walker.nextNode())) {
      const block = node.parentElement && node.parentElement.closest("p, div, li, pre");
      if (prevBlock && block !== prevBlock) offset += 1; // the "\n" innerText adds
      prevBlock = block;
      map.push({ node, start: offset, end: offset + node.data.length });
      offset += node.data.length;
    }
    return map;
  }

  function rangeFromOffsets(map, start, end) {
    let sNode = null, sOff = 0, eNode = null, eOff = 0;
    for (const item of map) {
      if (!sNode && start >= item.start && start <= item.end) {
        sNode = item.node; sOff = start - item.start;
      }
      if (end >= item.start && end <= item.end) {
        eNode = item.node; eOff = end - item.start;
      }
    }
    if (!sNode || !eNode) return null;
    try {
      const range = document.createRange();
      range.setStart(sNode, Math.min(sOff, sNode.data.length));
      range.setEnd(eNode, Math.min(eOff, eNode.data.length));
      return range;
    } catch (_) { return null; }
  }

  let mirrorEl = null;
  function getMirror(ta) {
    if (!mirrorEl) {
      mirrorEl = document.createElement("div");
      mirrorEl.className = "sap-mirror";
      document.documentElement.appendChild(mirrorEl);
    }
    const cs = getComputedStyle(ta);
    for (const p of ["fontFamily","fontSize","fontWeight","lineHeight","letterSpacing","padding","border","boxSizing","whiteSpace","wordWrap","overflowWrap","width"]) {
      mirrorEl.style[p] = cs[p];
    }
    mirrorEl.style.width = ta.clientWidth + "px";
    return mirrorEl;
  }

  // --------------------------------------------------------------------------
  // Send interception + warning modal
  // --------------------------------------------------------------------------
  function maybeIntercept(el) {
    if (!settings.enabled) return false;
    const st = editorState.get(el);
    if (!st) return false;
    // Re-scan synchronously so a fast paste-and-enter can't race the debounce
    st.lastText = "";
    st.acknowledged || scanEditorSync(el);
    if (!st.findings.length || st.acknowledged) return false;
    showModal(el, st);
    logEvent("intercepted", st.findings);
    return true;
  }

  function scanEditorSync(el) {
    const st = editorState.get(el);
    const text = editorText(el);
    st.lastText = text;
    st.findings = Detect.scan(text, settings);
    renderOverlay(el);
    updateBadge();
  }

  function showModal(el, st) {
    closeModal();
    const blockers = st.findings.filter((f) => f.severity === "block");
    const hardBlock = settings.mode === "block" && blockers.length > 0;
    const canOverride = settings.allowSendAnyway && !hardBlock;

    const wrap = document.createElement("div");
    wrap.className = "sap-modal-backdrop";
    wrap.id = "sap-modal";

    const card = document.createElement("div");
    card.className = "sap-modal";
    card.setAttribute("role", "alertdialog");
    card.setAttribute("aria-label", "Sensitive data detected");

    const h = document.createElement("div");
    h.className = "sap-modal-head";
    const shield = document.createElement("span");
    shield.className = "sap-shield";
    shield.textContent = "\u25CF";
    const htext = document.createElement("span");
    htext.textContent = hardBlock ? "Sending blocked by company policy" : "Hold on — sensitive data detected";
    h.append(shield, htext);
    card.appendChild(h);

    const p = document.createElement("p");
    p.className = "sap-modal-sub";
    p.textContent =
      "Your prompt contains " + st.findings.length +
      (st.findings.length === 1 ? " item" : " items") +
      " that may violate your organization's data handling policy. Scanning happened locally — nothing has left your browser.";
    card.appendChild(p);

    const list = document.createElement("ul");
    list.className = "sap-findings";
    for (const f of st.findings.slice(0, 12)) {
      const li = document.createElement("li");
      const sev = document.createElement("span");
      sev.className = "sap-sev sap-sev-" + f.severity;
      sev.textContent = f.severity === "block" ? "secret" : "review";
      const lbl = document.createElement("span");
      lbl.className = "sap-lbl";
      lbl.textContent = f.label;
      const prev = document.createElement("code");
      prev.className = "sap-preview";
      prev.textContent = preview(f.match);
      li.append(sev, lbl, prev);
      list.appendChild(li);
    }
    if (st.findings.length > 12) {
      const li = document.createElement("li");
      li.className = "sap-more";
      li.textContent = "+ " + (st.findings.length - 12) + " more";
      list.appendChild(li);
    }
    card.appendChild(list);

    const actions = document.createElement("div");
    actions.className = "sap-actions";

    const editBtn = btn("Edit message", "sap-btn-primary", () => {
      closeModal();
      el.focus();
    });

    const redactBtn = btn("Redact for me", "sap-btn-secondary", () => {
      applyRedaction(el, st);
      closeModal();
      el.focus();
      logEvent("redacted", st.findings);
    });

    actions.append(editBtn, redactBtn);

    if (canOverride) {
      const sendBtn = btn("Send anyway", "sap-btn-ghost", () => {
        st.acknowledged = true;
        closeModal();
        logEvent("overridden", st.findings);
        // Re-dispatch: user must press send again; safest cross-site behavior.
        toast("Warning acknowledged — press send again to submit.");
      });
      actions.appendChild(sendBtn);
    }

    card.appendChild(actions);
    wrap.appendChild(card);
    wrap.addEventListener("click", (e) => { if (e.target === wrap) closeModal(); });
    document.documentElement.appendChild(wrap);
    editBtn.focus();
    document.addEventListener("keydown", escClose, true);
  }

  function escClose(e) { if (e.key === "Escape") { closeModal(); } }
  function closeModal() {
    const m = document.getElementById("sap-modal");
    if (m) m.remove();
    document.removeEventListener("keydown", escClose, true);
  }

  function btn(text, cls, onClick) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "sap-btn " + cls;
    b.textContent = text;
    b.addEventListener("click", onClick);
    return b;
  }

  function preview(s) {
    if (!s) return "";
    const clean = s.replace(/\s+/g, " ").trim();
    if (clean.length <= 24) return clean;
    return clean.slice(0, 8) + "…" + clean.slice(-6);
  }

  function applyRedaction(el, st) {
    const text = editorText(el);
    const redacted = Detect.redact(text, st.findings);
    if (el.tagName === "TEXTAREA") {
      const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
      setter.call(el, redacted);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    } else {
      // contenteditable: replace content preserving simple line structure
      el.focus();
      const sel = window.getSelection();
      sel.selectAllChildren(el);
      document.execCommand("insertText", false, redacted);
    }
    scanEditorSync(el);
  }

  function toast(msg) {
    const t = document.createElement("div");
    t.className = "sap-toast";
    t.textContent = msg;
    document.documentElement.appendChild(t);
    setTimeout(() => t.remove(), 3500);
  }

  // --------------------------------------------------------------------------
  // Local audit log (counts only — never the secret values)
  // --------------------------------------------------------------------------
  function logEvent(action, findings) {
    try {
      chrome.runtime.sendMessage({
        type: "audit",
        action,
        site: location.hostname,
        detectors: findings.map((f) => f.detector),
        ts: Date.now(),
      });
    } catch (_) {}
  }

  function debounce(fn, ms) {
    let t;
    return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  }

  // --------------------------------------------------------------------------
  // Boot
  // --------------------------------------------------------------------------
  loadSettings().then(() => {
    console.debug("[Secure AI Prompt] active on", location.hostname, "frame:", window === top ? "top" : "iframe");
    discoverEditors(document);
    observer.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => {
      let n = 0; editorState.forEach(() => n++);
      console.debug("[Secure AI Prompt] editors tracked after 5s:", n);
    }, 5000);
  });
})();
