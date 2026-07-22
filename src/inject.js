/**
 * Secure AI Prompt — main-world injector.
 * Runs at document_start in the PAGE's world, before any site code.
 * Wraps attachShadow so closed shadow roots are created open, letting the
 * isolated-world content script discover editors inside them (Gemini).
 * The page behaves identically; only inspectability changes.
 */
(function () {
  "use strict";
  try {
    const orig = Element.prototype.attachShadow;
    if (!orig || orig.__sapPatched) return;
    const patched = function (init) {
      if (init && init.mode === "closed") {
        init = Object.assign({}, init, { mode: "open" });
      }
      return orig.call(this, init);
    };
    patched.__sapPatched = true;
    Object.defineProperty(Element.prototype, "attachShadow", {
      value: patched,
      writable: true,
      configurable: true,
    });
  } catch (_) {
    /* never break the host page */
  }
})();
