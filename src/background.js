/**
 * Secure AI Prompt — service worker.
 * Keeps the toolbar badge in sync and maintains a local, privacy-preserving
 * audit log (event counts + detector IDs only — never matched values).
 */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !sender.tab) return;

  if (msg.type === "findings-count") {
    const n = msg.count || 0;
    chrome.action.setBadgeText({ tabId: sender.tab.id, text: n ? String(n) : "" });
    chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: "#d64545" });
  }

  if (msg.type === "audit") {
    chrome.storage.local.get({ audit: [], stats: {} }, ({ audit, stats }) => {
      audit.push({
        ts: msg.ts,
        site: msg.site,
        action: msg.action,           // intercepted | redacted | overridden
        detectors: msg.detectors,     // e.g. ["aws-access-key-id"]
      });
      if (audit.length > 500) audit = audit.slice(-500);

      stats[msg.action] = (stats[msg.action] || 0) + 1;
      chrome.storage.local.set({ audit, stats });
    });
  }

  sendResponse && sendResponse({ ok: true });
  return false;
});

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === "install") {
    chrome.runtime.openOptionsPage();
  }
});
