const toggle = document.getElementById("enabledToggle");
const dot = document.getElementById("statusDot");

chrome.storage.sync.get({ enabled: true }, ({ enabled }) => {
  toggle.checked = enabled;
  dot.classList.toggle("off", !enabled);
});

chrome.storage.managed.get(null, (managed) => {
  if (!chrome.runtime.lastError && managed && Object.keys(managed).length) {
    document.getElementById("managedNote").style.display = "block";
    if (managed.enabled !== undefined) {
      toggle.checked = managed.enabled;
      toggle.disabled = true;
    }
  }
});

toggle.addEventListener("change", () => {
  chrome.storage.sync.set({ enabled: toggle.checked });
  dot.classList.toggle("off", !toggle.checked);
});

chrome.storage.local.get({ stats: {} }, ({ stats }) => {
  document.getElementById("statIntercepted").textContent = stats.intercepted || 0;
  document.getElementById("statRedacted").textContent = stats.redacted || 0;
  document.getElementById("statOverridden").textContent = stats.overridden || 0;
});

document.getElementById("openOptions").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});
