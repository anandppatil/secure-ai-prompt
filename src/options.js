const DEFAULTS = {
  mode: "warn",
  blurEnabled: true,
  entropy: true,
  detectCode: true,
  flagAllCode: false,
  disabledDetectors: [],
  customPatternsRaw: "",
  allowlistRaw: "",
};

const listEl = document.getElementById("detectorList");
const detectors = self.SecurePromptDetect.listDetectors();

for (const d of detectors) {
  const label = document.createElement("label");
  label.className = "opt";
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.dataset.id = d.id;
  const span = document.createElement("span");
  span.textContent = d.label;
  label.append(cb, span);
  listEl.appendChild(label);
}

let managedKeys = new Set();

chrome.storage.managed.get(null, (managed) => {
  if (!chrome.runtime.lastError && managed && Object.keys(managed).length) {
    managedKeys = new Set(Object.keys(managed));
    document.getElementById("managedBanner").style.display = "block";
  }
  load();
});

function load() {
  chrome.storage.sync.get(DEFAULTS, (cfg) => {
    document.querySelector(`input[name="mode"][value="${cfg.mode}"]`).checked = true;
    document.getElementById("blurEnabled").checked = cfg.blurEnabled;
    document.getElementById("entropy").checked = cfg.entropy;
    document.getElementById("detectCode").checked = cfg.detectCode;
    document.getElementById("flagAllCode").checked = cfg.flagAllCode;
    document.getElementById("customPatterns").value = cfg.customPatternsRaw;
    document.getElementById("allowlist").value = cfg.allowlistRaw;
    const disabled = new Set(cfg.disabledDetectors);
    listEl.querySelectorAll("input[data-id]").forEach((cb) => {
      cb.checked = !disabled.has(cb.dataset.id);
    });
    // Lock enterprise-enforced fields
    if (managedKeys.has("mode")) document.querySelectorAll('input[name="mode"]').forEach((r) => (r.disabled = true));
    for (const k of ["blurEnabled", "entropy", "detectCode", "flagAllCode"]) {
      if (managedKeys.has(k)) document.getElementById(k).disabled = true;
    }
  });
}

document.getElementById("save").addEventListener("click", () => {
  const customPatternsRaw = document.getElementById("customPatterns").value;
  const customPatterns = customPatternsRaw
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const idx = l.indexOf("::");
      if (idx === -1) return { label: "Custom rule", pattern: l, flags: "i" };
      return { label: l.slice(0, idx).trim(), pattern: l.slice(idx + 2).trim(), flags: "i" };
    });

  const allowlistRaw = document.getElementById("allowlist").value;
  const allowlist = allowlistRaw.split("\n").map((l) => l.trim()).filter(Boolean);

  const disabledDetectors = [];
  listEl.querySelectorAll("input[data-id]").forEach((cb) => {
    if (!cb.checked) disabledDetectors.push(cb.dataset.id);
  });

  chrome.storage.sync.set(
    {
      mode: document.querySelector('input[name="mode"]:checked').value,
      blurEnabled: document.getElementById("blurEnabled").checked,
      entropy: document.getElementById("entropy").checked,
      detectCode: document.getElementById("detectCode").checked,
      flagAllCode: document.getElementById("flagAllCode").checked,
      disabledDetectors,
      customPatterns,
      customPatternsRaw,
      allowlist,
      allowlistRaw,
    },
    () => {
      const note = document.getElementById("savedNote");
      note.classList.add("show");
      setTimeout(() => note.classList.remove("show"), 1500);
    }
  );
});
