/**
 * Secure AI Prompt — detection engine.
 * Pure functions, no network, no DOM. Loaded before content.js.
 *
 * A "finding" = { id, detector, label, severity, start, end, match, redaction }
 * severity: "block" (secrets) | "warn" (suspicious) — enterprise policy can promote/demote.
 */
(function (global) {
  "use strict";

  // ---------------------------------------------------------------------------
  // Built-in detectors. Each: { id, label, severity, regex, validate?, redact? }
  // Regexes use the 'g' flag; scan() re-instantiates so state never leaks.
  // ---------------------------------------------------------------------------
  const DETECTORS = [
    // --- Cloud provider credentials -----------------------------------------
    {
      id: "aws-access-key-id",
      label: "AWS Access Key ID",
      severity: "block",
      regex: /\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b/g,
    },
    {
      id: "aws-secret-key",
      label: "AWS Secret Access Key",
      severity: "block",
      regex: /(?:aws|secret)[\w.\-]{0,20}["'\s:=]{1,4}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
      group: 1,
    },
    {
      id: "gcp-api-key",
      label: "Google API key",
      severity: "block",
      regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    },
    {
      id: "gcp-service-account",
      label: "GCP service account JSON",
      severity: "block",
      regex: /"private_key_id"\s*:\s*"[a-f0-9]{40}"/g,
    },
    {
      id: "azure-conn-string",
      label: "Azure connection string",
      severity: "block",
      regex: /(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{40,}/g,
    },

    // --- AI / SaaS API keys --------------------------------------------------
    {
      id: "openai-key",
      label: "OpenAI API key",
      severity: "block",
      regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9\-_]{20,}\b/g,
      validate: (m) => !/^sk-ant-/.test(m),
    },
    {
      id: "anthropic-key",
      label: "Anthropic API key",
      severity: "block",
      regex: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/g,
    },
    {
      id: "github-token",
      label: "GitHub token",
      severity: "block",
      regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g,
    },
    {
      id: "gitlab-token",
      label: "GitLab token",
      severity: "block",
      regex: /\bglpat-[A-Za-z0-9\-_]{20,}\b/g,
    },
    {
      id: "slack-token",
      label: "Slack token",
      severity: "block",
      regex: /\bxox[baprs]-[A-Za-z0-9\-]{10,}\b/g,
    },
    {
      id: "slack-webhook",
      label: "Slack webhook URL",
      severity: "block",
      regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g,
    },
    {
      id: "stripe-key",
      label: "Stripe live key",
      severity: "block",
      regex: /\b[rs]k_live_[A-Za-z0-9]{20,}\b/g,
    },
    {
      id: "sendgrid-key",
      label: "SendGrid API key",
      severity: "block",
      regex: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/g,
    },
    {
      id: "twilio-key",
      label: "Twilio API key",
      severity: "block",
      regex: /\bSK[a-f0-9]{32}\b/g,
    },
    {
      id: "npm-token",
      label: "npm token",
      severity: "block",
      regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    },

    // --- Generic secret shapes ----------------------------------------------
    {
      id: "private-key-block",
      label: "Private key (PEM)",
      severity: "block",
      regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----|$)/g,
    },
    {
      id: "jwt",
      label: "JWT (signed token)",
      severity: "block",
      regex: /\beyJ[A-Za-z0-9\-_]{8,}\.eyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\b/g,
    },
    {
      id: "connection-string",
      label: "Database connection string with credentials",
      severity: "block",
      regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql|jdbc:[a-z]+):\/\/[^\s:@/]+:[^\s@/]+@[^\s/]+/gi,
    },
    {
      id: "basic-auth-url",
      label: "URL with embedded credentials",
      severity: "block",
      regex: /\bhttps?:\/\/[^\s:@/]+:[^\s@/]+@[^\s/]+/gi,
    },
    {
      id: "password-assignment",
      label: "Password / secret assignment",
      severity: "warn",
      regex: /\b(?:password|passwd|pwd|api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']?([^\s"']{8,})/gi,
      group: 1,
      validate: (m) => !/^(?:\$\{|\$[A-Z_]|<|%|process\.env|os\.environ|env\(|getenv|\*{3,}|x{4,}|your[-_]?|changeme|placeholder|redacted|example)/i.test(m),
    },

    // --- Internal infrastructure --------------------------------------------
    {
      id: "internal-hostname",
      label: "Internal hostname",
      severity: "warn",
      regex: /\b[a-z0-9][a-z0-9\-.]*\.(?:internal|corp|intranet|lan|local|private|prod\.internal)\b(?:[:/][^\s]*)?/gi,
    },
    {
      id: "private-ip",
      label: "Private / internal IP address",
      severity: "warn",
      regex: /\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.\d{1,3}|192\.168\.(?:\d{1,3})\.\d{1,3})\b(?::\d{2,5})?/g,
    },
    {
      id: "unc-path",
      label: "Internal file share path",
      severity: "warn",
      regex: /\\\\[a-z0-9\-._]+\\[^\s"']+/gi,
    },
    {
      id: "kube-secret",
      label: "Kubernetes secret manifest",
      severity: "block",
      regex: /kind:\s*Secret[\s\S]{0,400}?data:/g,
    },

    // --- People data ---------------------------------------------------------
    {
      id: "credit-card",
      label: "Payment card number",
      severity: "block",
      regex: /\b(?:\d[ -]?){13,16}\b/g,
      validate: luhnCheck,
    },
    {
      id: "email-bulk",
      label: "Bulk email addresses (3+)",
      severity: "warn",
      regex: /(?:[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}[\s,;]+){2,}[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi,
    },
  ];

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------
  function luhnCheck(raw) {
    const digits = raw.replace(/[ -]/g, "");
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0, alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (d < 0 || d > 9) return false;
      if (alt) { d *= 2; if (d > 9) d -= 9; }
      sum += d; alt = !alt;
    }
    return sum % 10 === 0;
  }

  function shannonEntropy(s) {
    const freq = Object.create(null);
    for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
    let e = 0;
    for (const k in freq) {
      const p = freq[k] / s.length;
      e -= p * Math.log2(p);
    }
    return e;
  }

  /**
   * High-entropy string detector — catches secrets no regex knows about.
   * Long base64/hex-ish tokens with entropy above threshold.
   */
  function entropyScan(text, findings) {
    const re = /\b[A-Za-z0-9+/=_\-]{32,}\b/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const s = m[0];
      // Skip things that are clearly words/UUID-with-dashes/URLs already matched
      if (/^[a-z]+$/i.test(s)) continue;
      if (!/\d/.test(s)) continue;
      const ent = shannonEntropy(s);
      if (ent >= 4.2) {
        findings.push(mkFinding("high-entropy", "High-entropy string (possible secret)", "warn", m.index, m.index + s.length, s));
      }
    }
  }

  /**
   * Proprietary code heuristic: multi-line block with code punctuation density
   * plus confidentiality markers or company-internal package roots.
   */
  function codeBlockScan(text, findings, opts) {
    if (!opts.detectCode) return;
    const marker = /(?:proprietary|confidential|internal use only|do not distribute|copyright\s+\(c\)|all rights reserved)/i;
    const lines = text.split("\n");
    if (lines.length < (opts.codeMinLines || 8)) {
      // Still flag if an explicit confidentiality marker exists
      const mm = marker.exec(text);
      if (mm) {
        findings.push(mkFinding("confidential-marker", "Confidentiality marker in text", "warn", mm.index, mm.index + mm[0].length, mm[0]));
      }
      return;
    }
    let codey = 0;
    for (const ln of lines) {
      if (/[{};]|=>|\breturn\b|\bdef\b|\bclass\b|\bimport\b|\bfunc\b|\bpublic\b|#include/.test(ln)) codey++;
    }
    if (codey / lines.length >= 0.4) {
      const hasMarker = marker.test(text);
      if (hasMarker || opts.flagAllCode) {
        findings.push(mkFinding(
          "proprietary-code",
          hasMarker ? "Code block with confidentiality marker" : "Large code block (check company policy)",
          "warn", 0, Math.min(text.length, 200), lines.slice(0, 2).join("\n")
        ));
      }
    }
  }

  let seq = 0;
  function mkFinding(detector, label, severity, start, end, match) {
    return {
      id: "f" + (++seq) + "-" + Date.now().toString(36),
      detector, label, severity, start, end, match,
      redaction: "[REDACTED:" + detector.toUpperCase() + "]",
    };
  }

  function compileCustom(customPatterns) {
    const out = [];
    for (const p of customPatterns || []) {
      try {
        out.push({
          id: "custom-" + (p.id || p.label || "rule"),
          label: p.label || "Custom rule",
          severity: p.severity === "block" ? "block" : "warn",
          regex: new RegExp(p.pattern, p.flags && p.flags.includes("i") ? "gi" : "g"),
        });
      } catch (_) { /* invalid enterprise regex — skip, never crash the page */ }
    }
    return out;
  }

  /**
   * Main entry. Returns deduplicated, sorted findings.
   * opts: { disabledDetectors: [], customPatterns: [], allowlist: [],
   *         detectCode: bool, flagAllCode: bool, entropy: bool }
   */
  function scan(text, opts) {
    opts = opts || {};
    const findings = [];
    if (!text || text.length < 8) return findings;
    const disabled = new Set(opts.disabledDetectors || []);
    const allow = (opts.allowlist || []).filter(Boolean);

    const all = DETECTORS.concat(compileCustom(opts.customPatterns));
    for (const d of all) {
      if (disabled.has(d.id)) continue;
      const re = new RegExp(d.regex.source, d.regex.flags);
      let m;
      let guard = 0;
      while ((m = re.exec(text)) !== null && guard++ < 500) {
        if (m.index === re.lastIndex) re.lastIndex++; // zero-width safety
        const whole = m[0];
        const captured = d.group ? m[d.group] : whole;
        if (!captured) continue;
        if (d.validate && !d.validate(captured)) continue;
        if (allow.some((a) => captured.includes(a))) continue;
        const offset = d.group ? m.index + whole.indexOf(captured) : m.index;
        findings.push(mkFinding(d.id, d.label, d.severity, offset, offset + captured.length, captured));
      }
    }

    if (opts.entropy !== false) entropyScan(text, findings);
    codeBlockScan(text, findings, opts);

    // Dedupe overlapping findings — keep the more severe / longer one.
    findings.sort((a, b) => a.start - b.start || b.end - a.end);
    const kept = [];
    for (const f of findings) {
      const prev = kept[kept.length - 1];
      if (prev && f.start < prev.end) {
        if (f.severity === "block" && prev.severity !== "block") kept[kept.length - 1] = f;
        continue;
      }
      kept.push(f);
    }
    return kept;
  }

  function redact(text, findings) {
    let out = "";
    let cursor = 0;
    for (const f of findings) {
      if (f.detector === "proprietary-code" || f.detector === "confidential-marker") continue;
      if (f.start < cursor) continue;
      out += text.slice(cursor, f.start) + f.redaction;
      cursor = f.end;
    }
    return out + text.slice(cursor);
  }

  global.SecurePromptDetect = {
    scan,
    redact,
    listDetectors: () => DETECTORS.map((d) => ({ id: d.id, label: d.label, severity: d.severity })),
  };
})(typeof self !== "undefined" ? self : globalThis);
