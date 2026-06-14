/* =========================================================
   PhishShield AI — URL analysis engine
   A transparent, rule-based heuristic scanner. Every check
   below is documented on the "How It Works" page so results
   can always be explained.
   ========================================================= */

/* ---------- Reference data ---------- */

// Top-level domains that are frequently abused for throwaway /
// free phishing domains. Not proof of anything on their own,
// but a useful signal combined with other checks.
const SUSPICIOUS_TLDS = [
  "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
  "loan", "men", "pw", "rest", "icu", "cam", "cyou", "quest", "live"
];

// Common URL-shortening services. These hide the real
// destination until after a click.
const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "cutt.ly", "tiny.cc", "rebrand.ly", "shorturl.at",
  "rb.gy", "s.id", "bl.ink"
];

// Keywords that frequently appear in phishing landing-page
// paths/queries (account takeover, "verify your details" etc.)
const SUSPICIOUS_KEYWORDS = [
  "login", "log-in", "signin", "sign-in", "verify", "secure",
  "account", "update", "confirm", "password", "unlock", "billing", "wallet"
];

// A short list of frequently-impersonated brands mapped to
// their real registrable domains. If the brand name shows up
// in the hostname but the domain isn't one of these, that's
// a strong typosquatting / impersonation signal.
const BRAND_DOMAINS = {
  paypal: ["paypal.com"],
  google: ["google.com"],
  microsoft: ["microsoft.com", "live.com", "office.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com"],
  facebook: ["facebook.com", "fb.com"],
  instagram: ["instagram.com"],
  netflix: ["netflix.com"],
  whatsapp: ["whatsapp.com"],
  linkedin: ["linkedin.com"],
  bankofamerica: ["bankofamerica.com"],
  chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"],
  outlook: ["outlook.com", "live.com"]
};

/* ---------- Icons used inside the report ---------- */
const ICON = {
  flag: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
  pass: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  safe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 9.01"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  danger: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
};

/* ---------- Helpers ---------- */

function getRegistrableDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join(".");
}

// Normalizes common "leetspeak" character swaps (0->o, 1->l, etc.)
// so typosquats like "amaz0n.com" or "paypa1.com" still match the
// brand name they're imitating.
function leetNormalize(str) {
  return str
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t");
}

function isIpAddress(hostname) {
  // IPv4 (e.g. 192.168.0.1) and a basic IPv6 check
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4.test(hostname)) {
    return hostname.split(".").every((octet) => Number(octet) <= 255);
  }
  return hostname.includes(":") && /^[0-9a-f:]+$/i.test(hostname);
}

/* ---------- Check definitions ----------
   Each check is independently testable and weighted by how
   strong a signal it is on its own. category is used to group
   results on the "How It Works" page. */
const CHECKS = [
  {
    id: "ip-host",
    category: "Domain & Hosting",
    weight: 25,
    flagText: "Uses a raw IP address instead of a domain name",
    passText: "Uses a real domain name, not a raw IP address",
    test: (ctx) => isIpAddress(ctx.hostname)
  },
  {
    id: "punycode",
    category: "Domain & Hosting",
    weight: 25,
    flagText: "Domain uses Punycode (xn--), often used to disguise look-alike characters",
    passText: "Domain does not use Punycode look-alike encoding",
    test: (ctx) => ctx.hostname.includes("xn--")
  },
  {
    id: "brand-mismatch",
    category: "Domain & Hosting",
    weight: 25,
    flagText: "Contains a well-known brand name on a domain that brand doesn't own",
    passText: "No mismatched brand names found in the domain",
    test: (ctx) => {
      const normalized = leetNormalize(ctx.hostname);
      for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
        const containsBrand = ctx.hostname.includes(brand) || normalized.includes(brand);
        if (containsBrand && !domains.includes(ctx.registrable)) {
          return true;
        }
      }
      return false;
    }
  },
  {
    id: "suspicious-tld",
    category: "Domain & Hosting",
    weight: 15,
    flagText: "Top-level domain is one often used for free or disposable sites",
    passText: "Top-level domain isn't on the commonly-abused list",
    test: (ctx) => {
      const tld = ctx.hostname.split(".").pop();
      return SUSPICIOUS_TLDS.includes(tld);
    }
  },
  {
    id: "subdomain-depth",
    category: "Domain & Hosting",
    weight: 12,
    flagText: "Domain has an unusually deep chain of subdomains",
    passText: "Subdomain structure looks normal",
    test: (ctx) => ctx.hostname.split(".").length > 4
  },
  {
    id: "credential-trick",
    category: "Connection Security",
    weight: 30,
    flagText: "URL hides the real destination using an '@' before the domain",
    passText: "No hidden '@' redirect trick in the URL",
    test: (ctx) => ctx.site.username !== ""
  },
  {
    id: "https",
    category: "Connection Security",
    weight: 12,
    flagText: "Connection is not encrypted (no HTTPS)",
    passText: "Connection uses HTTPS encryption",
    test: (ctx) => ctx.site.protocol !== "https:"
  },
  {
    id: "port",
    category: "Connection Security",
    weight: 12,
    flagText: "URL specifies an unusual network port",
    passText: "No unusual port number specified",
    test: (ctx) => ctx.site.port !== "" && !["80", "443"].includes(ctx.site.port)
  },
  {
    id: "shortener",
    category: "Connection Security",
    weight: 12,
    flagText: "Uses a link-shortening service that hides the real destination",
    passText: "Not using a known link-shortening service",
    test: (ctx) => URL_SHORTENERS.includes(ctx.hostname)
  },
  {
    id: "hyphens",
    category: "Structure & Pattern",
    weight: 8,
    flagText: "Domain name contains multiple hyphens",
    passText: "Domain name doesn't contain excessive hyphens",
    test: (ctx) => (ctx.hostname.match(/-/g) || []).length >= 2
  },
  {
    id: "long-url",
    category: "Structure & Pattern",
    weight: 6,
    flagText: "URL is unusually long",
    passText: "URL length looks normal",
    test: (ctx) => ctx.url.length > 75
  },
  {
    id: "redirect-trick",
    category: "Structure & Pattern",
    weight: 15,
    flagText: "Path contains a pattern that can redirect to another site",
    passText: "No suspicious redirect pattern in the path",
    test: (ctx) => ctx.site.pathname.includes("//")
  },
  {
    id: "digits-in-domain",
    category: "Structure & Pattern",
    weight: 8,
    flagText: "Domain name contains an unusual number of digits",
    passText: "Domain name doesn't contain excessive digits",
    test: (ctx) => (ctx.hostname.match(/\d/g) || []).length >= 4
  },
  {
    id: "suspicious-keywords",
    category: "Content Signals",
    weight: 10,
    flagText: "URL contains words commonly used on phishing pages (e.g. login, verify, secure)",
    passText: "No high-risk keywords found in the URL",
    test: (ctx) => {
      const target = (ctx.hostname + ctx.site.pathname + ctx.site.search).toLowerCase();
      return SUSPICIOUS_KEYWORDS.some((word) => target.includes(word));
    }
  }
];

/* ---------- Core analysis function ---------- */
function analyzeUrl(rawInput) {
  const raw = (rawInput || "").trim();
  if (!raw) return { empty: true };

  let normalized = raw;
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = "http://" + normalized;
  }

  let site;
  try {
    site = new URL(normalized);
  } catch {
    return { error: true };
  }

  if (!site.hostname || !site.hostname.includes(".")) {
    // Things like "http://localhost" or a bare word aren't
    // meaningful URLs for this tool.
    if (!isIpAddress(site.hostname)) {
      return { error: true };
    }
  }

  const hostname = site.hostname.toLowerCase();
  const ctx = {
    url: normalized,
    site,
    hostname,
    registrable: getRegistrableDomain(hostname)
  };

  const flagged = [];
  const passed = [];
  let score = 0;

  CHECKS.forEach((check) => {
    if (check.test(ctx)) {
      score += check.weight;
      flagged.push(check);
    } else {
      passed.push(check);
    }
  });

  let verdict;
  if (score >= 50) verdict = "danger";
  else if (score >= 20) verdict = "warn";
  else verdict = "safe";

  return {
    target: normalized,
    hostname,
    score,
    cappedScore: Math.min(score, 100),
    verdict,
    flagged,
    passed
  };
}

/* ---------- Verdict copy ---------- */
const VERDICTS = {
  safe: {
    label: "Likely Safe",
    pillClass: "pill-safe",
    icon: ICON.safe,
    description: "No major red flags were found, but always stay cautious with links you didn't expect."
  },
  warn: {
    label: "Suspicious \u2014 Proceed With Caution",
    pillClass: "pill-warn",
    icon: ICON.warn,
    description: "This URL shows some patterns associated with phishing. Avoid entering personal information."
  },
  danger: {
    label: "High Risk \u2014 Likely Phishing",
    pillClass: "pill-danger",
    icon: ICON.danger,
    description: "Multiple strong phishing indicators were detected. We recommend not visiting this link."
  }
};

/* ---------- History (stored locally in this browser) ---------- */
const HISTORY_KEY = "phishshield_scan_history";
const HISTORY_LIMIT = 6;

function loadHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveHistory(entries) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, HISTORY_LIMIT)));
  } catch {
    /* localStorage unavailable (private mode etc.) - fail silently */
  }
}

/* ---------- UI wiring ---------- */
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("scan-form");
  if (!form) return; // not on the scanner page

  const input = document.getElementById("url-input");
  const errorEl = document.getElementById("scan-error");
  const submitBtn = document.getElementById("scan-submit");

  const result = document.getElementById("result");
  const statusPill = document.getElementById("result-pill");
  const statusIcon = document.getElementById("result-icon");
  const statusLabel = document.getElementById("result-label");
  const resultTarget = document.getElementById("result-target");
  const gaugeFill = document.getElementById("gauge-fill");
  const scoreLabel = document.getElementById("score-label");
  const verdictDesc = document.getElementById("verdict-description");
  const flaggedList = document.getElementById("flagged-list");
  const passedList = document.getElementById("passed-list");

  const historyList = document.getElementById("history-list");
  const historyEmpty = document.getElementById("history-empty");
  const clearHistoryBtn = document.getElementById("clear-history");

  function renderHistory() {
    const entries = loadHistory();
    historyList.innerHTML = "";

    if (entries.length === 0) {
      historyEmpty.hidden = false;
      return;
    }

    historyEmpty.hidden = true;

    entries.forEach((entry) => {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "history-item";

      const badge = document.createElement("span");
      badge.className = "history-badge";
      badge.style.background = `var(--${entry.verdict === "danger" ? "danger" : entry.verdict === "warn" ? "warn" : "safe"})`;

      const urlSpan = document.createElement("span");
      urlSpan.className = "h-url";
      urlSpan.textContent = entry.target;

      const scoreSpan = document.createElement("span");
      scoreSpan.textContent = `${entry.score}/100`;

      btn.appendChild(badge);
      btn.appendChild(urlSpan);
      btn.appendChild(scoreSpan);

      btn.addEventListener("click", () => {
        input.value = entry.target;
        runScan();
      });

      li.appendChild(btn);
      historyList.appendChild(li);
    });
  }

  function renderReportColumn(listEl, items, textKey, iconKey, itemClass) {
    listEl.innerHTML = "";

    if (items.length === 0) {
      const li = document.createElement("li");
      li.className = "report-empty";
      li.textContent = itemClass === "flagged"
        ? "No issues flagged in this category."
        : "No checks passed.";
      listEl.appendChild(li);
      return;
    }

    items.forEach((check) => {
      const li = document.createElement("li");
      li.className = itemClass;
      li.innerHTML = `${ICON[iconKey]}<span>${check[textKey]}</span>`;
      listEl.appendChild(li);
    });
  }

  function renderResult(analysis) {
    const verdict = VERDICTS[analysis.verdict];

    result.hidden = false;
    statusPill.className = `pill ${verdict.pillClass}`;
    statusIcon.innerHTML = verdict.icon;
    statusLabel.textContent = verdict.label;
    resultTarget.textContent = analysis.target;
    verdictDesc.textContent = verdict.description;

    requestAnimationFrame(() => {
      gaugeFill.style.width = analysis.cappedScore + "%";
    });

    scoreLabel.innerHTML = `<span>Risk score</span><span>${analysis.score} / 100</span>`;

    renderReportColumn(flaggedList, analysis.flagged, "flagText", "flag", "flagged");
    renderReportColumn(passedList, analysis.passed, "passText", "pass", "passed");

    const entries = loadHistory();
    entries.unshift({
      target: analysis.target,
      score: analysis.score,
      verdict: analysis.verdict,
      time: Date.now()
    });
    saveHistory(entries);
    renderHistory();
  }

  function setLoading(isLoading) {
    submitBtn.disabled = isLoading;
    submitBtn.textContent = isLoading ? "Scanning\u2026" : "Scan Website";
  }

  function runScan() {
    const value = input.value;
    const analysis = analyzeUrl(value);

    if (analysis.empty) {
      errorEl.textContent = "Enter a URL first.";
      return;
    }

    if (analysis.error) {
      errorEl.textContent = "That doesn't look like a valid URL. Try something like example.com";
      return;
    }

    errorEl.textContent = "";
    setLoading(true);
    result.hidden = true;
    gaugeFill.style.width = "0%";

    // Brief delay so the UI clearly communicates a scan happened,
    // without pretending to call an external service.
    window.setTimeout(() => {
      renderResult(analysis);
      setLoading(false);
    }, 500);
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    runScan();
  });

  clearHistoryBtn.addEventListener("click", () => {
    saveHistory([]);
    renderHistory();
  });

  renderHistory();
});
