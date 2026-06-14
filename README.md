# PhishShield AI

A lightweight, client-side URL phishing scanner built as a cybersecurity
internship project. PhishShield AI runs **14 weighted heuristic checks** on
any URL — entirely in the browser — and returns a 0–100 risk score with a
plain-language explanation of every check that passed or failed.

## Live Demo
https://phishshield-url-detector.onrender.com/

## ✨ Features

- **4 pages**: Home, About, How It Works, and the Scanner tool
- **14 detection checks** across 4 categories (domain, connection, structure, content)
- **Transparent scoring** — every flagged and passed check is shown to the user
- **Scan history** stored locally in the browser (no backend, no database)
- Fully **responsive** layout (mobile nav, fluid grids)
- Accessible: keyboard focus states, `aria-` attributes, semantic HTML
- Zero external dependencies besides Google Fonts — pure HTML/CSS/JS

## 📁 Project structure

```
phishshield-ai/
├── index.html          # Home page
├── about.html          # About / project context
├── how.html            # How It Works — full list of checks
├── scanner.html         # The scanner tool
├── 404.html             # Custom not-found page
├── render.yaml          # Render Blueprint config (optional)
├── assets/
│   ├── css/style.css    # Shared design system (used by all pages)
│   ├── js/main.js       # Shared nav behaviour (mobile menu, active link)
│   ├── js/scanner.js     # Detection engine + scanner UI logic
│   └── icons/favicon.svg
└── README.md
```

## 🧠 How detection works

The scanner parses the URL with the standard `URL` API and runs it through
14 independent checks, each worth a different number of points:

| Category | Examples |
|---|---|
| Domain & Hosting | Raw IP address, Punycode domains, brand impersonation, risky TLDs, deep subdomains |
| Connection Security | Hidden `@` redirect trick, missing HTTPS, unusual ports, link shorteners |
| Structure & Pattern | Excess hyphens, very long URLs, `//` redirect patterns, digit-heavy domains |
| Content Signals | Keywords like `login`, `verify`, `secure`, `update` in the path |

Points from triggered checks are summed into a score (capped at 100):

- **0–19** → Likely Safe
- **20–49** → Suspicious — proceed with caution
- **50–100** → High Risk — likely phishing

See `how.html` for the full, page-rendered breakdown.

> **Note:** This is a rule-based educational tool, not a substitute for
> enterprise threat intelligence (e.g. Google Safe Browsing, VirusTotal).
> It's designed to teach and demonstrate common phishing patterns.

## 🖥️ Run it locally

No build step is required. Either:

- Open `index.html` directly in your browser, **or**
- Serve the folder with any static server, e.g.:
  ```bash
  python3 -m http.server 8000
  ```
  then visit `http://localhost:8000`

## 🚀 Deploy on Render

### Option A — Blueprint (recommended, uses `render.yaml`)

1. Push this project to a GitHub repository.
2. In the Render dashboard, click **New → Blueprint**.
3. Select your repository. Render will detect `render.yaml` automatically
   and configure a **Static Site** for you.
4. Click **Apply** — your site will be live at `https://<your-service-name>.onrender.com`.

### Option B — Manual static site

1. Push this project to a GitHub repository.
2. In the Render dashboard, click **New → Static Site**.
3. Connect your repository.
4. Leave **Build Command** empty.
5. Set **Publish Directory** to `.` (the repo root).
6. Click **Create Static Site**.

That's it — every file is already at the repo root with relative paths, so
no extra configuration is needed.

## 📄 License / use

Built for educational purposes as part of a cybersecurity internship.
Feel free to reuse and extend for learning.
