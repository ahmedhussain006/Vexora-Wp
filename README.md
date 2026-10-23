# VexoraWP 🛡️

> **Fast, passive WordPress reconnaissance, threat intelligence, and security posture audit suite.** Built for hackathons, blue teams, and security researchers.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Audit-Passive%20OSINT-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

---

## ⚡ Highlights & Key Features

- **🌐 Cross-Platform Native**: Engineered with UTF-8 console reconfiguring and Windows VT100 ANSI escape compatibility out-of-the-box.
- **🔍 Multi-Vector User & Admin Enumeration**:
  - WordPress REST API (`/wp/v2/users`)
  - Author redirection IDOR harvesting (`/?author=N`)
  - XML Author sitemaps (`author-sitemap.xml`)
  - oEmbed author data extraction
- **🔌 Multi-Threaded Plugin & Theme Probing**:
  - Parallel inspection of top ~100 common WordPress plugins via `readme.txt` metadata and file headers.
  - Connection-pooled networking with automatic retry handling.
- **⚠️ Version-Aware CVE Correlation**:
  - Offline curated CVE intelligence database.
  - Semver version comparison (`packaging.version`) — only alerts if the detected version is `< fixed_in` (distinguishing **VULNERABLE**, **PATCHED**, and **UNVERIFIED** states).
- **🔒 Sensitive Asset Exposure Auditing**:
  - Inspects 40+ critical paths: `.env`, `.git`, `wp-config.php.bak`, database dumps (`db.sql`), backup archives (`site.zip`), `debug.log`, `xmlrpc.php`.
  - **Smart Soft-404 Filtering**: Baselines randomized 404 responses and validates MIME content types to eliminate false positives on servers returning HTTP 200 for missing pages.
- **🛡️ Executive Security Posture Score (0–100 / Grades A–F)**:
  - Algorithmic security rating calculating deductions for exposed critical files, missing HTTP headers (CSP, HSTS, X-Frame-Options), vulnerable plugins, and user exposure.
- **📊 Modern Dark-Mode HTML Report Export (`--html`)**:
  - Generates a standalone, dependency-free interactive HTML security dashboard with KPI cards, severity badges, and remediation guidance.
- **📄 Structured JSON Export (`-o / --output`)**:
  - Full machine-readable audit report for CI/CD pipelines or SIEM ingestion.

---

## 🚀 Quickstart & Installation

### 1. Clone or Open Project
```bash
git clone https://github.com/your-username/VexoraWP.git
cd VexoraWP
```

### 2. Set Up Virtual Environment & Dependencies
```bash
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# On Linux / macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

---

## 🌐 Web Application & Vercel Deployment

VexoraWP comes with a web application powered by a dark cybersecurity dashboard and a Vercel-ready Python serverless API.

### 1. Deploying to Vercel (1-Click / Zero Config)

1. Push your repository to **GitHub / GitLab / Bitbucket**.
2. Go to [vercel.com](https://vercel.com/) and click **"Add New Project"**.
3. Import your VexoraWP repository.
4. Vercel automatically detects the static frontend and Python serverless function in `api/scan.py`.
5. Click **"Deploy"**!

*Or deploy directly from the CLI:*
```bash
npm i -g vercel
vercel
```

### 2. Running the Web UI Locally

You can run the web dashboard locally using the built-in development server:
```bash
python dev_server.py
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser!

---

## 💻 CLI Usage

```bash
python VexoraWp.py <TARGET_URL> [OPTIONS]
```

### Quick Scan with HTML & JSON Reports
```bash
python VexoraWp.py https://example.com --html report.html -o report.json
```

### Full Options & Flags

| Flag | Description | Default |
| :--- | :--- | :--- |
| `url` | Target WordPress site URL (**required**) | — |
| `--html <FILE>` | Export interactive standalone HTML audit report | `None` |
| `-o`, `--output <FILE>` | Export full machine-readable JSON report | `None` |
| `--threads <N>` | Concurrent worker threads for plugin probing | `25` |
| `--timeout <SEC>` | HTTP request timeout in seconds | `12` |
| `--proxy <URL>` | Route traffic through HTTP/S proxy | `None` |
| `--ua <STRING>` | Custom User-Agent header string | Chrome Default |
| `--skip-plugins` | Skip brute-force plugin enumeration | `False` |
| `--skip-emails` | Skip contact and email address scraping | `False` |
| `--skip-structure` | Skip site structure and taxonomy mapping | `False` |

---

## 📊 Security Posture Scoring Model

VexoraWP calculates a transparent score from **0 to 100** based on industry hardening standards:

| Grade | Score Range | Meaning |
| :---: | :---: | :--- |
| **A** | 90 – 100 | **Excellent**: Hardened configuration, no major exposures. |
| **B** | 80 – 89 | **Good**: Minor header or version disclosure hardening recommended. |
| **C** | 65 – 79 | **Moderate Risk**: Sensitive endpoint leaks or missing defensive headers. |
| **D** | 50 – 64 | **High Risk**: Unpatched plugin vulnerabilities or user enumeration. |
| **F** | 0 – 49 | **Critical Risk**: Sensitive files (.env, config backups, SQL dumps) exposed. |

---

## 🛡️ Ethical Usage & Disclaimer

> **Important**: VexoraWP is designed strictly for authorized security assessments, penetration testing with written permission, and defensive posture evaluation of assets you own. Scanning third-party infrastructure without explicit consent may violate local and international cyber laws.
