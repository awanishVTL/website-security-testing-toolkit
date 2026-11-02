# Website Security Testing Toolkit

An enterprise-grade, defensive web application security assessment toolkit, non-destructive automated test runners, vulnerability payload collections, and comprehensive remediation guides built with Node.js and Express.

Created by **awanishVTL** for authorized security assessments of owned web applications, APIs, and staging environments.

---

## Table of Contents
1. [Core Features](#core-features)
2. [Technologies](#technologies)
3. [Repository Structure](#repository-structure)
4. [Installation & Setup](#installation--setup)
5. [Target Configuration & Safety Guardrails](#target-configuration--safety-guardrails)
6. [Available npm Commands](#available-npm-commands)
7. [Running Local Test Demonstrations](#running-local-test-demonstrations)
8. [Automated Testing Modules](#automated-testing-modules)
9. [Payload Collections](#payload-collections)
10. [Documentation & Remediation Guides](#documentation--remediation-guides)
11. [AGY Code Audit & Remediation Prompts](#agy-code-audit--remediation-prompts)
12. [Assessment Reports](#assessment-reports)
13. [Security Testing Checklist](#security-testing-checklist)
14. [Legal Disclaimer & Security Policy](#legal-disclaimer--security-policy)

---

## Core Features

- **Non-Destructive Probing:** Automated checks verify reflection, parameter binding, and headers without altering records or exfiltrating data.
- **Strict Allowlist Guardrails:** Refuses scans against unauthorized external domains or production systems by default.
- **Side-by-Side Testbed:** Built-in Express fixture provides paired vulnerable (`/api/vulnerable/...`) and secure (`/api/secure/...`) endpoints with an interactive browser UI.
- **Automated Reporting:** Generates audit reports in both machine-readable JSON and human-readable Markdown formats with automatic credential redaction.
- **Agentic DevSecOps Prompts:** Reusable AGY prompts in `prompts/` guide AI coding agents through code auditing, reproduction, fix implementation, and regression testing.

---

## Technologies

- **Runtime:** Node.js (>= 18.0.0; tested on Node 24)
- **Languages:** JavaScript (ES2022+ / CommonJS), TypeScript definitions (`lib/types.d.ts`)
- **Server / Fixture:** Express.js 4.21, `cookie-parser`, `cors`
- **UI:** Pure HTML5 / CSS3 / Vanilla JS (no heavy frameworks required)
- **Test Runner:** Built-in Node.js Test Runner (`node --test`)
- **Payload Collections:** Structured JSON schemas
- **Documentation:** GitHub-flavored Markdown

---

## Repository Structure

```text
website-security-testing-toolkit/
├── .env.example                       # Template for target URL & allowlist configuration
├── .gitignore                         # Prevents leaking credentials, .env, and scan artifacts
├── package.json                       # Scripts and lightweight dependencies
├── tsconfig.json                      # TypeScript configuration
├── SECURITY.md                        # Authorized testing policy & responsible disclosure
├── README.md                          # Comprehensive documentation & execution manual
├── config/
│   ├── default.json                   # Scanner timeouts, concurrency, and default endpoints
│   └── allowlist.json                 # Strict target host allowlist definition
├── fixtures/
│   ├── server.js                      # Express fixture (vulnerable & secure paired endpoints)
│   ├── data/
│   │   └── seed-data.json             # Seed dummy data (no real credentials or PII)
│   └── public/
│       ├── index.html                 # Interactive browser security testbed
│       ├── app.js                     # Browser test runners
│       └── style.css                  # UI styling
├── lib/
│   ├── types.d.ts                     # TypeScript definitions for findings & configs
│   ├── allowlist.js                   # Target validation & domain guardrails
│   ├── http-client.js                 # Safe HTTP client with timeouts & concurrency limits
│   ├── logger.js                      # Colored terminal output formatting
│   └── reporter.js                    # JSON & Markdown report generator with secret redaction
├── payloads/
│   ├── xss.json                       # Safe XSS reflection and attribute payloads
│   ├── sqli.json                      # Safe SQL syntax, boolean, and auth bypass probes
│   ├── csrf.json                      # CSRF state-change, SameSite, and origin payloads
│   ├── auth.json                      # Brute-force, JWT none-algorithm, and host injection probes
│   ├── idor.json                      # IDOR, object ownership, and privilege escalation probes
│   ├── cors.json                      # Origin reflection and credential probes
│   ├── headers.json                   # Security headers presence and information leak checks
│   ├── traversal.json                 # Path traversal probe sequences
│   ├── file-upload.json               # Extension spoofing and SVG upload checks
│   ├── ssrf.json                      # Loopback and metadata service detection
│   ├── cmdi.json                      # Safe non-destructive echo sentinel probes
│   └── rate-limit.json                # Request burst and IP spoofing tests
├── prompts/
│   ├── xss-audit-and-fix.md           # AGY prompt for XSS code review & remediation
│   ├── sqli-audit-and-fix.md          # AGY prompt for SQLi code review & remediation
│   ├── csrf-audit-and-fix.md          # AGY prompt for CSRF code review & remediation
│   ├── auth-audit-and-fix.md          # AGY prompt for Authentication hardening
│   ├── idor-audit-and-fix.md          # AGY prompt for IDOR & authorization fixes
│   ├── headers-cors-audit-and-fix.md  # AGY prompt for Headers & CORS hardening
│   └── full-assessment.md             # AGY prompt for complete application security audit
├── docs/
│   ├── 01-xss.md                      # Complete guide to XSS (Express, React, Remediation)
│   ├── 02-sqli.md                     # Complete guide to SQLi (Prepared statements, MySQL)
│   ├── 03-csrf.md                     # Complete guide to CSRF (Tokens, SameSite cookies)
│   ├── 04-authentication.md           # Authentication security & rate limiting
│   ├── 05-authorization.md             # Authorization, IDOR, and RBAC
│   ├── 06-additional-vulnerabilities.md # CORS, Headers, SSRF, Traversal, Upload, Cmd Injection
│   ├── 07-remediation-guide.md        # Master remediation cheatsheet & patterns
│   └── 08-methodology.md              # Assessment methodology & classification rules
├── scripts/
│   ├── xss-test.js                    # Automated XSS verification runner
│   ├── sqli-test.js                   # Automated SQL Injection runner
│   ├── csrf-test.js                   # Automated CSRF runner
│   ├── cors-test.js                   # Automated CORS misconfiguration runner
│   ├── headers-check.js               # Automated security headers checker
│   └── security-scan.js               # Master security assessment scanner
├── tests/
│   ├── allowlist.test.js              # Unit tests for allowlist guardrails
│   ├── http-client.test.js            # Unit tests for safe HTTP client & method blocking
│   └── reporter.test.js               # Unit tests for reporting & evidence sanitization
└── reports/
    ├── sample-assessment-report.json  # Sample JSON assessment audit report
    └── sample-assessment-report.md    # Sample Markdown assessment audit report
```

---

## Installation & Setup

### Prerequisites
- Ubuntu Linux / Debian / macOS / Windows WSL
- Node.js (v18 or higher; Node.js 24 recommended)
- Git

### Installation Steps
```bash
# 1. Clone repository
git clone https://github.com/awanishVTL/website-security-testing-toolkit.git
cd website-security-testing-toolkit

# 2. Install dependencies
npm install

# 3. Create your environment configuration
cp .env.example .env

# 4. Verify unit tests
npm test
```

---

## Target Configuration & Safety Guardrails

The toolkit incorporates mandatory guardrails to prevent accidental scans against production systems or unauthorized hosts.

Configure your target in `.env`:
```env
# Target base URL
TARGET_URL=http://localhost:3000

# Strict Target Allowlist (comma-separated list of approved domains)
# Scans against any domain NOT listed here will immediately abort!
ALLOWED_HOSTS=localhost,127.0.0.1,staging.local

# Request timeouts & throttling
REQUEST_TIMEOUT_MS=5000
MAX_CONCURRENCY=5

# Report output directory
REPORT_OUTPUT_DIR=./reports
```

You can also pass `TARGET_URL` inline at execution time:
```bash
TARGET_URL=http://127.0.0.1:3000 npm run test:xss
```

---

## Available npm Commands

| Command | Description |
| :--- | :--- |
| `npm start` / `npm run fixture:start` | Launches the local Express testbed server on `http://localhost:3000`. |
| `npm test` | Executes unit tests for scanner components (allowlist, http client, reporter). |
| `npm run test:xss` | Runs automated non-destructive Cross-Site Scripting (XSS) checks. |
| `npm run test:sqli` | Runs automated SQL Injection checks (syntax errors, booleans, auth bypass). |
| `npm run test:csrf` | Runs automated CSRF checks (token omission, GET method mutation, SameSite cookies). |
| `npm run test:cors` | Runs automated CORS misconfiguration checks (origin reflection, credentials). |
| `npm run test:headers` | Runs automated security headers audit (CSP, HSTS, XFO, XCTO, info leaks). |
| `npm run security:scan` | Runs the master scanner executing all modules and generating audit reports. |

---

## Running Local Test Demonstrations

### 1. Start the Local Fixture
Open a terminal and start the server:
```bash
npm run fixture:start
```
Output:
```text
[FIXTURE SERVER] Running on http://localhost:3000
- Web Demonstration UI: http://localhost:3000/
- Vulnerable API:       http://localhost:3000/api/vulnerable/...
- Secure API:           http://localhost:3000/api/secure/...
```

### 2. Browser Interactive Playground
Navigate to `http://localhost:3000/` in your browser. You can interactively test:
- **XSS:** Compare raw unencoded output vs HTML entity encoded output.
- **SQLi:** Test string concatenation error responses vs parameterized queries.
- **CSRF:** Trigger tokenless cross-site transfers vs verified CSRF tokens.
- **CORS & Headers:** Inspect response headers for missing policies.
- **IDOR:** Attempt to access user ID 99 from simulated session ID 1.

### 3. Run Automated Scans Against Localhost
In a second terminal:
```bash
# Run individual checks
npm run test:xss
npm run test:sqli
npm run test:csrf
npm run test:cors
npm run test:headers

# Run full master assessment
npm run security:scan
```

---

## Automated Testing Modules

1. **XSS Scanner (`scripts/xss-test.js`):** Tests reflected input parameters using benign sentinel tags (`<test-xss-sentinel>`). Flags vulnerabilities when raw unencoded tags are mirrored in responses.
2. **SQLi Scanner (`scripts/sqli-test.js`):** Tests error-based syntax leakage (`'`), authentication bypass (`admin' OR '1'='1' -- `), and boolean condition divergence (`1' AND '1'='1`).
3. **CSRF Scanner (`scripts/csrf-test.js`):** Verifies if state-changing endpoints accept HTTP GET, checks token omission on POST, and inspects `SameSite` and `HttpOnly` flags on session cookies.
4. **CORS Scanner (`scripts/cors-test.js`):** Checks whether untrusted origins (`https://attacker.test` or `null`) are reflected in `Access-Control-Allow-Origin` alongside `Access-Control-Allow-Credentials: true`.
5. **Headers Checker (`scripts/headers-check.js`):** Verifies CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and flags fingerprint leakage (`X-Powered-By`).
6. **Master Scanner (`scripts/security-scan.js`):** Orchestrates all checks, verifies target health, audits IDOR, and writes JSON/Markdown reports.

---

## Payload Collections

All payloads reside in `payloads/` as structured JSON files conforming to the following schema:
- `id`: Unique payload identifier
- `category`: Vulnerability category
- `payload`: Safe non-destructive probe string
- `purpose`: Rationale for the check
- `expected_secure_behavior`: Correct secure response
- `expected_vulnerable_behavior`: Flawed behavior indicating vulnerability
- `risk_level`: Critical / High / Medium / Low / Informational
- `remediation`: Concise code fix recommendation

---

## Documentation & Remediation Guides

Detailed guides located in `docs/` provide comprehensive vulnerability analysis, attack scenarios, vulnerable code snippets, and production-ready secure implementations:

- [docs/01-xss.md](docs/01-xss.md): Reflected, Stored, and DOM XSS remediation for Express and React.
- [docs/02-sqli.md](docs/02-sqli.md): MySQL prepared statements, parameterized queries, and allowlists.
- [docs/03-csrf.md](docs/03-csrf.md): Synchronizer Token Pattern, `csrf-csrf`, and SameSite cookie hardening.
- [docs/04-authentication.md](docs/04-authentication.md): Password hashing with bcrypt, rate limiting, and JWT validation.
- [docs/05-authorization.md](docs/05-authorization.md): IDOR, object ownership validation, and RBAC middleware.
- [docs/06-additional-vulnerabilities.md](docs/06-additional-vulnerabilities.md): CORS, Security Headers, SSRF, Traversal, File Uploads, Command Injection.
- [docs/07-remediation-guide.md](docs/07-remediation-guide.md): Master remediation cheatsheet.
- [docs/08-methodology.md](docs/08-methodology.md): Ethical boundaries and classification standards.

---

## AGY Code Audit & Remediation Prompts

The `prompts/` directory contains specialized prompts designed for AI coding agents to perform structured source code audits without altering code without permission:

- [prompts/xss-audit-and-fix.md](prompts/xss-audit-and-fix.md)
- [prompts/sqli-audit-and-fix.md](prompts/sqli-audit-and-fix.md)
- [prompts/csrf-audit-and-fix.md](prompts/csrf-audit-and-fix.md)
- [prompts/auth-audit-and-fix.md](prompts/auth-audit-and-fix.md)
- [prompts/idor-audit-and-fix.md](prompts/idor-audit-and-fix.md)
- [prompts/headers-cors-audit-and-fix.md](prompts/headers-cors-audit-and-fix.md)
- [prompts/full-assessment.md](prompts/full-assessment.md)

---

## Assessment Reports

Assessment reports are saved automatically to `reports/`:
- **JSON Format:** `reports/<scan-name>.json` (ideal for CI/CD pipeline integration and security dashboards).
- **Markdown Format:** `reports/<scan-name>.md` (formatted for developer remediation and audit logs).

### Sample Reports Included
- [reports/sample-assessment-report.json](reports/sample-assessment-report.json)
- [reports/sample-assessment-report.md](reports/sample-assessment-report.md)

---

## Security Testing Checklist

- [ ] Target URL is explicitly verified and approved in `ALLOWED_HOSTS`.
- [ ] No queries use dynamic string concatenation; all use prepared statements (`?` / `$1`).
- [ ] All reflected search parameters and dynamic HTML contexts are entity-escaped.
- [ ] All non-idempotent endpoints (`POST`, `PUT`, `DELETE`) require anti-CSRF tokens.
- [ ] Session cookies are set with `HttpOnly`, `SameSite=Lax` (or `Strict`), and `Secure`.
- [ ] CORS policies use an explicit static domain allowlist rather than reflecting `Origin`.
- [ ] Essential security headers are enabled (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `HSTS`).
- [ ] Authentication endpoints enforce rate limiting (`max: 5` attempts per window).
- [ ] Object lookups verify ownership (`WHERE id = ? AND user_id = ?`).
- [ ] File upload endpoints randomize filenames, validate magic bytes, and store off webroot.

---

## Legal Disclaimer & Security Policy

This toolkit is provided strictly for **authorized defensive security assessments** of web applications you own or have explicit written authorization to test. Use of this software against unauthorized targets without prior consent is strictly prohibited and violates local and international cybersecurity laws.

See [SECURITY.md](SECURITY.md) for full policy details and vulnerability reporting guidelines.
