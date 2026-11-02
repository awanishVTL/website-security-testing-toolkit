# Master Security Remediation & Hardening Guide

This document serves as the developer's quick-reference guide for addressing vulnerabilities identified during testing with the **Website Security Testing Toolkit**.

---

## 1. Quick Remediation Checklist

| Vulnerability | Primary Remediation Strategy | Technology Example |
| :--- | :--- | :--- |
| **XSS** | Contextual output encoding + Content-Security-Policy | `escapeHtml()`, JSX `{text}`, `helmet.contentSecurityPolicy()` |
| **SQL Injection** | Prepared statements & parameterized queries | `db.execute('SELECT * WHERE id = ?', [id])` |
| **CSRF** | Anti-CSRF token verification + SameSite cookies | `csrf-csrf`, `SameSite=Lax`, custom API headers |
| **CORS Flaws** | Static origin allowlist; avoid echoing request origin | Explicit `cors({ origin: ['https://app.example.com'] })` |
| **Missing Headers** | HTTP response header hardening | `helmet()` with CSP, HSTS, frameguard |
| **IDOR / BOLA** | Object ownership validation in database query | `WHERE id = :id AND user_id = :userId` |
| **Authentication** | Adaptive hashing + rate limiting + constant-time comparison | `bcrypt` (rounds: 12), `express-rate-limit` |
| **Command Injection** | Avoid shell execution; pass argument arrays | `child_process.execFile()` with `shell: false` |
| **Path Traversal** | Canonical path validation against base directory | `path.resolve(base, input).startsWith(base)` |

---

## 2. Framework-Specific Hardening

### Node.js & Express Security Baseline
```javascript
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const session = require('express-session');

const app = express();

// 1. Hide framework identification
app.disable('x-powered-by');

// 2. Security headers via Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true }
}));

// 3. Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

// 4. Body parser limits (Prevent payload exhaustion DoS)
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// 5. Secure Session Cookies
app.use(session({
  secret: process.env.SESSION_SECRET,
  name: '__Host-sess',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7200000
  }
}));
```

---

## 3. Database Prepared Statements Reference

### MySQL (mysql2)
```javascript
// Parameterized query: Question mark syntax
const [rows] = await connection.execute(
  'SELECT id, username, email FROM users WHERE status = ? AND role = ?',
  ['active', 'editor']
);
```

### PostgreSQL (pg)
```javascript
// Parameterized query: Positional argument syntax
const res = await pool.query(
  'SELECT id, username, email FROM users WHERE status = $1 AND role = $2',
  ['active', 'editor']
);
```

---

## 4. Remediation Verification Workflow

Whenever a vulnerability fix is committed:
1. Re-run the automated security check (e.g. `npm run test:xss` or `npm run test:sqli`).
2. Verify that the finding status transitions from **Confirmed** to **Secure**.
3. Verify that unit and regression tests pass without errors (`npm test`).
4. Generate an updated assessment report (`npm run security:scan`).
