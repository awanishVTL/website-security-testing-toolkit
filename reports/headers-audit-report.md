# Security Assessment Report: Security Headers Audit

**Target URL:** `http://localhost:3000`  
**Assessment Date:** 2026-11-02T07:18:46.837Z  
**Classification:** Authorized Defensive Assessment  

## Executive Summary

| Metric | Count |
| :--- | :--- |
| **Total Endpoints Tested** | 2 |
| **Confirmed Vulnerabilities** | **5** |
| **Potential Findings** | 0 |
| **Verified Secure Controls** | 4 |
| **Critical Severity** | 0 |
| **High Severity** | 0 |
| **Medium Severity** | 2 |
| **Low Severity** | 3 |
| **Informational** | 4 |

## Findings Matrix

| ID | Status | Severity | Category | Title | Endpoint |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `HEADER-MISSING-CONTENT_SECURITY_POLICY` | **Confirmed** | Medium | Security Headers | Missing Security Header: Content-Security-Policy on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `HEADER-MISSING-X_FRAME_OPTIONS` | **Confirmed** | Medium | Security Headers | Missing Security Header: X-Frame-Options on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `HEADER-MISSING-X_CONTENT_TYPE_OPTIONS` | **Confirmed** | Low | Security Headers | Missing Security Header: X-Content-Type-Options on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `HEADER-MISSING-REFERRER_POLICY` | **Confirmed** | Low | Security Headers | Missing Security Header: Referrer-Policy on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `HEADER-LEAK-POWERED-BY` | **Confirmed** | Low | Security Headers | Technology Fingerprint Disclosed via X-Powered-By on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `HEADER-PRESENT-CONTENT_SECURITY_POLICY` | **Secure** | Informational | Security Headers | Header Present: Content-Security-Policy | `/api/secure/profile` |
| `HEADER-PRESENT-X_FRAME_OPTIONS` | **Secure** | Informational | Security Headers | Header Present: X-Frame-Options | `/api/secure/profile` |
| `HEADER-PRESENT-X_CONTENT_TYPE_OPTIONS` | **Secure** | Informational | Security Headers | Header Present: X-Content-Type-Options | `/api/secure/profile` |
| `HEADER-PRESENT-REFERRER_POLICY` | **Secure** | Informational | Security Headers | Header Present: Referrer-Policy | `/api/secure/profile` |

## Confirmed Vulnerabilities

### [Medium] HEADER-MISSING-CONTENT_SECURITY_POLICY: Missing Security Header: Content-Security-Policy on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** Security Headers
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-16
- **Verification Status:** `Confirmed`

#### Security Impact
Missing Content-Security-Policy degrades browser-side defense-in-depth protections.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/profile
2. Inspect response headers for presence of "Content-Security-Policy"

#### Evidence
```text
Header "Content-Security-Policy" was not returned by server in response to GET /api/vulnerable/profile
```

#### Recommended Remediation
Implement CSP directives (e.g. default-src 'self'; script-src 'self').

---

### [Medium] HEADER-MISSING-X_FRAME_OPTIONS: Missing Security Header: X-Frame-Options on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** Security Headers
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-16
- **Verification Status:** `Confirmed`

#### Security Impact
Missing X-Frame-Options degrades browser-side defense-in-depth protections.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/profile
2. Inspect response headers for presence of "X-Frame-Options"

#### Evidence
```text
Header "X-Frame-Options" was not returned by server in response to GET /api/vulnerable/profile
```

#### Recommended Remediation
Set X-Frame-Options: DENY or SAMEORIGIN to prevent Clickjacking.

---

### [Low] HEADER-MISSING-X_CONTENT_TYPE_OPTIONS: Missing Security Header: X-Content-Type-Options on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** Security Headers
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-16
- **Verification Status:** `Confirmed`

#### Security Impact
Missing X-Content-Type-Options degrades browser-side defense-in-depth protections.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/profile
2. Inspect response headers for presence of "X-Content-Type-Options"

#### Evidence
```text
Header "X-Content-Type-Options" was not returned by server in response to GET /api/vulnerable/profile
```

#### Recommended Remediation
Set X-Content-Type-Options: nosniff to prevent MIME-sniffing.

---

### [Low] HEADER-MISSING-REFERRER_POLICY: Missing Security Header: Referrer-Policy on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** Security Headers
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-16
- **Verification Status:** `Confirmed`

#### Security Impact
Missing Referrer-Policy degrades browser-side defense-in-depth protections.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/profile
2. Inspect response headers for presence of "Referrer-Policy"

#### Evidence
```text
Header "Referrer-Policy" was not returned by server in response to GET /api/vulnerable/profile
```

#### Recommended Remediation
Configure Referrer-Policy: strict-origin-when-cross-origin.

---

### [Low] HEADER-LEAK-POWERED-BY: Technology Fingerprint Disclosed via X-Powered-By on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** Security Headers
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-200: Exposure of Sensitive Information
- **Verification Status:** `Confirmed`

#### Security Impact
Exposes underlying framework and potential version details to reconnaissance.

#### Reproduction Steps
1. Inspect headers of /api/vulnerable/profile

#### Evidence
```text
X-Powered-By: Express/4.21.2
```

#### Recommended Remediation
Disable fingerprinting in Express via app.disable("x-powered-by") or helmet.hidePoweredBy().

---

## Verified Secure Controls

- **[PASS] HEADER-PRESENT-CONTENT_SECURITY_POLICY**: Header Present: Content-Security-Policy on `/api/secure/profile` (Security Headers)
- **[PASS] HEADER-PRESENT-X_FRAME_OPTIONS**: Header Present: X-Frame-Options on `/api/secure/profile` (Security Headers)
- **[PASS] HEADER-PRESENT-X_CONTENT_TYPE_OPTIONS**: Header Present: X-Content-Type-Options on `/api/secure/profile` (Security Headers)
- **[PASS] HEADER-PRESENT-REFERRER_POLICY**: Header Present: Referrer-Policy on `/api/secure/profile` (Security Headers)

## Confidentiality & Disclaimer

This report was generated using the **Website Security Testing Toolkit** for authorized defensive validation. No sensitive passwords, production tokens, or customer personal data were gathered or stored during this assessment.
