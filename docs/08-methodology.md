# Security Assessment Methodology & Guardrails

This document outlines the operational methodology, ethical guidelines, and testing protocols governing the **Website Security Testing Toolkit**.

---

## 1. Ethical Boundaries & Target Authorization

1. **Explicit Authorization:** Testing must **only** be performed on web applications, staging servers, and APIs where you possess written authorization or direct ownership.
2. **Allowlist Enforcement:** The toolkit strictly rejects any target whose hostname is not present in the authorized allowlist (`config/allowlist.json` or `ALLOWED_HOSTS` environment variable).
3. **Refuse External Production by Default:** Scanning external domains or production systems without deliberate allowlist configuration is prohibited.

---

## 2. Non-Destructive Testing Principles

- **No Data Destruction:** Automated scripts do not execute `DROP`, `DELETE`, `TRUNCATE`, or filesystem removal commands.
- **Safe Probes Only:** Injection probes utilize non-destructive sentinel tokens (e.g. `<test-sentinel-xyz>`, syntax single quotes, balanced booleans) rather than malicious exploitation code.
- **No Credential Exfiltration:** Payloads are designed solely to confirm reflection, syntax errors, or header anomalies. They never transmit credentials to external third-party servers.
- **Throttling & Concurrency Limits:** Request volume is capped to prevent denial of service (DoS) on testing targets.

---

## 3. Finding Classification Standard

| Status | Definition | Action Required |
| :--- | :--- | :--- |
| **Confirmed** | Unequivocal proof of vulnerability observed (e.g., raw HTML tag reflected verbatim, SQL error leaked, tokenless CSRF mutation executed). | Immediate remediation required. High confidence. |
| **Potential** | Behavioral anomaly detected (e.g., response size divergence), but full exploitability cannot be verified purely through automated probing. | Manual code review or targeted inspection needed. |
| **Secure** | Verified that defensive controls (e.g., parameter binding, output entity encoding, anti-CSRF tokens, security headers) successfully neutralized probe. | Maintain existing secure design. |

---

## 4. Assessment Workflow

```
[1. Target Configuration & Allowlist Verification]
                        │
                        ▼
[2. Target Health & Connectivity Check]
                        │
                        ▼
[3. Automated Non-Destructive Probing]
  ├─ XSS Reflection & Context Tests
  ├─ SQL Parameterization & Error Tests
  ├─ CSRF Token & Cookie Policy Tests
  ├─ CORS & Origin Reflection Tests
  └─ Security Headers Inspection
                        │
                        ▼
[4. Sanitize Evidence & Filter Secrets]
                        │
                        ▼
[5. Generate JSON & Markdown Audit Reports]
                        │
                        ▼
[6. Review & Apply Remediation Guide]
```
