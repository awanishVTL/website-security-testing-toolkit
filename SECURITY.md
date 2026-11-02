# Security Policy

## Authorized Testing & Legal Compliance

The **Website Security Testing Toolkit** is designed strictly for **authorized security assessments**, defensive validation, code auditing, and educational demonstrations on web applications and staging environments you own or have explicit written permission to test.

### Rules of Engagement
1. **Target Authorization:** Always verify written approval before initiating any scan.
2. **Allowlist Enforcement:** The toolkit includes strict allowlist guardrails (`config/allowlist.json` and `ALLOWED_HOSTS`). Scans against external or production domains not explicitly approved will be aborted.
3. **Non-Destructive Operations:** Automated scripts use benign sentinel tokens and safe non-destructive probes. They do not drop tables, alter databases, deploy persistence, or exfiltrate private user data.
4. **Data Protection:** Never collect, store, or commit real user credentials, session tokens, passwords, or production PII into reports or repository files.

## Reporting a Security Vulnerability in this Toolkit

If you discover a security vulnerability or safety issue within this toolkit itself:

1. **Do not** create a public GitHub issue.
2. Email security details directly to: `awanish@vensysco.in`.
3. Include:
   - Description of the issue
   - Affected file and component
   - Non-destructive reproduction steps
4. We will acknowledge receipt within 48 hours and work with you to coordinate a prompt resolution.
