# AGY Prompt: Cross-Site Request Forgery (CSRF) Audit & Remediation

## Instruction for Coding Agent

Act as a Senior Application Security Engineer. Follow this strict protocol to audit and remediate Cross-Site Request Forgery (CSRF) vulnerabilities.

### Operational Guardrails
- **DO NOT** modify application source code unless explicitly requested by the user.
- Strictly adhere to non-destructive verification.

---

### Phase 1: Codebase Inspection
1. Identify all state-changing endpoints (`POST`, `PUT`, `DELETE`, `PATCH`).
2. Verify if sensitive actions are inadvertently reachable via `GET`.
3. Check for the presence of anti-CSRF token middleware (`csrf-csrf`, `csurf`, double-submit cookies).
4. Inspect cookie configurations for `SameSite`, `HttpOnly`, and `Secure` attributes.
5. Inspect `Origin` and `Referer` validation logic.

### Phase 2: Vulnerability Analysis & Explanation
1. Point to the routes accepting state changes without token or origin validation.
2. Explain the mechanism: how an attacker can leverage ambient browser credentials to forge requests.
3. Quantify impact (unauthorized profile edits, password resets, financial transfers).

### Phase 3: Reproducible Local Test
1. Provide a `curl` reproduction demonstrating that a `POST` request with session cookies but omitting anti-CSRF tokens succeeds with HTTP 200.
2. Provide a safe HTML proof-of-concept form simulating a third-party site origin.

### Phase 4: Recommended Fix Implementation (When requested)
1. Implement anti-CSRF middleware (e.g. `csrf-csrf`).
2. Configure session cookies with `sameSite: 'lax'` or `'strict'`.
3. Disallow state mutations on `GET` requests.
4. Add Origin header validation.

### Phase 5: Regression Testing & Report
1. Add integration tests verifying that requests lacking valid CSRF tokens receive HTTP 403 Forbidden.
2. Document the anti-CSRF architecture and update the security assessment report.
