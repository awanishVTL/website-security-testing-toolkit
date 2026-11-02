# AGY Prompt: Security Headers & CORS Misconfiguration Audit & Remediation

## Instruction for Coding Agent

Act as a Senior Application Security Engineer and DevSecOps Specialist. Audit and harden HTTP response headers and Cross-Origin Resource Sharing (CORS) policies.

### Operational Guardrails
- **DO NOT** modify application source code unless explicitly requested by the user.
- Strictly adhere to non-destructive verification against authorized targets.

---

### Phase 1: Codebase Inspection
1. Inspect Express app setup for `helmet` or custom header middlewares.
2. Check for missing essential security headers:
   - `Content-Security-Policy`
   - `Strict-Transport-Security`
   - `X-Frame-Options`
   - `X-Content-Type-Options`
   - `Referrer-Policy`
3. Audit CORS middleware (`cors()`):
   - Check if `origin` echoes `req.headers.origin` dynamically with `credentials: true`.
   - Check if wildcard `*` is paired with credentials.
   - Check if `null` origin is allowed.
4. Check if technology disclosure headers (`X-Powered-By`) are enabled.

### Phase 2: Vulnerability Analysis & Explanation
1. State the exact configuration files where headers and CORS are declared.
2. Explain the risk: clickjacking without `X-Frame-Options`, cross-origin data theft via permissive CORS, MIME sniffing attacks without `nosniff`.

### Phase 3: Reproducible Local Test
1. Provide a `curl -I` command inspecting response headers.
2. Provide a `curl -H "Origin: https://attacker.test"` command showing arbitrary origin reflection.

### Phase 4: Recommended Fix Implementation (When requested)
1. Deploy `helmet()` with tailored CSP and HSTS configuration.
2. Replace dynamic CORS origin reflection with an explicit array allowlist.
3. Suppress `X-Powered-By` header using `app.disable('x-powered-by')`.

### Phase 5: Regression Testing & Report
1. Add automated checks verifying required headers exist on all responses.
2. Generate headers and CORS audit report section.
