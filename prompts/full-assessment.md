# AGY Prompt: Comprehensive Web Application Security Assessment

## Instruction for Coding Agent

Act as a Principal Application Security Architect, DevSecOps Lead, and Ethical Hacker. Perform an end-to-end authorized security assessment across the entire web application.

### Operational Guardrails
- **DO NOT** modify application source code unless explicitly requested by the user.
- **DO NOT** use destructive testing techniques, live credential harvesting, or unapproved targets.
- Target must be on the authorized allowlist (`localhost`, staging).

---

### Step 1: Pre-Assessment Reconnaissance & Target Validation
1. Verify target environment authorization and allowlist configuration.
2. Confirm health of the target via `/api/health` or root URL.
3. Map endpoints: authentication, profile, mutating operations, search, static downloads.

### Step 2: Automated Testing Execution
1. Execute the testing modules:
   - `npm run test:xss`
   - `npm run test:sqli`
   - `npm run test:csrf`
   - `npm run test:cors`
   - `npm run test:headers`
   - `npm run security:scan`
2. Record all confirmed findings, potential anomalies, and verified secure controls.

### Step 3: Deep Source Code Review
1. Inspect backend route handlers for injection, missing authorization middleware, and insecure configurations.
2. Inspect frontend components (React/HTML) for unsafe DOM sinks or sensitive data leakage in client-side storage.

### Step 4: Security Assessment Report Generation
Produce a complete security assessment report containing:
- Target application & URL
- Assessment date
- Tested endpoints
- Summary matrix by severity (Critical / High / Medium / Low / Informational)
- Detailed finding cards:
  - Finding ID
  - Category
  - Severity
  - Status (Confirmed / Potential / Secure)
  - Evidence (Sanitized)
  - Reproduction steps
  - Impact
  - Actionable code remediation
  - OWASP & CWE references

### Step 5: Executive Debrief & Remediation Roadmap
1. Summarize the top 3 highest-priority risks.
2. Provide a clear, sequenced remediation roadmap for the engineering team.
