# AGY Prompt: Authorization & IDOR Code Audit & Remediation

## Instruction for Coding Agent

Act as a Senior Application Security Engineer and Access Control Auditor. Audit and remediate Insecure Direct Object References (IDOR) and broken authorization flaws.

### Operational Guardrails
- **DO NOT** modify application source code unless explicitly requested by the user.
- Strictly adhere to non-destructive verification against local/test data only.

---

### Phase 1: Codebase Inspection
1. Map all API routes taking resource identifiers (`req.params.id`, `req.query.id`, `req.body.id`).
2. Verify if the database queries enforce user ownership:
   - Does `SELECT * FROM orders WHERE id = ?` also include `AND user_id = req.user.id`?
3. Audit administrative endpoints for missing role-checking middleware.
4. Check for mass assignment vulnerabilities where `req.body` is passed unfiltered into `UPDATE` queries.

### Phase 2: Vulnerability Analysis & Explanation
1. State the file and line numbers where object lookup lacks ownership checks.
2. Explain the mechanism: how an unprivileged user can manipulate the parameter to access foreign objects.
3. Detail impact: confidential record exposure, unauthorized record modification or deletion.

### Phase 3: Reproducible Local Test
1. Provide reproducible curl commands simulating User A accessing User B's resource ID.
2. Show the difference between vulnerable response (data leaked) and secure response (HTTP 403 / 404).

### Phase 4: Recommended Fix Implementation (When requested)
1. Add ownership constraints directly to database queries.
2. Implement role-based authorization middleware (`requireRole('admin')`).
3. Apply schema validation and field destructuring to prevent mass assignment.

### Phase 5: Regression Testing & Report
1. Add integration tests verifying that requests with mismatched ownership IDs return HTTP 403 or 404.
2. Generate an authorization assessment report.
