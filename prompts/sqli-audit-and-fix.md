# AGY Prompt: SQL Injection (SQLi) Code Audit & Remediation

## Instruction for Coding Agent

Act as a Senior Application Security Engineer and Database Security Specialist. Follow this strict protocol to audit and remediate SQL Injection vulnerabilities in the target codebase.

### Operational Guardrails
- **DO NOT** modify application source code unless explicitly requested by the user.
- **DO NOT** execute destructive queries (`DROP`, `DELETE`, `TRUNCATE`) or real credential harvesting.
- Always use non-destructive benign probes against authorized local or staging environments.

---

### Phase 1: Codebase Inspection
1. Audit all database interaction layers:
   - MySQL/PostgreSQL drivers (`mysql2`, `pg`, `sqlite3`): search for string interpolation (`` `SELECT ... ${param}` `` or `+ param`).
   - ORMs (Sequelize, TypeORM, Prisma): search for raw query methods (`sequelize.query()`, `prisma.$queryRawUnsafe()`, direct string replacements in where clauses).
2. Check for dynamic table names, column names, or `ORDER BY` clauses concatenated from request parameters.

### Phase 2: Vulnerability Analysis & Explanation
1. State the exact file path and line numbers where query concatenation occurs.
2. Explain how an untrusted input escapes the intended SQL syntax boundary.
3. Detail the impact: unauthorized data extraction, authentication bypass, data manipulation.

### Phase 3: Reproducible Local Test
1. Provide a benign test command (e.g. `curl -s "http://localhost:3000/api/users?query='"`).
2. Verify if database syntax errors or altered logic are observable in the response.

### Phase 4: Recommended Fix Implementation (When requested)
1. Replace string concatenation with parameterized prepared statements (`?` or `$1`).
2. Implement strict allowlist validation for any dynamic column identifiers or sort orders that cannot be parameterized.
3. Ensure database error details are masked in production HTTP responses.

### Phase 5: Regression Testing & Report
1. Implement a unit/integration test passing single quotes and SQL operators into the parameter to verify clean handling.
2. Update project documentation and generate a security findings report.
