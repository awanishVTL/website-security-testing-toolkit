#!/usr/bin/env node
/**
 * Master Security Scan Orchestrator
 *
 * Runs comprehensive authorized security assessments against approved targets.
 * Integrates:
 * - Cross-Site Scripting (XSS)
 * - SQL Injection (SQLi)
 * - Cross-Site Request Forgery (CSRF)
 * - CORS Misconfiguration
 * - Security Headers
 * - Authorization (IDOR)
 *
 * Produces structured JSON and Markdown audit reports.
 */

const { ensureAuthorizedTarget } = require('../lib/allowlist');
const { safeRequest } = require('../lib/http-client');
const SecurityReporter = require('../lib/reporter');
const logger = require('../lib/logger');

const { runXssTests } = require('./xss-test');
const { runSqliTests } = require('./sqli-test');
const { runCsrfTests } = require('./csrf-test');
const { runCorsTests } = require('./cors-test');
const { runHeadersCheck } = require('./headers-check');

async function checkIdor(targetBase, reporter) {
  logger.header('Running Authorization & IDOR Checks');
  reporter.addEndpoint('/api/vulnerable/idor/user/:id');
  reporter.addEndpoint('/api/secure/idor/user/:id');

  // Test vulnerable endpoint: requesting ID 99 without credentials
  const vulnRes = await safeRequest(`${targetBase}/api/vulnerable/idor/user/99`, { method: 'GET' });
  if (vulnRes.status === 200 && vulnRes.json && vulnRes.json.user) {
    logger.finding('High', 'IDOR: Unauthorized Record Retrieval on /api/vulnerable/idor/user/99', '/api/vulnerable/idor/user/99');
    reporter.addFinding({
      id: 'IDOR-UNAUTH-READ',
      category: 'Authorization (IDOR)',
      severity: 'High',
      status: 'Confirmed',
      title: 'Insecure Direct Object Reference (IDOR) on User Profile API',
      endpoint: '/api/vulnerable/idor/user/99',
      method: 'GET',
      evidence: `Record retrieved without session ownership check: ${JSON.stringify(vulnRes.json.user)}`,
      reproduction_steps: [
        `Send GET to ${targetBase}/api/vulnerable/idor/user/99`,
        `Observe full user object returned despite lack of administrator privileges`
      ],
      impact: 'High. Allows any caller to enumerate and read sensitive profile records belonging to other users.',
      remediation: 'Verify that req.session.userId === requestedUserId or check ownership in the database query.',
      owasp_ref: 'OWASP A01:2021 - Broken Access Control',
      cwe_ref: 'CWE-639: Authorization Bypass Through User-Controlled Key'
    });
  }

  // Test secure endpoint
  const secRes = await safeRequest(`${targetBase}/api/secure/idor/user/99`, { method: 'GET' });
  if (secRes.status === 403) {
    logger.success('Safe: IDOR attempt rejected with HTTP 403 on /api/secure/idor/user/99');
    reporter.addFinding({
      id: 'IDOR-SECURE-ENFORCED',
      category: 'Authorization (IDOR)',
      severity: 'Informational',
      status: 'Secure',
      title: 'Object Ownership Verified on User Profile Endpoint',
      endpoint: '/api/secure/idor/user/99',
      method: 'GET',
      evidence: `Request for unauthorized ID was rejected with HTTP 403 Forbidden`,
      reproduction_steps: [`Requested ID 99 on secure endpoint`],
      impact: 'Unauthorized access prevented.',
      remediation: 'Maintain object-level ownership checks.'
    });
  }
}

async function runSecurityScan() {
  const targetBase = ensureAuthorizedTarget(process.env.TARGET_URL || 'http://localhost:3000');
  const appName = process.env.APP_NAME || 'Web Application Assessment Lab';
  const reporter = new SecurityReporter(targetBase, appName);

  console.log(`\n======================================================`);
  console.log(` WEBSITE SECURITY TESTING TOOLKIT - MASTER SCANNER`);
  console.log(` Target: ${targetBase}`);
  console.log(` Date:   ${new Date().toISOString()}`);
  console.log(`======================================================\n`);

  // 1. Verify target connectivity
  logger.info(`Pinging target health: ${targetBase}/api/health...`);
  const healthRes = await safeRequest(`${targetBase}/api/health`, { method: 'GET' }, 3000);
  if (!healthRes.ok && healthRes.status === 0) {
    logger.error(`Target at ${targetBase} is unreachable (${healthRes.error}).`);
    logger.info(`If testing locally, start the fixture first with: npm run fixture:start`);
    process.exit(1);
  }
  logger.success(`Target responded: HTTP ${healthRes.status}`);

  // 2. Run modules
  await runXssTests({ targetUrl: targetBase, reporter });
  await runSqliTests({ targetUrl: targetBase, reporter });
  await runCsrfTests({ targetUrl: targetBase, reporter });
  await runCorsTests({ targetUrl: targetBase, reporter });
  await runHeadersCheck({ targetUrl: targetBase, reporter });
  await checkIdor(targetBase, reporter);

  // 3. Save comprehensive reports
  const outputDir = process.env.REPORT_OUTPUT_DIR || './reports';
  const reportFiles = reporter.saveReports(outputDir, 'master-security-scan-report');

  // 4. Print Executive Summary
  const summary = reporter.getSummary();
  logger.divider();
  console.log(`\nEXECUTIVE SCAN SUMMARY:`);
  console.log(`- Total Findings:   ${summary.total_findings}`);
  console.log(`- Confirmed Issues: ${summary.confirmed}`);
  console.log(`- Potential Issues: ${summary.potential}`);
  console.log(`- Verified Controls:${summary.secure}`);
  console.log(`- Critical:         ${summary.by_severity.Critical}`);
  console.log(`- High:             ${summary.by_severity.High}`);
  console.log(`- Medium:           ${summary.by_severity.Medium}`);
  console.log(`- Low:              ${summary.by_severity.Low}`);
  console.log(`\nAudit artifacts generated:`);
  console.log(`- Markdown Report:  ${reportFiles.mdPath}`);
  console.log(`- JSON Report:      ${reportFiles.jsonPath}\n`);

  return reporter;
}

if (require.main === module) {
  runSecurityScan().catch(err => {
    logger.error('Master scan failed:', err.message);
    process.exit(1);
  });
}

module.exports = { runSecurityScan };
