#!/usr/bin/env node
/**
 * Cross-Origin Resource Sharing (CORS) Automated Verification Script
 *
 * Tests:
 * - Arbitrary origin reflection
 * - Null origin reflection
 * - Permissive wildcard + credentials misconfigurations
 */

const { safeRequest } = require('../lib/http-client');
const { ensureAuthorizedTarget } = require('../lib/allowlist');
const SecurityReporter = require('../lib/reporter');
const logger = require('../lib/logger');

async function runCorsTests(options = {}) {
  const targetBase = ensureAuthorizedTarget(options.targetUrl || process.env.TARGET_URL || 'http://localhost:3000');
  const reporter = options.reporter || new SecurityReporter(targetBase, 'CORS Misconfiguration Audit');

  logger.header('Running CORS Misconfiguration Tests');
  logger.info(`Target: ${targetBase}`);

  const endpoints = options.endpoints || [
    '/api/vulnerable/profile',
    '/api/secure/profile'
  ];

  const testOrigins = [
    { name: 'arbitrary_origin', origin: 'https://unauthorized-attacker.test' },
    { name: 'null_origin', origin: 'null' }
  ];

  for (const ep of endpoints) {
    reporter.addEndpoint(ep);

    for (const t of testOrigins) {
      const res = await safeRequest(`${targetBase}${ep}`, {
        method: 'GET',
        headers: {
          'Origin': t.origin
        }
      });

      const acao = res.headers.get('access-control-allow-origin');
      const acac = res.headers.get('access-control-allow-credentials');

      if (acao === t.origin && acac === 'true') {
        logger.finding('High', `Permissive CORS with Credentials on ${ep} (${t.name})`, ep);
        reporter.addFinding({
          id: `CORS-VULN-${t.name.toUpperCase()}`,
          category: 'CORS Misconfiguration',
          severity: 'High',
          status: 'Confirmed',
          title: `Arbitrary Origin Reflected with Credentials Allowed on ${ep}`,
          endpoint: ep,
          method: 'GET',
          evidence: `Origin: ${t.origin} reflected in Access-Control-Allow-Origin: ${acao} with Access-Control-Allow-Credentials: ${acac}`,
          reproduction_steps: [
            `Send GET to ${targetBase}${ep} with header 'Origin: ${t.origin}'`,
            `Verify response contains 'Access-Control-Allow-Origin: ${acao}' and 'Access-Control-Allow-Credentials: true'`
          ],
          impact: 'High. Untrusted external web origins can read sensitive user data and bypass browser SOP.',
          remediation: 'Replace dynamic origin reflection with a static allowlist of trusted origins.',
          owasp_ref: 'OWASP A05:2021 - Security Misconfiguration',
          cwe_ref: 'CWE-346: Origin Validation Error'
        });
      } else if (acao === '*' && acac === 'true') {
        logger.finding('High', `Invalid CORS: Wildcard with Credentials on ${ep}`, ep);
        reporter.addFinding({
          id: 'CORS-WILDCARD-CREDS',
          category: 'CORS Misconfiguration',
          severity: 'High',
          status: 'Confirmed',
          title: `Wildcard Origin Paired with Credentials on ${ep}`,
          endpoint: ep,
          method: 'GET',
          evidence: `ACAO: *, ACAC: true`,
          reproduction_steps: [`Test origin headers on ${ep}`],
          impact: 'Browser security violation and misconfigured cross-origin sharing.',
          remediation: 'Specify explicit origins when using credentials.',
          owasp_ref: 'OWASP A05:2021 - Security Misconfiguration'
        });
      } else {
        logger.success(`Safe: Origin "${t.origin}" rejected or unreflected on ${ep}`);
        reporter.addFinding({
          id: `CORS-SAFE-${ep.replace(/\//g, '-')}-${t.name}`,
          category: 'CORS Misconfiguration',
          severity: 'Informational',
          status: 'Secure',
          title: `Strict CORS Origin Handling on ${ep}`,
          endpoint: ep,
          method: 'GET',
          evidence: `Untrusted origin was not reflected. ACAO: ${acao || 'None'}`,
          reproduction_steps: [`Tested GET with Origin: ${t.origin}`],
          impact: 'Unauthorized cross-origin reading prevented.',
          remediation: 'Maintain origin allowlisting.'
        });
      }
    }
  }

  return reporter;
}

if (require.main === module) {
  (async () => {
    try {
      const reporter = await runCorsTests();
      reporter.saveReports('./reports', 'cors-audit-report');
      logger.info('CORS Security Test execution finished.');
    } catch (err) {
      logger.error('CORS Test execution aborted:', err.message);
      process.exit(1);
    }
  })();
}

module.exports = { runCorsTests };
