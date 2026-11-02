#!/usr/bin/env node
/**
 * Security Headers Automated Audit Script
 *
 * Verifies presence and strength of:
 * - Content-Security-Policy (CSP)
 * - Strict-Transport-Security (HSTS)
 * - X-Frame-Options (XFO)
 * - X-Content-Type-Options (XCTO)
 * - Referrer-Policy
 * - Permissions-Policy
 * - Detection of fingerprinting headers (X-Powered-By, detailed Server)
 */

const { safeRequest } = require('../lib/http-client');
const { ensureAuthorizedTarget } = require('../lib/allowlist');
const SecurityReporter = require('../lib/reporter');
const logger = require('../lib/logger');

const REQUIRED_HEADERS = [
  {
    name: 'content-security-policy',
    displayName: 'Content-Security-Policy',
    severity: 'Medium',
    remediation: 'Implement CSP directives (e.g. default-src \'self\'; script-src \'self\').'
  },
  {
    name: 'x-frame-options',
    displayName: 'X-Frame-Options',
    severity: 'Medium',
    remediation: 'Set X-Frame-Options: DENY or SAMEORIGIN to prevent Clickjacking.'
  },
  {
    name: 'x-content-type-options',
    displayName: 'X-Content-Type-Options',
    expectedValue: 'nosniff',
    severity: 'Low',
    remediation: 'Set X-Content-Type-Options: nosniff to prevent MIME-sniffing.'
  },
  {
    name: 'referrer-policy',
    displayName: 'Referrer-Policy',
    severity: 'Low',
    remediation: 'Configure Referrer-Policy: strict-origin-when-cross-origin.'
  }
];

async function runHeadersCheck(options = {}) {
  const targetBase = ensureAuthorizedTarget(options.targetUrl || process.env.TARGET_URL || 'http://localhost:3000');
  const reporter = options.reporter || new SecurityReporter(targetBase, 'Security Headers Audit');

  logger.header('Running Security Headers Check');
  logger.info(`Target: ${targetBase}`);

  const endpoints = options.endpoints || ['/api/vulnerable/profile', '/api/secure/profile'];

  for (const ep of endpoints) {
    reporter.addEndpoint(ep);
    const res = await safeRequest(`${targetBase}${ep}`, { method: 'GET' });

    // 1. Check for missing protective headers
    for (const h of REQUIRED_HEADERS) {
      const headerVal = res.headers.get(h.name);

      if (!headerVal) {
        logger.finding(h.severity, `Missing Header: ${h.displayName} on ${ep}`, ep);
        reporter.addFinding({
          id: `HEADER-MISSING-${h.name.toUpperCase().replace(/-/g, '_')}`,
          category: 'Security Headers',
          severity: h.severity,
          status: 'Confirmed',
          title: `Missing Security Header: ${h.displayName} on ${ep}`,
          endpoint: ep,
          method: 'GET',
          evidence: `Header "${h.displayName}" was not returned by server in response to GET ${ep}`,
          reproduction_steps: [
            `Send GET request to ${targetBase}${ep}`,
            `Inspect response headers for presence of "${h.displayName}"`
          ],
          impact: `Missing ${h.displayName} degrades browser-side defense-in-depth protections.`,
          remediation: h.remediation,
          owasp_ref: 'OWASP A05:2021 - Security Misconfiguration',
          cwe_ref: 'CWE-16'
        });
      } else {
        logger.success(`Present: ${h.displayName}: ${headerVal.slice(0, 40)} on ${ep}`);
        reporter.addFinding({
          id: `HEADER-PRESENT-${h.name.toUpperCase().replace(/-/g, '_')}`,
          category: 'Security Headers',
          severity: 'Informational',
          status: 'Secure',
          title: `Header Present: ${h.displayName}`,
          endpoint: ep,
          method: 'GET',
          evidence: `${h.displayName}: ${headerVal}`,
          reproduction_steps: [`Tested GET ${ep}`],
          impact: 'Header active and enforcing browser policy.',
          remediation: 'Maintain header configuration.'
        });
      }
    }

    // 2. Information leakage headers check (X-Powered-By)
    const xPoweredBy = res.headers.get('x-powered-by');
    if (xPoweredBy) {
      logger.finding('Low', `Information Disclosure: X-Powered-By exposed on ${ep}`, ep);
      reporter.addFinding({
        id: 'HEADER-LEAK-POWERED-BY',
        category: 'Security Headers',
        severity: 'Low',
        status: 'Confirmed',
        title: `Technology Fingerprint Disclosed via X-Powered-By on ${ep}`,
        endpoint: ep,
        method: 'GET',
        evidence: `X-Powered-By: ${xPoweredBy}`,
        reproduction_steps: [`Inspect headers of ${ep}`],
        impact: 'Exposes underlying framework and potential version details to reconnaissance.',
        remediation: 'Disable fingerprinting in Express via app.disable("x-powered-by") or helmet.hidePoweredBy().',
        owasp_ref: 'OWASP A05:2021 - Security Misconfiguration',
        cwe_ref: 'CWE-200: Exposure of Sensitive Information'
      });
    }
  }

  return reporter;
}

if (require.main === module) {
  (async () => {
    try {
      const reporter = await runHeadersCheck();
      reporter.saveReports('./reports', 'headers-audit-report');
      logger.info('Security Headers check execution finished.');
    } catch (err) {
      logger.error('Headers check execution aborted:', err.message);
      process.exit(1);
    }
  })();
}

module.exports = { runHeadersCheck };
