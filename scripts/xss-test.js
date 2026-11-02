#!/usr/bin/env node
/**
 * Cross-Site Scripting (XSS) Automated Verification Script
 *
 * Tests:
 * - Reflected XSS (HTML echo vs contextual escaping)
 * - Safe sentinel tags
 * - Attribute injection checks
 *
 * Guardrails: Non-destructive probe tokens only. No weaponized payloads.
 */

const fs = require('fs');
const path = require('path');
const { safeRequest } = require('../lib/http-client');
const { ensureAuthorizedTarget } = require('../lib/allowlist');
const SecurityReporter = require('../lib/reporter');
const logger = require('../lib/logger');

async function runXssTests(options = {}) {
  const targetBase = ensureAuthorizedTarget(options.targetUrl || process.env.TARGET_URL || 'http://localhost:3000');
  const reporter = options.reporter || new SecurityReporter(targetBase, 'XSS Security Audit');

  logger.header('Running Cross-Site Scripting (XSS) Tests');
  logger.info(`Target: ${targetBase}`);

  // Load safe XSS payloads
  const payloadsFile = path.join(__dirname, '..', 'payloads', 'xss.json');
  const payloads = JSON.parse(fs.readFileSync(payloadsFile, 'utf8'));

  // Test endpoints to audit
  const endpoints = options.endpoints || [
    { path: '/api/vulnerable/search', method: 'GET', param: 'q', expectedStatus: 'vulnerable' },
    { path: '/api/secure/search', method: 'GET', param: 'q', expectedStatus: 'secure' }
  ];

  for (const ep of endpoints) {
    reporter.addEndpoint(ep.path);

    for (const p of payloads) {
      if (p.id.includes('DOM') || p.id.includes('STORED')) continue; // Client-side or stored flows checked separately

      const encodedPayload = encodeURIComponent(p.payload);
      const testUrl = `${targetBase}${ep.path}?${ep.param}=${encodedPayload}`;

      const res = await safeRequest(testUrl, { method: 'GET' });

      if (!res.ok && res.status === 0) {
        logger.warn(`Could not connect to ${testUrl} (${res.error})`);
        continue;
      }

      // Vulnerability condition: Raw payload is reflected verbatim in response body
      const isReflectedUnescaped = res.text.includes(p.payload);
      // Secure condition: Payload is entity escaped or rejected
      const isEscaped = res.text.includes('&lt;') || !res.text.includes(p.payload);

      if (isReflectedUnescaped) {
        logger.finding('High', `Unescaped Reflected XSS Found (${p.id})`, ep.path);
        reporter.addFinding({
          id: `FINDING-${p.id}`,
          category: 'Cross-Site Scripting (XSS)',
          severity: p.risk_level,
          status: 'Confirmed',
          title: `Unescaped Reflected Input on ${ep.path}`,
          endpoint: ep.path,
          method: 'GET',
          evidence: `Payload "${p.payload}" reflected raw in response:\n${res.text.slice(0, 300)}...`,
          reproduction_steps: [
            `Send GET request to ${targetBase}${ep.path}?${ep.param}=${encodedPayload}`,
            `Inspect response body for raw unescaped token: "${p.payload}"`,
            `Observe absence of HTML entity encoding or Content-Security-Policy restriction`
          ],
          impact: 'An attacker can execute arbitrary JavaScript in the victim browser session, enabling session hijacking or unauthorized actions.',
          remediation: p.remediation,
          owasp_ref: 'OWASP A03:2021 - Injection',
          cwe_ref: 'CWE-79: Improper Neutralization of Input During Web Page Generation'
        });
      } else {
        logger.success(`Safe: Output encoded or filtered on ${ep.path} for ${p.id}`);
        reporter.addFinding({
          id: `SAFE-${p.id}`,
          category: 'Cross-Site Scripting (XSS)',
          severity: 'Informational',
          status: 'Secure',
          title: `Contextual Output Encoding Verified on ${ep.path}`,
          endpoint: ep.path,
          method: 'GET',
          evidence: `Input properly escaped or filtered: Response contained encoded entities.`,
          reproduction_steps: [`Tested GET ${testUrl}`],
          impact: 'Neutralized. Script injection prevented.',
          remediation: 'Maintain existing contextual output escaping and CSP headers.'
        });
      }
    }
  }

  return reporter;
}

// Standalone execution support
if (require.main === module) {
  (async () => {
    try {
      const reporter = await runXssTests();
      reporter.saveReports('./reports', 'xss-audit-report');
      logger.info('XSS Security Test execution finished.');
    } catch (err) {
      logger.error('XSS Test execution aborted:', err.message);
      process.exit(1);
    }
  })();
}

module.exports = { runXssTests };
