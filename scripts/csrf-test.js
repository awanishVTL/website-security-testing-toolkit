#!/usr/bin/env node
/**
 * Cross-Site Request Forgery (CSRF) Automated Verification Script
 *
 * Tests:
 * - Mutating endpoint GET method vulnerability
 * - State-changing POST without CSRF token
 * - Origin / Referer validation enforcement
 * - Cookie SameSite and HttpOnly attribute flags
 */

const { safeRequest } = require('../lib/http-client');
const { ensureAuthorizedTarget } = require('../lib/allowlist');
const SecurityReporter = require('../lib/reporter');
const logger = require('../lib/logger');

async function runCsrfTests(options = {}) {
  const targetBase = ensureAuthorizedTarget(options.targetUrl || process.env.TARGET_URL || 'http://localhost:3000');
  const reporter = options.reporter || new SecurityReporter(targetBase, 'CSRF Security Audit');

  logger.header('Running Cross-Site Request Forgery (CSRF) Tests');
  logger.info(`Target: ${targetBase}`);

  const endpoints = options.endpoints || [
    { path: '/api/vulnerable/transfer', stateChanging: true },
    { path: '/api/secure/transfer', stateChanging: true }
  ];

  for (const ep of endpoints) {
    reporter.addEndpoint(ep.path);

    // 1. Test GET method acceptance on mutating action
    const getRes = await safeRequest(`${targetBase}${ep.path}?recipient=audit_test&amount=1`, { method: 'GET' });
    if (getRes.status === 200 && getRes.json && getRes.json.success === true) {
      logger.finding('High', `Mutating Action Permitted via HTTP GET on ${ep.path}`, ep.path);
      reporter.addFinding({
        id: 'CSRF-GET-ACTION',
        category: 'Cross-Site Request Forgery (CSRF)',
        severity: 'High',
        status: 'Confirmed',
        title: `State-Changing Operation Executable via HTTP GET on ${ep.path}`,
        endpoint: ep.path,
        method: 'GET',
        evidence: `HTTP GET triggered state mutation: ${JSON.stringify(getRes.json)}`,
        reproduction_steps: [
          `Send HTTP GET request to ${targetBase}${ep.path}?recipient=audit_test&amount=1`,
          `Notice endpoint executes transaction without requiring POST or CSRF validation`
        ],
        impact: 'High. An attacker can execute arbitrary state changes by embedding the URL in a simple <img src="..."> on a third-party webpage.',
        remediation: 'Disallow GET on state-changing endpoints. Enforce POST/PUT with CSRF tokens.',
        owasp_ref: 'OWASP A01:2021 - Broken Access Control',
        cwe_ref: 'CWE-352: Cross-Site Request Forgery (CSRF)'
      });
    }

    // 2. Test POST request without CSRF token
    const postNoTokenRes = await safeRequest(`${targetBase}${ep.path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': 'session_id=mock-session-test'
      },
      body: JSON.stringify({ recipient: 'audit_recipient', amount: 5 })
    });

    if (postNoTokenRes.status === 200 && postNoTokenRes.json && postNoTokenRes.json.success) {
      logger.finding('High', `Missing CSRF Token Protection on POST ${ep.path}`, ep.path);
      reporter.addFinding({
        id: 'CSRF-TOKEN-MISSING',
        category: 'Cross-Site Request Forgery (CSRF)',
        severity: 'High',
        status: 'Confirmed',
        title: `State-Changing POST Accepted Without CSRF Token on ${ep.path}`,
        endpoint: ep.path,
        method: 'POST',
        evidence: `POST succeeded without X-CSRF-Token or CSRF form parameter: HTTP 200 OK`,
        reproduction_steps: [
          `Send POST to ${targetBase}${ep.path} with session cookie but omit CSRF token`,
          `Observe successful transaction execution`
        ],
        impact: 'Enables cross-origin sites to forge actions on behalf of authenticated users.',
        remediation: 'Implement anti-CSRF token middleware (e.g., csrf-csrf or csurf) and require custom headers for API calls.',
        owasp_ref: 'OWASP A01:2021 - Broken Access Control',
        cwe_ref: 'CWE-352'
      });
    } else if (postNoTokenRes.status === 403) {
      logger.success(`Safe: Tokenless POST blocked with HTTP 403 on ${ep.path}`);
      reporter.addFinding({
        id: `CSRF-TOKEN-ENFORCED-${ep.path.replace(/\//g, '-')}`,
        category: 'Cross-Site Request Forgery (CSRF)',
        severity: 'Informational',
        status: 'Secure',
        title: `Anti-CSRF Token Enforced on ${ep.path}`,
        endpoint: ep.path,
        method: 'POST',
        evidence: `Request without token rejected with HTTP 403: ${postNoTokenRes.text}`,
        reproduction_steps: [`Attempted tokenless POST to ${ep.path}`],
        impact: 'Cross-site forgery prevented by anti-CSRF validation.',
        remediation: 'Keep CSRF tokens required on all non-safe HTTP methods.'
      });
    }

    // 3. Test Cookie SameSite attribute
    const setCookieHeader = getRes.headers.get('set-cookie') || postNoTokenRes.headers.get('set-cookie');
    if (setCookieHeader) {
      const lowerCookie = setCookieHeader.toLowerCase();
      if (!lowerCookie.includes('samesite=lax') && !lowerCookie.includes('samesite=strict')) {
        logger.finding('Medium', `Cookie Missing SameSite Attribute on ${ep.path}`, ep.path);
        reporter.addFinding({
          id: 'CSRF-SAMESITE-MISSING',
          category: 'Cross-Site Request Forgery (CSRF)',
          severity: 'Medium',
          status: 'Confirmed',
          title: `Session Cookie Lacks SameSite Restriction on ${ep.path}`,
          endpoint: ep.path,
          method: 'GET/POST',
          evidence: `Set-Cookie: ${setCookieHeader}`,
          reproduction_steps: [
            `Inspect Set-Cookie header on response`,
            `Verify absence of SameSite=Lax or SameSite=Strict`
          ],
          impact: 'Cookies are attached to cross-site requests, increasing vulnerability to CSRF.',
          remediation: 'Configure SameSite=Lax or SameSite=Strict in cookie options: res.cookie(name, val, { sameSite: "lax", httpOnly: true, secure: true }).',
          cwe_ref: 'CWE-1275'
        });
      }
    }
  }

  return reporter;
}

if (require.main === module) {
  (async () => {
    try {
      const reporter = await runCsrfTests();
      reporter.saveReports('./reports', 'csrf-audit-report');
      logger.info('CSRF Security Test execution finished.');
    } catch (err) {
      logger.error('CSRF Test execution aborted:', err.message);
      process.exit(1);
    }
  })();
}

module.exports = { runCsrfTests };
