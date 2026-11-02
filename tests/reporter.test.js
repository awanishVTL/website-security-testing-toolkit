const test = require('node:test');
const assert = require('node:assert');
const SecurityReporter = require('../lib/reporter');

test('SecurityReporter and Sanitizer', async (t) => {
  await t.test('initializes with default metrics', () => {
    const reporter = new SecurityReporter('http://localhost:3000', 'Test App');
    const summary = reporter.getSummary();
    assert.strictEqual(summary.total_findings, 0);
    assert.strictEqual(summary.confirmed, 0);
  });

  await t.test('redacts sensitive credentials from evidence', () => {
    const reporter = new SecurityReporter('http://localhost:3000', 'Test App');
    reporter.addFinding({
      id: 'TEST-001',
      category: 'Test Category',
      severity: 'High',
      status: 'Confirmed',
      title: 'Credential Leak Test',
      endpoint: '/api/login',
      method: 'POST',
      evidence: 'password=SuperSecretPassword123&token=abcd1234efgh',
      reproduction_steps: ['Submit password=SuperSecretPassword123'],
      impact: 'Test impact',
      remediation: 'Do not log credentials'
    });

    const json = reporter.toJSON();
    const finding = json.findings[0];
    assert.strictEqual(finding.evidence.includes('SuperSecretPassword123'), false);
    assert.match(finding.evidence, /password=\[REDACTED\]/);
    assert.match(finding.evidence, /token=\[REDACTED\]/);
  });

  await t.test('generates markdown report containing key sections', () => {
    const reporter = new SecurityReporter('http://localhost:3000', 'Test App');
    reporter.addEndpoint('/api/test');
    reporter.addFinding({
      id: 'XSS-001',
      category: 'Cross-Site Scripting (XSS)',
      severity: 'High',
      status: 'Confirmed',
      title: 'Reflected XSS Test',
      endpoint: '/api/test',
      method: 'GET',
      evidence: '<script>alert(1)</script>',
      reproduction_steps: ['Step 1', 'Step 2'],
      impact: 'Session hijacking',
      remediation: 'HTML encode output'
    });

    const md = reporter.toMarkdown();
    assert.match(md, /# Security Assessment Report/);
    assert.match(md, /## Executive Summary/);
    assert.match(md, /## Findings Matrix/);
    assert.match(md, /## Confirmed Vulnerabilities/);
    assert.match(md, /XSS-001/);
  });
});
