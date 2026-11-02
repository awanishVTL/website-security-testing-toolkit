const test = require('node:test');
const assert = require('node:assert');
const { validateTarget } = require('../lib/allowlist');

test('Target Allowlist Validation', async (t) => {
  await t.test('allows localhost and loopback addresses', () => {
    assert.strictEqual(validateTarget('http://localhost:3000').valid, true);
    assert.strictEqual(validateTarget('http://127.0.0.1:8080').valid, true);
  });

  await t.test('rejects unapproved external public domains', () => {
    const res = validateTarget('https://unauthorized-external-site.com');
    assert.strictEqual(res.valid, false);
    assert.match(res.error, /REFUSED/);
  });

  await t.test('rejects invalid URL strings', () => {
    assert.strictEqual(validateTarget('not-a-valid-url').valid, false);
    assert.strictEqual(validateTarget('').valid, false);
    assert.strictEqual(validateTarget(null).valid, false);
  });

  await t.test('rejects non-HTTP protocols', () => {
    const res = validateTarget('ftp://localhost:21');
    assert.strictEqual(res.valid, false);
    assert.match(res.error, /Unsupported protocol/);
  });
});
