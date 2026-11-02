const test = require('node:test');
const assert = require('node:assert');
const { ConcurrencyLimiter, safeRequest } = require('../lib/http-client');

test('HTTP Client & Guardrails', async (t) => {
  await t.test('limits concurrency accurately', async () => {
    const limiter = new ConcurrencyLimiter(2);
    let activeMax = 0;
    let currentlyRunning = 0;

    const worker = async () => {
      return limiter.run(async () => {
        currentlyRunning++;
        if (currentlyRunning > activeMax) activeMax = currentlyRunning;
        await new Promise(r => setTimeout(r, 20));
        currentlyRunning--;
      });
    };

    await Promise.all([worker(), worker(), worker(), worker()]);
    assert.strictEqual(activeMax <= 2, true);
  });

  await t.test('blocks potentially destructive HTTP methods', async () => {
    await assert.rejects(
      async () => {
        await safeRequest('http://localhost:3000/api/users', { method: 'DELETE' });
      },
      /potentially destructive and is disallowed/
    );
  });
});
