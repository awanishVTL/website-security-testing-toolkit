/**
 * Safe HTTP Client for Security Assessment
 *
 * Implements:
 * - Request timeouts (AbortController)
 * - Safe concurrency throttling
 * - Guardrails against destructive HTTP methods (DELETE, DROP, etc.)
 * - Non-destructive probe headers
 */

const { validateTarget } = require('./allowlist');
const logger = require('./logger');

const DEFAULT_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS || '5000', 10);
const DEFAULT_CONCURRENCY = parseInt(process.env.MAX_CONCURRENCY || '5', 10);
const USER_AGENT = process.env.USER_AGENT || 'WebSecTestToolkit/1.0 (+AuthorizedSecurityAssessment; Non-Destructive)';

// Disallowed destructive HTTP methods
const DISALLOWED_METHODS = new Set(['DELETE', 'TRACE', 'CONNECT']);

class ConcurrencyLimiter {
  constructor(limit = 5) {
    this.limit = limit;
    this.active = 0;
    this.queue = [];
  }

  async run(fn) {
    if (this.active >= this.limit) {
      await new Promise(resolve => this.queue.push(resolve));
    }
    this.active++;
    try {
      return await fn();
    } finally {
      this.active--;
      if (this.queue.length > 0) {
        const next = this.queue.shift();
        next();
      }
    }
  }
}

const globalLimiter = new ConcurrencyLimiter(DEFAULT_CONCURRENCY);

/**
 * Executes a safe, non-destructive HTTP request.
 * @param {string} url - Target URL
 * @param {object} options - Fetch options
 * @param {number} [timeoutMs] - Request timeout in milliseconds
 * @returns {Promise<{ status: number, headers: Headers, text: string, json: any, durationMs: number, error?: string }>}
 */
async function safeRequest(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  // 1. Validate target authorization
  const val = validateTarget(url);
  if (!val.valid) {
    throw new Error(val.error);
  }

  // 2. Guard against destructive HTTP methods
  const method = (options.method || 'GET').toUpperCase();
  if (DISALLOWED_METHODS.has(method)) {
    throw new Error(`Execution blocked: Method "${method}" is considered potentially destructive and is disallowed in this toolkit.`);
  }

  return globalLimiter.run(async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const start = Date.now();

    const requestHeaders = {
      'User-Agent': USER_AGENT,
      'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
      'X-Security-Scan': 'Authorized-Test',
      ...(options.headers || {})
    };

    try {
      const response = await fetch(url, {
        ...options,
        method,
        headers: requestHeaders,
        signal: controller.signal
      });

      const text = await response.text();
      let parsedJson = null;
      try {
        parsedJson = JSON.parse(text);
      } catch {
        // Response is HTML or plain text
      }

      const durationMs = Date.now() - start;

      return {
        ok: response.ok,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        text,
        json: parsedJson,
        durationMs
      };
    } catch (err) {
      const durationMs = Date.now() - start;
      if (err.name === 'AbortError') {
        return {
          ok: false,
          status: 0,
          statusText: 'Timeout',
          headers: new Headers(),
          text: '',
          json: null,
          durationMs,
          error: `Request timed out after ${timeoutMs}ms`
        };
      }
      return {
        ok: false,
        status: 0,
        statusText: 'Network Error',
        headers: new Headers(),
        text: '',
        json: null,
        durationMs,
        error: err.message
      };
    } finally {
      clearTimeout(timeout);
    }
  });
}

module.exports = {
  safeRequest,
  ConcurrencyLimiter,
  DEFAULT_TIMEOUT_MS
};
