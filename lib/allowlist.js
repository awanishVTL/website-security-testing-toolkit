/**
 * Target Validation & Allowlist Enforcement
 *
 * Prevents unintended scans against unauthorized or production systems.
 * Refuses public external targets unless explicitly allowed.
 */

const fs = require('fs');
const path = require('path');
const logger = require('./logger');

function loadAllowlistConfig() {
  try {
    const filePath = path.join(__dirname, '..', 'config', 'allowlist.json');
    if (fs.existsSync(filePath)) {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return data.allowed_hosts || [];
    }
  } catch (err) {
    logger.warn('Could not read config/allowlist.json, falling back to defaults:', err.message);
  }
  return ['localhost', '127.0.0.1', '::1'];
}

/**
 * Validates whether the given target URL is authorized for security testing.
 * @param {string} targetUrl - Target URL string (e.g., http://localhost:3000)
 * @returns {{ valid: boolean, hostname: string, error?: string }}
 */
function validateTarget(targetUrl) {
  if (!targetUrl || typeof targetUrl !== 'string') {
    return { valid: false, hostname: '', error: 'Target URL is missing or empty' };
  }

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (e) {
    return { valid: false, hostname: '', error: `Invalid URL format: "${targetUrl}"` };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, hostname: parsed.hostname, error: `Unsupported protocol "${parsed.protocol}". Only http: and https: are permitted.` };
  }

  // Load configured allowed hosts
  const fileAllowed = loadAllowlistConfig();
  const envAllowed = (process.env.ALLOWED_HOSTS || '')
    .split(',')
    .map(h => h.trim().toLowerCase())
    .filter(Boolean);

  const mergedAllowed = new Set([...fileAllowed.map(h => h.toLowerCase()), ...envAllowed]);

  const hostname = parsed.hostname.toLowerCase();

  // Guard against accidental public internet scans
  const isAllowed = mergedAllowed.has(hostname) ||
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1';

  if (!isAllowed) {
    return {
      valid: false,
      hostname,
      error: `REFUSED: Target host "${hostname}" is not in the authorized allowlist.\n` +
             `To test this target, add it explicitly to ALLOWED_HOSTS environment variable or config/allowlist.json.\n` +
             `Ensure you have explicit written authorization before testing any non-local target.`
    };
  }

  return { valid: true, hostname };
}

/**
 * Asserts target is valid, or terminates process with helpful error.
 * @param {string} targetUrl
 * @returns {string} Normalized target URL
 */
function ensureAuthorizedTarget(targetUrl) {
  const result = validateTarget(targetUrl);
  if (!result.valid) {
    logger.error(result.error);
    throw new Error(result.error);
  }
  return targetUrl.replace(/\/+$/, ''); // Remove trailing slash
}

module.exports = {
  validateTarget,
  ensureAuthorizedTarget,
  loadAllowlistConfig
};
