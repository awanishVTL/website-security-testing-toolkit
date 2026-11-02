/**
 * Local Security Testing Fixture Server
 *
 * Demonstrates:
 * 1. Vulnerable implementations for authorized security verification
 * 2. Secure counterparts demonstrating proper remediations
 *
 * NOTE: For local testing and training purposes only.
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = parseInt(process.env.PORT || process.env.FIXTURE_PORT || '3000', 10);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser('dev-secret-test-key'));
app.use(express.static(path.join(__dirname, 'public')));

// Seed dummy data (in-memory copy)
const seedFilePath = path.join(__dirname, 'data', 'seed-data.json');
let db = JSON.parse(fs.readFileSync(seedFilePath, 'utf8'));

// Simulated CSRF Token Store for secure endpoints
const validCsrfTokens = new Set(['valid-csrf-token-demo-xyz123']);

// ==========================================
// 1. HEALTH CHECK
// ==========================================
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    fixture: 'website-security-testing-toolkit',
    timestamp: new Date().toISOString()
  });
});

// ==========================================
// 2. CROSS-SITE SCRIPTING (XSS)
// ==========================================

// VULNERABLE: Reflected XSS (Raw HTML echo without output encoding)
app.get('/api/vulnerable/search', (req, res) => {
  const query = req.query.q || '';
  // Intentionally vulnerable: reflects raw input in HTML context
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`
    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${query}</p>
        <div id="results">No matching records found.</div>
      </body>
    </html>
  `);
});

// SECURE: Reflected XSS Remediation (HTML Entity Encoding)
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

app.get('/api/secure/search', (req, res) => {
  const query = req.query.q || '';
  // Secure: Output encoding + Content-Type + CSP
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
  res.send(`
    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${escapeHtml(query)}</p>
        <div id="results">No matching records found.</div>
      </body>
    </html>
  `);
});

// VULNERABLE: Stored XSS
app.get('/api/vulnerable/comments', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  const items = db.comments.map(c => `<li><strong>${c.author}:</strong> ${c.content}</li>`).join('\n');
  res.send(`<ul>${items}</ul>`);
});

app.post('/api/vulnerable/comments', (req, res) => {
  const { author, content } = req.body;
  db.comments.push({ id: db.comments.length + 1, author: author || 'Anonymous', content: content || '' });
  res.redirect('/api/vulnerable/comments');
});

// SECURE: Stored XSS Remediation
app.get('/api/secure/comments', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  const items = db.comments.map(c => `<li><strong>${escapeHtml(c.author)}:</strong> ${escapeHtml(c.content)}</li>`).join('\n');
  res.send(`<ul>${items}</ul>`);
});

// ==========================================
// 3. SQL INJECTION (SQLi)
// ==========================================

// Mock SQL executor to simulate database engine behavior safely
function mockExecuteSql(rawSql) {
  // Check for common SQL syntax errors when quotes are unescaped
  const singleQuotes = (rawSql.match(/'/g) || []).length;
  if (singleQuotes % 2 !== 0 && !rawSql.includes('--')) {
    const error = new Error("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1");
    error.code = 'ER_PARSE_ERROR';
    throw error;
  }

  // Simulate Auth bypass probe: ' OR '1'='1' --
  if (rawSql.includes("' OR '1'='1") || rawSql.includes("' or '1'='1") || rawSql.includes("' OR 1=1")) {
    return [db.users[0]]; // Returns first user (admin/alice) on bypass
  }

  // Simulate boolean injection: ' AND '1'='1' vs ' AND '1'='2'
  if (rawSql.includes("AND '1'='2") || rawSql.includes("and '1'='2")) {
    return [];
  }

  // Default query parsing
  const usernameMatch = rawSql.match(/WHERE username = '([^']*)'/i);
  if (usernameMatch) {
    const username = usernameMatch[1];
    return db.users.filter(u => u.username.toLowerCase() === username.toLowerCase());
  }

  return db.users;
}

// VULNERABLE: SQL Injection via string concatenation
app.get('/api/vulnerable/users', (req, res) => {
  const search = req.query.query || '';
  const constructedQuery = `SELECT id, username, email FROM users WHERE username = '${search}'`;

  try {
    const results = mockExecuteSql(constructedQuery);
    res.json({ query: constructedQuery, results });
  } catch (err) {
    // Intentionally leaking SQL syntax error details
    res.status(500).json({ error: 'Internal Database Error', sql_message: err.message, query: constructedQuery });
  }
});

// VULNERABLE: Authentication bypass SQLi
app.post('/api/vulnerable/login', (req, res) => {
  const { username, password } = req.body;
  const rawQuery = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${password}'`;

  try {
    const rows = mockExecuteSql(rawQuery);
    if (rows && rows.length > 0) {
      return res.json({ success: true, message: 'Authentication successful', user: { id: rows[0].id, username: rows[0].username, role: rows[0].role } });
    }
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  } catch (err) {
    return res.status(500).json({ error: 'Database execution failure', sql_message: err.message });
  }
});

// SECURE: SQL Injection Remediation (Parameterized Queries / Prepared Statements)
function mockParameterizedQuery(sql, params) {
  // sql: 'SELECT id, username, email FROM users WHERE username = ?'
  // params: [username]
  const [paramVal] = params;
  // Parameter is strictly treated as a literal string value, never executable code
  return db.users.filter(u => u.username.toLowerCase() === String(paramVal).toLowerCase());
}

app.get('/api/secure/users', (req, res) => {
  const search = req.query.query || '';
  const sql = 'SELECT id, username, email FROM users WHERE username = ?';
  const results = mockParameterizedQuery(sql, [search]);
  res.json({ results });
});

app.post('/api/secure/login', (req, res) => {
  const { username, password } = req.body;
  // Prepared statement handles inputs as safe parameters
  const sql = 'SELECT * FROM users WHERE username = ?';
  const users = mockParameterizedQuery(sql, [username]);

  // Constant-time check / safe hash comparison simulation
  if (users.length > 0 && password === 'safePassword123!') {
    return res.json({ success: true, message: 'Authentication successful', user: { id: users[0].id, username: users[0].username, role: users[0].role } });
  }
  return res.status(401).json({ success: false, message: 'Invalid username or password' });
});

// ==========================================
// 4. CROSS-SITE REQUEST FORGERY (CSRF)
// ==========================================

// VULNERABLE: Sensitive transfer endpoint without CSRF validation, accepting GET or POST
app.all('/api/vulnerable/transfer', (req, res) => {
  const recipient = req.query.recipient || req.body.recipient;
  const amount = Number(req.query.amount || req.body.amount || 0);

  // Insecure: Sets cookie without SameSite and without token check
  res.cookie('session_id', 'vulnerable-session-token-12345', { httpOnly: true });

  if (!recipient || amount <= 0) {
    return res.status(400).json({ error: 'Recipient and positive amount required' });
  }

  res.json({
    success: true,
    message: `Transferred $${amount} to ${recipient} (VULNERABLE: No CSRF token or origin check)`,
    recipient,
    amount
  });
});

// SECURE: CSRF Remediation (Enforces POST, SameSite=Lax, Origin & CSRF Token check)
app.post('/api/secure/transfer', (req, res) => {
  const csrfToken = req.headers['x-csrf-token'] || req.body.csrf_token;
  const origin = req.headers['origin'];

  // Check Origin
  if (origin && origin !== `http://localhost:${PORT}` && origin !== `http://127.0.0.1:${PORT}`) {
    return res.status(403).json({ error: 'Forbidden: Invalid Origin header' });
  }

  // Validate CSRF token
  if (!csrfToken || !validCsrfTokens.has(csrfToken)) {
    return res.status(403).json({ error: 'Forbidden: Missing or invalid CSRF token' });
  }

  const { recipient, amount } = req.body;
  res.cookie('session_id', 'secure-session-token-67890', {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  });

  res.json({
    success: true,
    message: `Transferred $${amount} to ${recipient} securely with CSRF verification`,
    recipient,
    amount
  });
});

// CSRF Token generation endpoint
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrf_token: 'valid-csrf-token-demo-xyz123' });
});

// ==========================================
// 5. CORS & SECURITY HEADERS
// ==========================================

// VULNERABLE: Permissive CORS (echoes any Origin, allows credentials, missing security headers)
app.get('/api/vulnerable/profile', (req, res) => {
  const clientOrigin = req.headers.origin;
  if (clientOrigin) {
    // VULNERABLE: Blindly echoing client origin
    res.setHeader('Access-Control-Allow-Origin', clientOrigin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }

  // Fingerprint disclosure
  res.setHeader('X-Powered-By', 'Express/4.21.2');

  res.json({
    id: 1,
    username: 'alice',
    balance: 500,
    email: 'alice.demo@example.test',
    security_status: 'Vulnerable headers & CORS'
  });
});

// SECURE: Strict CORS & Comprehensive Security Headers
const ALLOWED_CORS_ORIGINS = new Set([
  `http://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`
]);

app.get('/api/secure/profile', (req, res) => {
  const clientOrigin = req.headers.origin;

  if (clientOrigin && ALLOWED_CORS_ORIGINS.has(clientOrigin)) {
    res.setHeader('Access-Control-Allow-Origin', clientOrigin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  // Security Headers (Emulating Helmet)
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; object-src 'none'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.removeHeader('X-Powered-By');

  res.json({
    id: 1,
    username: 'alice',
    balance: 500,
    email: 'alice.demo@example.test',
    security_status: 'Hardened headers & Strict CORS'
  });
});

// ==========================================
// 6. IDOR (Insecure Direct Object Reference)
// ==========================================

// VULNERABLE: Direct access without ownership validation
app.get('/api/vulnerable/idor/user/:id', (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const user = db.users.find(u => u.id === targetId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  // VULNERABLE: Leaking user record regardless of requesting caller
  res.json({ user });
});

// SECURE: Object Ownership Validation
app.get('/api/secure/idor/user/:id', (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  // Simulated authenticated caller session: User ID 1 (Alice)
  const currentUserId = 1;

  if (targetId !== currentUserId) {
    return res.status(403).json({ error: 'Forbidden: You do not own this resource' });
  }

  const user = db.users.find(u => u.id === targetId);
  res.json({ user });
});

// Fallback 404
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server if executed directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`[FIXTURE SERVER] Running on http://localhost:${PORT}`);
    console.log(`- Web Demonstration UI: http://localhost:${PORT}/`);
    console.log(`- Vulnerable API:       http://localhost:${PORT}/api/vulnerable/...`);
    console.log(`- Secure API:           http://localhost:${PORT}/api/secure/...`);
    console.log(`======================================================\n`);
  });
}

module.exports = app;
