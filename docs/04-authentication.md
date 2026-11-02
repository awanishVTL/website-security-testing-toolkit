# Authentication Security Testing & Hardening Guide

## 1. What is the Vulnerability?

Authentication security flaws encompass design and implementation defects in login mechanisms, password reset flows, multi-factor authentication (MFA/OTP), session token handling, and JSON Web Token (JWT) verification that allow an attacker to impersonate legitimate users or gain unauthorized account access.

## 2. Common Authentication Weaknesses

1. **User Enumeration:** Login or password reset error messages that distinguish between valid and invalid usernames (e.g. "User does not exist" vs "Incorrect password").
2. **Credential Brute-Force & Stuffing:** Endpoints lacking rate limiting, CAPTCHA, or exponential backoff.
3. **Flawed Password Reset Flows:** Reset tokens that are predictable, leak via the `Referer` header, or are subject to `Host` header poisoning.
4. **Weak OTP Implementations:** Short 4-digit codes without attempt limits, fixed test OTPs in staging, or lack of expiration.
5. **JWT Vulnerabilities:** Accepting the `none` algorithm, weak signing secrets susceptible to offline cracking, or missing expiration (`exp`) validation.
6. **Session Fixation:** Retaining the same session ID across authentication state transitions.

## 3. Realistic Attack Scenario

An attacker attacks a password reset endpoint by supplying a poisoned header: `X-Forwarded-Host: attacker.test`. The application constructs a reset link: `https://attacker.test/reset-password?token=secret123` and sends it to the victim. When the victim clicks the link, the reset token is sent directly to the attacker's web server, enabling account takeover.

## 4. Vulnerable Code Examples

### Vulnerable Express.js Login & JWT Verification
```javascript
const jwt = require('jsonwebtoken');

// VULNERABLE: User enumeration and missing rate limiting
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await findUser(username);

  if (!user) {
    // VULNERABLE: Leaks user existence
    return res.status(404).json({ error: 'Username not found' });
  }

  if (user.password !== password) {
    // VULNERABLE: Leaks incorrect password distinction & plaintext comparison
    return res.status(401).json({ error: 'Invalid password' });
  }

  // VULNERABLE: Missing secret enforcement, algorithm allowlist, or expiration
  const token = jwt.sign({ id: user.id }, 'weak_secret');
  res.json({ token });
});

// VULNERABLE: Insecure JWT verification accepting 'none' algorithm
app.get('/api/profile', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  // VULNERABLE: jwt.decode does NOT verify signatures!
  const decoded = jwt.decode(token);
  res.json({ user: decoded });
});
```

## 5. Safe Testing Payloads & Verification

| ID | Focus | Verification Technique |
| :--- | :--- | :--- |
| `AUTH-ENUM-001` | Enumeration | Submit known vs unknown usernames and compare response bodies and timing. |
| `AUTH-BRUTEFORCE-001` | Rate Limiting | Send 10 consecutive rapid login requests; verify HTTP 429 response. |
| `AUTH-JWT-NONE-001` | JWT Algorithm | Send unsigned JWT with header `{"alg": "none"}`; verify 401 rejection. |
| `AUTH-RESET-HOST-001` | Host Poisoning | Send `X-Forwarded-Host: evil.test` to password reset; ensure app domain is not overwritten. |
| `AUTH-OTP-BRUTE-001` | OTP Throttling | Submit 5 invalid OTPs; ensure OTP is invalidated and further attempts blocked. |

## 6. How to Fix It (Remediation)

1. **Generic Error Responses:** Always return "Invalid username or password" for all authentication failures.
2. **Password Hashing:** Use strong adaptive hashing algorithms like Argon2id or bcrypt (work factor >= 12). Never store plaintext or raw MD5/SHA-256 hashes.
3. **Strict Rate Limiting:** Enforce IP- and account-based rate limiting on `/login`, `/register`, `/reset-password`, and `/verify-otp`.
4. **Session Regeneration:** Call `req.session.regenerate()` immediately upon successful login to defeat session fixation.
5. **Secure JWT Configuration:** Specify explicit verification algorithms (`algorithms: ['HS256']`), enforce expiration checks (`exp`), and use high-entropy secrets (256+ bits).
6. **Hardcoded Base URLs:** Never construct password reset URLs using client-controlled `Host` or `X-Forwarded-*` headers.

## 7. Secure Code Examples

### Secure Authentication & Rate Limiting (Express.js)
```javascript
const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Strict rate limiter for authentication endpoints
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await findUserInDatabase(username);

    // Constant-time check simulation: compare even if user is null to prevent timing enumeration
    const dummyHash = '$2b$12$e8wF58f3m30V3kY720iBTeB50f1q334657689012345678901234';
    const hashToCompare = user ? user.password_hash : dummyHash;
    const isValid = await bcrypt.compare(password, hashToCompare);

    if (!user || !isValid) {
      // Unified error response
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Sign JWT with strong secret and explicit algorithm
    const token = jwt.sign(
      { sub: user.id, role: user.role },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' }
    );

    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ error: 'Authentication service unavailable' });
  }
});

// Secure JWT verification middleware
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'] // Explicit algorithm whitelist: prevents 'none' algorithm exploit
    });
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}
```

## 8. OWASP References
- [OWASP Top 10:2021 – A07 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## 9. Testing Checklist
- [ ] Error messages for failed login and reset requests do not disclose username existence.
- [ ] Password hashes use Argon2id or bcrypt (cost factor >= 12).
- [ ] Authentication endpoints enforce rate limiting (max 5 tries per IP/account).
- [ ] JWT tokens reject `alg: none` and enforce signature validation.
- [ ] Session ID changes upon successful authentication.
- [ ] Password reset links expire within 15 minutes and invalidate upon single use.
