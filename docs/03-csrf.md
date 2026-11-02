# Cross-Site Request Forgery (CSRF) Testing & Remediation Guide

## 1. What is the Vulnerability?

Cross-Site Request Forgery (CSRF) is an attack that tricks an authenticated victim into executing unwanted actions on a trusted web application. Because browsers automatically attach ambient credentials (such as session cookies or HTTP Basic Auth) to cross-origin requests, the vulnerable application cannot distinguish between a legitimate user action and a forged request initiated by a malicious site.

## 2. How Does it Work?

1. An authenticated user logs into `bank.example` and receives a session cookie.
2. Without logging out, the user visits an attacker-controlled site `attacker.test`.
3. `attacker.test` contains an automatic form submission or script:
   ```html
   <form action="https://bank.example/transfer" method="POST" id="csrfForm">
     <input type="hidden" name="toAccount" value="attacker" />
     <input type="hidden" name="amount" value="5000" />
   </form>
   <script>document.getElementById('csrfForm').submit();</script>
   ```
4. The victim's browser submits the request to `bank.example`, including the user's valid session cookie.
5. If `bank.example` lacks anti-CSRF tokens or SameSite cookie protections, the transfer is authorized and processed.

## 3. Why Does it Happen?

- Relying solely on automatic browser session cookies for state-changing authorization.
- Failure to validate cryptographically strong anti-CSRF tokens.
- Allowing state modifications via idempotent HTTP methods (like `GET`).
- Cookies configured without the `SameSite` attribute (or `SameSite=None` without justification).
- Lack of `Origin` and `Referer` header validation on mutating endpoints.

## 4. Realistic Attack Scenario

A user management portal provides an email change endpoint at `POST /api/user/change-email`. An attacker sends an enticing link to an admin. When opened, an invisible HTML form submits a new administrator recovery email address. The attacker then requests a password reset, taking over the administrator account.

## 5. Vulnerable Code Examples

### Express.js (Missing CSRF Protection)
```javascript
// VULNERABLE: No CSRF validation, accepting requests purely based on cookie session
app.post('/api/account/transfer', (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).send('Unauthorized');

  const { recipient, amount } = req.body;
  executeTransfer(userId, recipient, amount);
  res.send('Transfer complete');
});

// VULNERABLE: State mutation via GET method
app.get('/api/account/transfer', (req, res) => {
  const { to, amount } = req.query;
  executeTransfer(req.session.userId, to, amount);
  res.send('Done');
});
```

## 6. Safe Testing Payloads

| ID | Payload | Purpose |
| :--- | :--- | :--- |
| `CSRF-TOKEN-OMISSION-001` | POST without `X-CSRF-Token` | Tests whether missing tokens are rejected with 403 Forbidden. |
| `CSRF-ORIGIN-001` | Header `Origin: https://unauthorized.test` | Tests whether cross-origin requests are blocked. |
| `CSRF-SAMESITE-001` | Inspect `Set-Cookie` for `SameSite=Lax/Strict` | Verifies ambient cookie isolation. |
| `CSRF-GET-METHOD-001` | GET to mutating endpoint | Confirms GET is rejected on sensitive actions. |

## 7. Testing Methodology

1. **Catalog State-Changing Endpoints:** Identify all POST, PUT, PATCH, and DELETE operations (e.g., transfers, email updates, password changes).
2. **Remove Anti-CSRF Tokens:** Replay the request with the token completely removed.
3. **Tamper with Tokens:** Submit invalid, expired, or another user's CSRF token.
4. **Header Manipulation:** Change `Origin` and `Referer` headers to a foreign host.
5. **Inspect Cookies:** Check response `Set-Cookie` headers for `SameSite=Lax` or `SameSite=Strict`, `HttpOnly`, and `Secure`.

## 8. Expected Results

- **Vulnerable:** The request completes successfully with HTTP 200 without a valid CSRF token, or executes via HTTP GET.
- **Secure:** The application halts execution with HTTP 403 Forbidden or 405 Method Not Allowed.

## 9. How to Fix It (Remediation)

1. **Synchronizer Token Pattern:** Issue a cryptographically random, per-session anti-CSRF token (e.g. using `csrf-csrf` middleware in Express) and verify it on every non-idempotent request (`POST`, `PUT`, `DELETE`, `PATCH`).
2. **SameSite Cookie Attribute:** Always set `SameSite=Lax` (default in modern browsers) or `SameSite=Strict` for sensitive session cookies.
3. **Origin & Referer Verification:** Reject requests whose `Origin` or `Referer` header does not match the application's domain.
4. **Strict HTTP Verbs:** Ensure GET and HEAD methods never alter persistent application state.
5. **Custom Request Headers for APIs:** Require a custom header (such as `X-Requested-With` or `X-CSRF-Token`) for JSON endpoints, which cannot be set in simple cross-origin HTML form submissions.

## 10. Secure Code Examples

### Secure Express.js Implementation (csrf-csrf & Secure Cookies)
```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const { doubleCsrf } = require('csrf-csrf');

const app = express();

app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET || 'strong-secret-key-12345'));

// Configure session cookies with strict security flags
app.use(session({
  secret: process.env.SESSION_SECRET || 'strong-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax', // Protects against cross-site leakage
    secure: process.env.NODE_ENV === 'production', // Enforce HTTPS
    maxAge: 3600000 // 1 hour
  }
}));

// Initialize Double Submit Cookie CSRF protection
const { generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'csrf-secret-key-xyz',
  cookieName: '__Host-ps.x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
});

// Endpoint to provide CSRF token to frontend client
app.get('/api/csrf-token', (req, res) => {
  const token = generateToken(req, res);
  res.json({ csrfToken: token });
});

// Apply CSRF protection to all state-changing endpoints
app.post('/api/account/transfer', doubleCsrfProtection, (req, res) => {
  const { recipient, amount } = req.body;
  // Execution is guaranteed to have passed CSRF verification
  res.json({ success: true, message: `Transferred ${amount} to ${recipient}` });
});
```

### Secure React Frontend Token Integration
```javascript
// Fetch CSRF token on application startup
let csrfToken = '';

export async function initSecurity() {
  const res = await fetch('/api/csrf-token');
  const data = await res.json();
  csrfToken = data.csrfToken;
}

// Attach token to mutating API requests
export async function transferFunds(recipient, amount) {
  const res = await fetch('/api/account/transfer', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify({ recipient, amount })
  });

  if (!res.ok) throw new Error('Transfer failed CSRF verification');
  return res.json();
}
```

## 11. OWASP References
- [OWASP Top 10:2021 – A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

## 12. Testing Checklist
- [ ] No state mutation is permitted via HTTP GET requests.
- [ ] All POST, PUT, PATCH, and DELETE endpoints validate an anti-CSRF token.
- [ ] Session cookies specify `SameSite=Lax` or `SameSite=Strict`.
- [ ] The `Origin` and `Referer` headers are validated against an allowed domain list.
- [ ] Multi-factor or re-authentication is required before critical actions (e.g., password change).
