# Additional Security Testing & Remediation Guide

This guide covers critical supplemental web application vulnerabilities: CORS misconfigurations, missing security headers, path traversal, file upload flaws, Server-Side Request Forgery (SSRF), command injection, and rate limiting.

---

## 1. CORS Misconfiguration

### What & Why
Cross-Origin Resource Sharing (CORS) relaxes the browser's Same-Origin Policy (SOP). Misconfigurations arise when servers dynamically echo untrusted `Origin` request headers alongside `Access-Control-Allow-Credentials: true`, enabling malicious origins to read authenticated private data.

### Vulnerable Code
```javascript
// VULNERABLE: Reflects any Origin header and allows credentials
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});
```

### Remediation (Strict Allowlist)
```javascript
const cors = require('cors');

const ALLOWED_ORIGINS = ['https://app.example.com', 'https://staging.example.com'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS policy'));
    }
  },
  credentials: true
}));
```

---

## 2. Security Headers

### Essential Headers
1. **Content-Security-Policy (CSP):** Restricts script, style, and media origins. Prevents XSS execution.
2. **Strict-Transport-Security (HSTS):** Enforces HTTPS connections.
3. **X-Frame-Options:** Prevents UI redressing / Clickjacking.
4. **X-Content-Type-Options:** Prevents MIME-type sniffing (`nosniff`).
5. **Referrer-Policy:** Limits referrer leakage.
6. **Permissions-Policy:** Controls browser features (camera, microphone, geolocation).

### Remediation via Helmet
```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard: { action: 'deny' },
  noSniff: true,
  hidePoweredBy: true
}));
```

---

## 3. Path Traversal

### What & Why
Path traversal occurs when an application accepts user input (such as `filename=../../../../etc/passwd`) and appends it to filesystem access APIs without canonicalization, allowing attackers to read arbitrary files outside the web directory.

### Vulnerable Code
```javascript
// VULNERABLE: Direct path concatenation
app.get('/download', (req, res) => {
  const filePath = path.join(__dirname, 'public/files', req.query.filename);
  res.sendFile(filePath); // Attacker sends filename=../../../../etc/passwd
});
```

### Remediation (Safe Path Resolution)
```javascript
const path = require('path');

app.get('/download', (req, res) => {
  const SAFE_ROOT = path.resolve(__dirname, 'public/files');
  const userFile = req.query.filename || '';

  // Canonicalize and verify path stays within authorized base directory
  const resolvedPath = path.resolve(SAFE_ROOT, userFile);

  if (!resolvedPath.startsWith(SAFE_ROOT + path.sep)) {
    return res.status(403).json({ error: 'Access denied: invalid file path' });
  }

  res.sendFile(resolvedPath);
});
```

---

## 4. File Upload Validation

### Vulnerabilities
- Uploading executable scripts (e.g. `.php`, `.jsp`, `.exe`).
- Extension spoofing (double extensions e.g. `image.php.png` or null byte injection).
- Storing uploads directly within public webroot directories.

### Remediation
1. Generate server-side random filenames (UUIDv4) and discard client-provided names.
2. Verify MIME type using magic number byte inspection, not client-supplied `Content-Type`.
3. Store uploads outside the web document root or in an isolated cloud storage bucket (AWS S3) served with `Content-Disposition: attachment`.

```javascript
const crypto = require('crypto');
const path = require('path');

function generateSafeFilename(originalExtension) {
  const ALLOWED_EXTS = ['.png', '.jpg', '.jpeg', '.pdf'];
  const ext = path.extname(originalExtension).toLowerCase();

  if (!ALLOWED_EXTS.includes(ext)) {
    throw new Error('Unsupported file extension');
  }

  return `${crypto.randomUUID()}${ext}`;
}
```

---

## 5. Server-Side Request Forgery (SSRF)

### What & Why
SSRF occurs when a backend server fetches a remote resource (e.g., URL preview, webhook, image proxy) based on user-supplied URLs without verifying destination IP addresses, allowing access to internal services or cloud metadata endpoints (`169.254.169.254`).

### Remediation
1. Validate protocol: allow only `http:` and `https:`.
2. Resolve DNS hostname and reject private IP ranges (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, loopback `127.0.0.0/8`, and link-local `169.254.169.254`).
3. Disable redirects in backend HTTP clients or re-validate redirect destination IPs.

---

## 6. Command Injection

### What & Why
Occurs when user input is passed directly to system shell execution functions like `child_process.exec()` without escaping.

### Vulnerable Code
```javascript
const { exec } = require('child_process');

// VULNERABLE: Direct shell interpolation
app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {
    res.send(stdout); // Attacker passes 127.0.0.1; whoami
  });
});
```

### Remediation (Use execFile with argument arrays)
```javascript
const { execFile } = require('child_process');

app.get('/ping', (req, res) => {
  const host = req.query.host;

  // Strict regex input validation
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
    return res.status(400).send('Invalid hostname');
  }

  // execFile does not invoke a shell; arguments cannot break out
  execFile('/bin/ping', ['-c', '1', host], { timeout: 3000 }, (err, stdout) => {
    if (err) return res.status(500).send('Ping failed');
    res.send(stdout);
  });
});
```

---

## 7. Rate Limiting & Abuse Prevention

### What & Why
Protects endpoints against credential stuffing, brute-force attacks, and DoS by capping the request volume per IP or token.

### Remediation via express-rate-limit
```javascript
const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', apiLimiter);
```
