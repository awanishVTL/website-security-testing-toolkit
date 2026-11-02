# Security Assessment Report: Web Application Assessment Lab

**Target URL:** `http://localhost:3000`  
**Assessment Date:** 2026-11-02T07:18:52.064Z  
**Classification:** Authorized Defensive Assessment  

## Executive Summary

| Metric | Count |
| :--- | :--- |
| **Total Endpoints Tested** | 12 |
| **Confirmed Vulnerabilities** | **17** |
| **Potential Findings** | 0 |
| **Verified Secure Controls** | 13 |
| **Critical Severity** | 2 |
| **High Severity** | 9 |
| **Medium Severity** | 3 |
| **Low Severity** | 3 |
| **Informational** | 13 |

## Findings Matrix

| ID | Status | Severity | Category | Title | Endpoint |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FINDING-XSS-REFLECT-001` | **Confirmed** | High | Cross-Site Scripting (XSS) | Unescaped Reflected Input on /api/vulnerable/search | `/api/vulnerable/search` |
| `FINDING-XSS-REFLECT-002` | **Confirmed** | High | Cross-Site Scripting (XSS) | Unescaped Reflected Input on /api/vulnerable/search | `/api/vulnerable/search` |
| `FINDING-XSS-JS-CONTEXT-001` | **Confirmed** | High | Cross-Site Scripting (XSS) | Unescaped Reflected Input on /api/vulnerable/search | `/api/vulnerable/search` |
| `SAFE-XSS-REFLECT-001` | **Secure** | Informational | Cross-Site Scripting (XSS) | Contextual Output Encoding Verified on /api/secure/search | `/api/secure/search` |
| `SAFE-XSS-REFLECT-002` | **Secure** | Informational | Cross-Site Scripting (XSS) | Contextual Output Encoding Verified on /api/secure/search | `/api/secure/search` |
| `SAFE-XSS-JS-CONTEXT-001` | **Secure** | Informational | Cross-Site Scripting (XSS) | Contextual Output Encoding Verified on /api/secure/search | `/api/secure/search` |
| `SQLI-ERR-CONFIRMED` | **Confirmed** | Critical | SQL Injection | Raw SQL Syntax Error Leakage on /api/vulnerable/users | `/api/vulnerable/users` |
| `SQLI-BOOL--api-vulnerable-users` | **Confirmed** | High | SQL Injection | Boolean Query Response Disparity on /api/vulnerable/users | `/api/vulnerable/users` |
| `SQLI-SAFE--api-secure-users` | **Secure** | Informational | SQL Injection | Query Parameters Safely Bound on /api/secure/users | `/api/secure/users` |
| `SQLI-AUTH-BYPASS` | **Confirmed** | Critical | SQL Injection | Authentication Bypass via SQL Injection on /api/vulnerable/login | `/api/vulnerable/login` |
| `SQLI-AUTH-SAFE--api-secure-login` | **Secure** | Informational | SQL Injection | Authentication Input Properly Handled on /api/secure/login | `/api/secure/login` |
| `CSRF-GET-ACTION` | **Confirmed** | High | Cross-Site Request Forgery (CSRF) | State-Changing Operation Executable via HTTP GET on /api/vulnerable/transfer | `/api/vulnerable/transfer` |
| `CSRF-TOKEN-MISSING` | **Confirmed** | High | Cross-Site Request Forgery (CSRF) | State-Changing POST Accepted Without CSRF Token on /api/vulnerable/transfer | `/api/vulnerable/transfer` |
| `CSRF-SAMESITE-MISSING` | **Confirmed** | Medium | Cross-Site Request Forgery (CSRF) | Session Cookie Lacks SameSite Restriction on /api/vulnerable/transfer | `/api/vulnerable/transfer` |
| `CSRF-TOKEN-ENFORCED--api-secure-transfer` | **Secure** | Informational | Cross-Site Request Forgery (CSRF) | Anti-CSRF Token Enforced on /api/secure/transfer | `/api/secure/transfer` |
| `CORS-VULN-ARBITRARY_ORIGIN` | **Confirmed** | High | CORS Misconfiguration | Arbitrary Origin Reflected with Credentials Allowed on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `CORS-VULN-NULL_ORIGIN` | **Confirmed** | High | CORS Misconfiguration | Arbitrary Origin Reflected with Credentials Allowed on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `CORS-SAFE--api-secure-profile-arbitrary_origin` | **Secure** | Informational | CORS Misconfiguration | Strict CORS Origin Handling on /api/secure/profile | `/api/secure/profile` |
| `CORS-SAFE--api-secure-profile-null_origin` | **Secure** | Informational | CORS Misconfiguration | Strict CORS Origin Handling on /api/secure/profile | `/api/secure/profile` |
| `HEADER-MISSING-CONTENT_SECURITY_POLICY` | **Confirmed** | Medium | Security Headers | Missing Security Header: Content-Security-Policy on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `HEADER-MISSING-X_FRAME_OPTIONS` | **Confirmed** | Medium | Security Headers | Missing Security Header: X-Frame-Options on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `HEADER-MISSING-X_CONTENT_TYPE_OPTIONS` | **Confirmed** | Low | Security Headers | Missing Security Header: X-Content-Type-Options on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `HEADER-MISSING-REFERRER_POLICY` | **Confirmed** | Low | Security Headers | Missing Security Header: Referrer-Policy on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `HEADER-LEAK-POWERED-BY` | **Confirmed** | Low | Security Headers | Technology Fingerprint Disclosed via X-Powered-By on /api/vulnerable/profile | `/api/vulnerable/profile` |
| `HEADER-PRESENT-CONTENT_SECURITY_POLICY` | **Secure** | Informational | Security Headers | Header Present: Content-Security-Policy | `/api/secure/profile` |
| `HEADER-PRESENT-X_FRAME_OPTIONS` | **Secure** | Informational | Security Headers | Header Present: X-Frame-Options | `/api/secure/profile` |
| `HEADER-PRESENT-X_CONTENT_TYPE_OPTIONS` | **Secure** | Informational | Security Headers | Header Present: X-Content-Type-Options | `/api/secure/profile` |
| `HEADER-PRESENT-REFERRER_POLICY` | **Secure** | Informational | Security Headers | Header Present: Referrer-Policy | `/api/secure/profile` |
| `IDOR-UNAUTH-READ` | **Confirmed** | High | Authorization (IDOR) | Insecure Direct Object Reference (IDOR) on User Profile API | `/api/vulnerable/idor/user/99` |
| `IDOR-SECURE-ENFORCED` | **Secure** | Informational | Authorization (IDOR) | Object Ownership Verified on User Profile Endpoint | `/api/secure/idor/user/99` |

## Confirmed Vulnerabilities

### [High] FINDING-XSS-REFLECT-001: Unescaped Reflected Input on /api/vulnerable/search

- **Endpoint:** `GET /api/vulnerable/search`
- **Category:** Cross-Site Scripting (XSS)
- **OWASP Reference:** OWASP A03:2021 - Injection
- **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation
- **Verification Status:** `Confirmed`

#### Security Impact
An attacker can execute arbitrary JavaScript in the victim browser session, enabling session hijacking or unauthorized actions.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/search?q=%3Ctest-xss-sentinel%3Exss_probe_01%3C%2Ftest-xss-sentinel%3E
2. Inspect response body for raw unescaped token: "<test-xss-sentinel>xss_probe_01</test-xss-sentinel>"
3. Observe absence of HTML entity encoding or Content-Security-Policy restriction

#### Evidence
```text
Payload "<test-xss-sentinel>xss_probe_01</test-xss-sentinel>" reflected raw in response:

    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: <test-xss-sentinel>xss_probe_01</test-xss-sentinel></p>
        <div id="results">No matching records found.</div>
      </body>
    </html>
  ...
```

#### Recommended Remediation
Apply contextual HTML entity encoding using a safe templating engine or escape utility before embedding untrusted data.

---

### [High] FINDING-XSS-REFLECT-002: Unescaped Reflected Input on /api/vulnerable/search

- **Endpoint:** `GET /api/vulnerable/search`
- **Category:** Cross-Site Scripting (XSS)
- **OWASP Reference:** OWASP A03:2021 - Injection
- **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation
- **Verification Status:** `Confirmed`

#### Security Impact
An attacker can execute arbitrary JavaScript in the victim browser session, enabling session hijacking or unauthorized actions.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/search?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dconsole.log('xss_probe_02')%3E
2. Inspect response body for raw unescaped token: ""><img src=x onerror=console.log('xss_probe_02')>"
3. Observe absence of HTML entity encoding or Content-Security-Policy restriction

#### Evidence
```text
Payload ""><img src=x onerror=console.log('xss_probe_02')>" reflected raw in response:

    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: "><img src=x onerror=console.log('xss_probe_02')></p>
        <div id="results">No matching records found.</div>
      </body>
    </html>
  ...
```

#### Recommended Remediation
Use context-aware attribute escaping. In React/modern UI, bind values via JSX properties rather than string interpolation.

---

### [High] FINDING-XSS-JS-CONTEXT-001: Unescaped Reflected Input on /api/vulnerable/search

- **Endpoint:** `GET /api/vulnerable/search`
- **Category:** Cross-Site Scripting (XSS)
- **OWASP Reference:** OWASP A03:2021 - Injection
- **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation
- **Verification Status:** `Confirmed`

#### Security Impact
An attacker can execute arbitrary JavaScript in the victim browser session, enabling session hijacking or unauthorized actions.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/search?q='%3Bconsole.log('js_context_probe')%3B%2F%2F
2. Inspect response body for raw unescaped token: "';console.log('js_context_probe');//"
3. Observe absence of HTML entity encoding or Content-Security-Policy restriction

#### Evidence
```text
Payload "';console.log('js_context_probe');//" reflected raw in response:

    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ';console.log('js_context_probe');//</p>
        <div id="results">No matching records found.</div>
      </body>
    </html>
  ...
```

#### Recommended Remediation
Never interpolate raw strings into <script> blocks. Use JSON.parse(element.dataset.props) or secure serialization.

---

### [Critical] SQLI-ERR-CONFIRMED: Raw SQL Syntax Error Leakage on /api/vulnerable/users

- **Endpoint:** `GET /api/vulnerable/users`
- **Category:** SQL Injection
- **OWASP Reference:** OWASP A03:2021 - Injection
- **CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- **Verification Status:** `Confirmed`

#### Security Impact
Critical. Attackers can extract complete database contents, bypass access controls, or tamper with business data.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/users?query='
2. Observe HTTP 500 with unhandled SQL error syntax disclosure

#### Evidence
```text
Database error signature matched: /you have an error in your sql syntax/i
Response snippet: {"error":"Internal Database Error","sql_message":"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1","query":"SELECT id, username, email FROM users WHER
```

#### Recommended Remediation
Replace string concatenation with parameterized prepared statements (e.g. db.query(sql, [param])).

---

### [High] SQLI-BOOL--api-vulnerable-users: Boolean Query Response Disparity on /api/vulnerable/users

- **Endpoint:** `GET /api/vulnerable/users`
- **Category:** SQL Injection
- **Verification Status:** `Confirmed`

#### Security Impact
Enables blind SQL inference of database records character-by-character.

#### Reproduction Steps
1. Submit 1' AND '1'='1 -> returns filtered data
2. Submit 1' AND '1'='2 -> returns empty set or error

#### Evidence
```text
True payload returned 95 bytes; False payload returned 95 bytes.
```

#### Recommended Remediation
Use strict type casting and prepared statements.

---

### [Critical] SQLI-AUTH-BYPASS: Authentication Bypass via SQL Injection on /api/vulnerable/login

- **Endpoint:** `POST /api/vulnerable/login`
- **Category:** SQL Injection
- **OWASP Reference:** OWASP A03:2021 - Injection
- **CWE:** CWE-89
- **Verification Status:** `Confirmed`

#### Security Impact
Critical. Attackers can log in as administrator or arbitrary users without knowing their password.

#### Reproduction Steps
1. Submit POST to /api/vulnerable/login with username: "admin' OR '1'='1' -- "
2. Observe successful HTTP 200 authentication response

#### Evidence
```text
Bypass payload granted authenticated session without valid password: {"success":true,"message":"Authentication successful","user":{"id":1,"username":"alice","role":"user"}}
```

#### Recommended Remediation
Validate credentials using parameterized SELECT WHERE username = ? and compare hashed password via bcrypt.

---

### [High] CSRF-GET-ACTION: State-Changing Operation Executable via HTTP GET on /api/vulnerable/transfer

- **Endpoint:** `GET /api/vulnerable/transfer`
- **Category:** Cross-Site Request Forgery (CSRF)
- **OWASP Reference:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
- **Verification Status:** `Confirmed`

#### Security Impact
High. An attacker can execute arbitrary state changes by embedding the URL in a simple <img src="..."> on a third-party webpage.

#### Reproduction Steps
1. Send HTTP GET request to http://localhost:3000/api/vulnerable/transfer?recipient=audit_test&amount=1
2. Notice endpoint executes transaction without requiring POST or CSRF validation

#### Evidence
```text
HTTP GET triggered state mutation: {"success":true,"message":"Transferred $1 to audit_test (VULNERABLE: No CSRF token or origin check)","recipient":"audit_test","amount":1}
```

#### Recommended Remediation
Disallow GET on state-changing endpoints. Enforce POST/PUT with CSRF tokens.

---

### [High] CSRF-TOKEN-MISSING: State-Changing POST Accepted Without CSRF Token on /api/vulnerable/transfer

- **Endpoint:** `POST /api/vulnerable/transfer`
- **Category:** Cross-Site Request Forgery (CSRF)
- **OWASP Reference:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-352
- **Verification Status:** `Confirmed`

#### Security Impact
Enables cross-origin sites to forge actions on behalf of authenticated users.

#### Reproduction Steps
1. Send POST to http://localhost:3000/api/vulnerable/transfer with session cookie but omit CSRF token
2. Observe successful transaction execution

#### Evidence
```text
POST succeeded without X-CSRF-Token or CSRF form parameter: HTTP 200 OK
```

#### Recommended Remediation
Implement anti-CSRF token middleware (e.g., csrf-csrf or csurf) and require custom headers for API calls.

---

### [Medium] CSRF-SAMESITE-MISSING: Session Cookie Lacks SameSite Restriction on /api/vulnerable/transfer

- **Endpoint:** `GET/POST /api/vulnerable/transfer`
- **Category:** Cross-Site Request Forgery (CSRF)
- **CWE:** CWE-1275
- **Verification Status:** `Confirmed`

#### Security Impact
Cookies are attached to cross-site requests, increasing vulnerability to CSRF.

#### Reproduction Steps
1. Inspect Set-Cookie header on response
2. Verify absence of SameSite=Lax or SameSite=Strict

#### Evidence
```text
Set-Cookie: session_id=vulnerable-session-token-12345; Path=/; HttpOnly
```

#### Recommended Remediation
Configure SameSite=Lax or SameSite=Strict in cookie options: res.cookie(name, val, { sameSite: "lax", httpOnly: true, secure: true }).

---

### [High] CORS-VULN-ARBITRARY_ORIGIN: Arbitrary Origin Reflected with Credentials Allowed on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** CORS Misconfiguration
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-346: Origin Validation Error
- **Verification Status:** `Confirmed`

#### Security Impact
High. Untrusted external web origins can read sensitive user data and bypass browser SOP.

#### Reproduction Steps
1. Send GET to http://localhost:3000/api/vulnerable/profile with header 'Origin: https://unauthorized-attacker.test'
2. Verify response contains 'Access-Control-Allow-Origin: https://unauthorized-attacker.test' and 'Access-Control-Allow-Credentials: true'

#### Evidence
```text
Origin: https://unauthorized-attacker.test reflected in Access-Control-Allow-Origin: https://unauthorized-attacker.test with Access-Control-Allow-Credentials: true
```

#### Recommended Remediation
Replace dynamic origin reflection with a static allowlist of trusted origins.

---

### [High] CORS-VULN-NULL_ORIGIN: Arbitrary Origin Reflected with Credentials Allowed on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** CORS Misconfiguration
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-346: Origin Validation Error
- **Verification Status:** `Confirmed`

#### Security Impact
High. Untrusted external web origins can read sensitive user data and bypass browser SOP.

#### Reproduction Steps
1. Send GET to http://localhost:3000/api/vulnerable/profile with header 'Origin: null'
2. Verify response contains 'Access-Control-Allow-Origin: null' and 'Access-Control-Allow-Credentials: true'

#### Evidence
```text
Origin: null reflected in Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true
```

#### Recommended Remediation
Replace dynamic origin reflection with a static allowlist of trusted origins.

---

### [Medium] HEADER-MISSING-CONTENT_SECURITY_POLICY: Missing Security Header: Content-Security-Policy on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** Security Headers
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-16
- **Verification Status:** `Confirmed`

#### Security Impact
Missing Content-Security-Policy degrades browser-side defense-in-depth protections.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/profile
2. Inspect response headers for presence of "Content-Security-Policy"

#### Evidence
```text
Header "Content-Security-Policy" was not returned by server in response to GET /api/vulnerable/profile
```

#### Recommended Remediation
Implement CSP directives (e.g. default-src 'self'; script-src 'self').

---

### [Medium] HEADER-MISSING-X_FRAME_OPTIONS: Missing Security Header: X-Frame-Options on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** Security Headers
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-16
- **Verification Status:** `Confirmed`

#### Security Impact
Missing X-Frame-Options degrades browser-side defense-in-depth protections.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/profile
2. Inspect response headers for presence of "X-Frame-Options"

#### Evidence
```text
Header "X-Frame-Options" was not returned by server in response to GET /api/vulnerable/profile
```

#### Recommended Remediation
Set X-Frame-Options: DENY or SAMEORIGIN to prevent Clickjacking.

---

### [Low] HEADER-MISSING-X_CONTENT_TYPE_OPTIONS: Missing Security Header: X-Content-Type-Options on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** Security Headers
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-16
- **Verification Status:** `Confirmed`

#### Security Impact
Missing X-Content-Type-Options degrades browser-side defense-in-depth protections.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/profile
2. Inspect response headers for presence of "X-Content-Type-Options"

#### Evidence
```text
Header "X-Content-Type-Options" was not returned by server in response to GET /api/vulnerable/profile
```

#### Recommended Remediation
Set X-Content-Type-Options: nosniff to prevent MIME-sniffing.

---

### [Low] HEADER-MISSING-REFERRER_POLICY: Missing Security Header: Referrer-Policy on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** Security Headers
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-16
- **Verification Status:** `Confirmed`

#### Security Impact
Missing Referrer-Policy degrades browser-side defense-in-depth protections.

#### Reproduction Steps
1. Send GET request to http://localhost:3000/api/vulnerable/profile
2. Inspect response headers for presence of "Referrer-Policy"

#### Evidence
```text
Header "Referrer-Policy" was not returned by server in response to GET /api/vulnerable/profile
```

#### Recommended Remediation
Configure Referrer-Policy: strict-origin-when-cross-origin.

---

### [Low] HEADER-LEAK-POWERED-BY: Technology Fingerprint Disclosed via X-Powered-By on /api/vulnerable/profile

- **Endpoint:** `GET /api/vulnerable/profile`
- **Category:** Security Headers
- **OWASP Reference:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-200: Exposure of Sensitive Information
- **Verification Status:** `Confirmed`

#### Security Impact
Exposes underlying framework and potential version details to reconnaissance.

#### Reproduction Steps
1. Inspect headers of /api/vulnerable/profile

#### Evidence
```text
X-Powered-By: Express/4.21.2
```

#### Recommended Remediation
Disable fingerprinting in Express via app.disable("x-powered-by") or helmet.hidePoweredBy().

---

### [High] IDOR-UNAUTH-READ: Insecure Direct Object Reference (IDOR) on User Profile API

- **Endpoint:** `GET /api/vulnerable/idor/user/99`
- **Category:** Authorization (IDOR)
- **OWASP Reference:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-639: Authorization Bypass Through User-Controlled Key
- **Verification Status:** `Confirmed`

#### Security Impact
High. Allows any caller to enumerate and read sensitive profile records belonging to other users.

#### Reproduction Steps
1. Send GET to http://localhost:3000/api/vulnerable/idor/user/99
2. Observe full user object returned despite lack of administrator privileges

#### Evidence
```text
Record retrieved without session ownership check: {"id":99,"username":"admin","email":"admin.demo@example.test","role":"admin","balance":10000,"password_hash":"$2b$10$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"}
```

#### Recommended Remediation
Verify that req.session.userId === requestedUserId or check ownership in the database query.

---

## Verified Secure Controls

- **[PASS] SAFE-XSS-REFLECT-001**: Contextual Output Encoding Verified on /api/secure/search on `/api/secure/search` (Cross-Site Scripting (XSS))
- **[PASS] SAFE-XSS-REFLECT-002**: Contextual Output Encoding Verified on /api/secure/search on `/api/secure/search` (Cross-Site Scripting (XSS))
- **[PASS] SAFE-XSS-JS-CONTEXT-001**: Contextual Output Encoding Verified on /api/secure/search on `/api/secure/search` (Cross-Site Scripting (XSS))
- **[PASS] SQLI-SAFE--api-secure-users**: Query Parameters Safely Bound on /api/secure/users on `/api/secure/users` (SQL Injection)
- **[PASS] SQLI-AUTH-SAFE--api-secure-login**: Authentication Input Properly Handled on /api/secure/login on `/api/secure/login` (SQL Injection)
- **[PASS] CSRF-TOKEN-ENFORCED--api-secure-transfer**: Anti-CSRF Token Enforced on /api/secure/transfer on `/api/secure/transfer` (Cross-Site Request Forgery (CSRF))
- **[PASS] CORS-SAFE--api-secure-profile-arbitrary_origin**: Strict CORS Origin Handling on /api/secure/profile on `/api/secure/profile` (CORS Misconfiguration)
- **[PASS] CORS-SAFE--api-secure-profile-null_origin**: Strict CORS Origin Handling on /api/secure/profile on `/api/secure/profile` (CORS Misconfiguration)
- **[PASS] HEADER-PRESENT-CONTENT_SECURITY_POLICY**: Header Present: Content-Security-Policy on `/api/secure/profile` (Security Headers)
- **[PASS] HEADER-PRESENT-X_FRAME_OPTIONS**: Header Present: X-Frame-Options on `/api/secure/profile` (Security Headers)
- **[PASS] HEADER-PRESENT-X_CONTENT_TYPE_OPTIONS**: Header Present: X-Content-Type-Options on `/api/secure/profile` (Security Headers)
- **[PASS] HEADER-PRESENT-REFERRER_POLICY**: Header Present: Referrer-Policy on `/api/secure/profile` (Security Headers)
- **[PASS] IDOR-SECURE-ENFORCED**: Object Ownership Verified on User Profile Endpoint on `/api/secure/idor/user/99` (Authorization (IDOR))

## Confidentiality & Disclaimer

This report was generated using the **Website Security Testing Toolkit** for authorized defensive validation. No sensitive passwords, production tokens, or customer personal data were gathered or stored during this assessment.
