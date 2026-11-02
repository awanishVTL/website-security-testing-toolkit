# Authorization & Access Control Testing Guide

## 1. What is the Vulnerability?

Authorization flaws, including Insecure Direct Object References (IDOR) and Broken Object-Level Authorization (BOLA), occur when an application relies on client-provided identifiers to access objects or administrative actions without verifying that the authenticated user possesses legitimate permissions or ownership rights to that resource.

## 2. Common Authorization Flaws

1. **IDOR (Horizontal Privilege Escalation):** User A modifies an object ID in an API request (e.g., `/api/documents/102` -> `/api/documents/103`) and accesses private records belonging to User B.
2. **Vertical Privilege Escalation:** A standard user directly invokes administrative endpoints (e.g., `DELETE /api/admin/users/42`) because the route checks only for authentication (`isLoggedIn`) but not specific administrative roles (`isAdmin`).
3. **Mass Assignment / Parameter Tampering:** A user updates their profile by sending `{"role": "admin"}` in a JSON body, which the backend blindly passes into the database update statement.
4. **Missing Function-Level Access Control:** Administrative APIs exposed without server-side permission checks, relying solely on hiding UI buttons on the client.

## 3. Realistic Attack Scenario

A patient portal allows viewing lab results via `GET /api/records/4591`. An attacker logs in as Patient A, inspects the network request, and modifies the URL to `GET /api/records/4592`. Because the database query simply runs `SELECT * FROM records WHERE id = ?` without verifying the requesting patient's ID, medical records belonging to other patients are leaked.

## 4. Vulnerable Code Examples

### Express.js (Vulnerable to IDOR & Mass Assignment)
```javascript
// VULNERABLE: Direct access to record by ID without checking ownership
app.get('/api/orders/:orderId', authenticateUser, async (req, res) => {
  const order = await db.getOrderById(req.params.orderId);
  if (!order) return res.status(404).send('Not found');

  // VULNERABLE: Returns order without verifying order.userId === req.user.id
  res.json(order);
});

// VULNERABLE: Mass assignment allowing privilege escalation
app.put('/api/profile', authenticateUser, async (req, res) => {
  // VULNERABLE: Blindly assigning request body to user record
  await db.updateUser(req.user.id, req.body); // Attacker sends { role: 'admin' }
  res.send('Profile updated');
});
```

## 5. Safe Testing Payloads & Verification

| ID | Category | Verification Technique |
| :--- | :--- | :--- |
| `IDOR-NUMERIC-001` | Horizontal IDOR | Authenticate as User 1; attempt to read/modify resource ID belonging to User 2. |
| `AUTHZ-ADMIN-BYPASS-001` | Vertical Escalation | Send standard user JWT/cookie to `/api/admin/*` endpoints; verify 403 Forbidden. |
| `AUTHZ-PRIV-ESCALATION-001` | Mass Assignment | Send `role: "admin"` in user update body; verify role remains unchanged. |
| `IDOR-UUID-LEAK-001` | UUID Obscurity Check | Request an unguessable UUID known from another user; verify ownership check still executes. |

## 6. How to Fix It (Remediation)

1. **Object-Level Ownership Validation:** Always scope database queries to the authenticated user's ID or organization:
   `SELECT * FROM orders WHERE id = ? AND user_id = ?`
2. **Explicit Role-Based Middleware:** Enforce role checks at the route layer:
   `app.use('/api/admin', requireAuth, requireRole('admin'))`
3. **Strict Parameter Allowlisting:** Never pass `req.body` directly to database update functions. Explicitly extract permitted fields (e.g. using Zod, Joi, or destructuring).
4. **Deny by Default:** Design access control policies to deny access unless an explicit rule grants permission.

## 7. Secure Code Examples

### Secure Object-Level Authorization & Role Middleware (Express.js)
```javascript
const express = require('express');
const app = express();
app.use(express.json());

// Role verification middleware
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied: insufficient permissions' });
    }
    next();
  };
}

// SECURE: Enforce resource ownership at the query level
app.get('/api/orders/:orderId', authenticateUser, async (req, res) => {
  const orderId = req.params.orderId;
  const currentUserId = req.user.id;

  // The database query itself guarantees ownership
  const [orders] = await db.query(
    'SELECT * FROM orders WHERE id = ? AND user_id = ?',
    [orderId, currentUserId]
  );

  if (orders.length === 0) {
    // Return 404 to avoid leaking record existence
    return res.status(404).json({ error: 'Order not found' });
  }

  res.json({ order: orders[0] });
});

// SECURE: Field allowlisting against Mass Assignment
app.put('/api/profile', authenticateUser, async (req, res) => {
  // Explicitly whitelist only editable fields
  const { displayName, bio } = req.body;

  await db.query(
    'UPDATE users SET display_name = ?, bio = ? WHERE id = ?',
    [displayName || '', bio || '', req.user.id]
  );

  res.json({ success: true, message: 'Profile updated safely' });
});

// SECURE: Administrative Route Grouping
app.delete('/api/admin/users/:userId', authenticateUser, requireRole('admin'), async (req, res) => {
  await db.query('DELETE FROM users WHERE id = ?', [req.params.userId]);
  res.json({ success: true, message: 'User account removed by administrator' });
});
```

## 8. OWASP References
- [OWASP Top 10:2021 – A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

## 9. Testing Checklist
- [ ] Every API endpoint fetching user data verifies that the requester owns the record.
- [ ] Administrative routes enforce `requireRole('admin')` middleware.
- [ ] Profile and user updates reject unexpected fields like `role`, `isAdmin`, or `balance`.
- [ ] Queries for sensitive resources use compound keys (`id = ? AND tenant_id = ?`).
- [ ] Access control tests verify negative test cases (unauthorized users receiving 403/404).
