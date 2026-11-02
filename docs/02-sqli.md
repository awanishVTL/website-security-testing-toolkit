# SQL Injection (SQLi) Testing & Remediation Guide

## 1. What is the Vulnerability?

SQL Injection occurs when untrusted user input is directly concatenated, interpolated, or formatted into a dynamic Structured Query Language (SQL) statement before being executed by a relational database engine (e.g. MySQL, PostgreSQL, SQLite, Oracle).

## 2. How Does it Work?

1. **Error-Based SQLi:** An unescaped single quote (`'`) causes an SQL syntax error. In poorly configured systems, the error message reveals query structure or database contents.
2. **Authentication Bypass:** Injected SQL logic (such as `' OR '1'='1`) alters the boolean outcome of a `WHERE username = ... AND password = ...` query, evaluating to TRUE and authenticating the caller without credentials.
3. **Boolean-Based Blind SQLi:** An attacker injects conditions (`AND 1=1` vs `AND 1=2`). By observing differences in response size, status code, or page content, data can be reconstructed bit-by-bit.
4. **Time-Based Blind SQLi:** Injected commands invoke database sleep functions (e.g., `SLEEP(2)`), measuring backend response latency to infer data.

## 3. Why Does it Happen?

- Building queries using string concatenation (`"SELECT * FROM users WHERE id = " + id`).
- Relying on client-side validation or flawed regular expression filters instead of prepared statements.
- Misconfigured ORMs or using raw query escapes incorrectly (e.g. escaping identifiers as strings).

## 4. Realistic Attack Scenario

An e-commerce login endpoint performs authentication via:
```sql
SELECT id, role, password_hash FROM accounts WHERE email = 'user@example.com' AND status = 'active';
```
If the email parameter is vulnerable to concatenation, an attacker inputs:
```text
admin@example.com' -- 
```
The resulting executed query becomes:
```sql
SELECT id, role, password_hash FROM accounts WHERE email = 'admin@example.com' -- ' AND status = 'active';
```
The double-dash comment (`-- `) discards the rest of the query. If the backend fails to verify the password hash separately, administrative session access is granted immediately.

## 5. Vulnerable Code Examples

### Node.js / Express with MySQL (mysql2)
```javascript
// VULNERABLE: Direct string interpolation into SQL query
app.get('/api/users', async (req, res) => {
  const username = req.query.username;
  const sql = `SELECT id, username, email FROM users WHERE username = '${username}'`;

  try {
    const [rows] = await db.query(sql);
    res.json(rows);
  } catch (err) {
    // Leaks raw database error and query structure
    res.status(500).json({ error: err.message, sql });
  }
});
```

### Vulnerable ORM Raw Query
```javascript
// VULNERABLE: Using Sequelize or Prisma with unsafe raw literal replacement
const results = await sequelize.query(
  `SELECT * FROM products WHERE category = '${req.query.cat}'`
);
```

## 6. Safe Testing Payloads

These safe proof-of-concept payloads detect SQL parsing flaws without modifying or deleting records:

| ID | Payload | Purpose |
| :--- | :--- | :--- |
| `SQLI-ERR-001` | `'` | Detects syntax error disclosure. |
| `SQLI-AUTH-001` | `admin' OR '1'='1' -- ` | Tests authentication query bypass logic. |
| `SQLI-BOOL-001` | `1' AND '1'='1` | Tests true condition branch. |
| `SQLI-BOOL-002` | `1' AND '1'='2` | Tests false condition branch. |

## 7. Testing Methodology

1. **Identify Query Parameters:** Test all GET parameters, POST form fields, JSON properties, and HTTP headers used in database filters.
2. **Syntax Error Probing:** Submit a single quote (`'`), double quote (`"`), and backslash (`\`). Check response for 500 errors containing database keywords (`syntax error`, `mysql`, `ora-`, `sqlite`).
3. **Boolean Inference:** Compare responses for balanced conditional queries (`AND 1=1` vs `AND 1=2`).
4. **Inspect Source Code:** Audit all database queries for string concatenation, template literals, or unescaped variables.

## 8. Expected Results

- **Vulnerable:** Database throws syntax exceptions, or returns different result sets reflecting injected logic.
- **Secure:** Input is treated strictly as an immutable parameter. A query searching for `'` looks literally for a username consisting of a single quote and returns 0 rows cleanly.

## 9. How to Fix It (Remediation)

1. **Prepared Statements (Parameterized Queries):** Always pass untrusted input as parameters (`?` or `$1`). The database engine pre-compiles query structure before binding parameter values.
2. **ORM Best Practices:** Use built-in ORM query builders (e.g. Prisma `where: { username }` or Sequelize `where: { username: req.query.username }`).
3. **Allowlist Sorting and Columns:** For dynamic table names or `ORDER BY` directions where parameters are unsupported, validate against an immutable whitelist.
4. **Least Privilege Database Accounts:** Grant the application database user only `SELECT`, `INSERT`, `UPDATE`, and `DELETE` on needed tables; revoke administrative privileges (`GRANT ALL`, `DROP`, `FILE`, `SUPER`).

## 10. Secure Code Examples

### Secure Node.js with MySQL (mysql2 prepared statements)
```javascript
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

// SECURE: Parameterized Query
app.get('/api/users', async (req, res) => {
  const searchUsername = req.query.username || '';
  const sql = 'SELECT id, username, email FROM users WHERE username = ?';

  try {
    const [rows] = await pool.execute(sql, [searchUsername]);
    res.json(rows);
  } catch (err) {
    // Generic error message - never leak raw SQL or stack trace
    console.error('Database query error:', err);
    res.status(500).json({ error: 'An internal error occurred while fetching user data' });
  }
});

// SECURE: Safe Authentication with Parameterization and Hashing
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const [users] = await pool.execute(
      'SELECT id, username, password_hash, role FROM users WHERE username = ?',
      [username]
    );

    if (users.length === 0) {
      // Prevent user enumeration by returning generic failure
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = users[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Login successful
    res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Authentication service temporarily unavailable' });
  }
});
```

### Secure Dynamic Column Sorting via Allowlist
```javascript
// SECURE: Whitelist validation for dynamic ORDER BY
app.get('/api/products', async (req, res) => {
  const ALLOWED_COLUMNS = ['price', 'created_at', 'name'];
  const ALLOWED_DIRECTIONS = ['ASC', 'DESC'];

  const sortBy = ALLOWED_COLUMNS.includes(req.query.sort) ? req.query.sort : 'created_at';
  const order = ALLOWED_DIRECTIONS.includes(req.query.order?.toUpperCase()) ? req.query.order.toUpperCase() : 'ASC';

  const [products] = await pool.execute(
    `SELECT id, name, price FROM products ORDER BY ${sortBy} ${order}`
  );
  res.json(products);
});
```

## 11. OWASP References
- [OWASP Top 10:2021 – A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

## 12. Testing Checklist
- [ ] Every database query uses prepared statements with placeholder parameters.
- [ ] No queries use string interpolation or concatenation for SQL generation.
- [ ] Dynamic table names and sort columns are validated against strict string allowlists.
- [ ] Database error messages are suppressed in production HTTP responses.
- [ ] Database credentials operate under the principle of least privilege.
