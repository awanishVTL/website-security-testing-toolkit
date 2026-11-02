/**
 * Interactive security test runner for browser demonstration UI
 */

async function testXss(mode) {
  const query = encodeURIComponent(document.getElementById('xssInput').value);
  const endpoint = mode === 'vulnerable' ? `/api/vulnerable/search?q=${query}` : `/api/secure/search?q=${query}`;
  document.getElementById('xssFrame').src = endpoint;
}

async function testSqli(mode) {
  const query = encodeURIComponent(document.getElementById('sqliInput').value);
  const endpoint = mode === 'vulnerable' ? `/api/vulnerable/users?query=${query}` : `/api/secure/users?query=${query}`;
  const out = document.getElementById('sqliOutput');
  out.textContent = 'Executing query test...';

  try {
    const res = await fetch(endpoint);
    const data = await res.json();
    out.textContent = `HTTP ${res.status} ${res.statusText}\n\n` + JSON.stringify(data, null, 2);
  } catch (err) {
    out.textContent = 'Error: ' + err.message;
  }
}

async function testCsrf(mode) {
  const recipient = document.getElementById('csrfRecipient').value;
  const amount = document.getElementById('csrfAmount').value;
  const out = document.getElementById('csrfOutput');
  out.textContent = 'Sending transfer request...';

  try {
    if (mode === 'vulnerable') {
      // Insecure: no CSRF token sent
      const res = await fetch('/api/vulnerable/transfer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient, amount })
      });
      const data = await res.json();
      out.textContent = `HTTP ${res.status}\n` + JSON.stringify(data, null, 2);
    } else {
      // Secure: fetch token first then send in header
      const tokenRes = await fetch('/api/csrf-token');
      const { csrf_token } = await tokenRes.json();

      const res = await fetch('/api/secure/transfer', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrf_token
        },
        body: JSON.stringify({ recipient, amount, csrf_token })
      });
      const data = await res.json();
      out.textContent = `HTTP ${res.status}\n` + JSON.stringify(data, null, 2);
    }
  } catch (err) {
    out.textContent = 'Error: ' + err.message;
  }
}

async function testCors(mode) {
  const endpoint = mode === 'vulnerable' ? '/api/vulnerable/profile' : '/api/secure/profile';
  const out = document.getElementById('corsOutput');
  out.textContent = 'Inspecting HTTP response headers...';

  try {
    const res = await fetch(endpoint, {
      headers: {
        'Origin': 'https://unauthorized-attacker.test'
      }
    });

    const headersList = [];
    res.headers.forEach((val, key) => {
      headersList.push(`${key}: ${val}`);
    });

    const body = await res.json();

    out.textContent = `Status: ${res.status} ${res.statusText}\n\n--- Response Headers ---\n` +
      headersList.join('\n') +
      `\n\n--- Response Body ---\n` +
      JSON.stringify(body, null, 2);
  } catch (err) {
    out.textContent = 'Error: ' + err.message;
  }
}

async function testIdor(mode) {
  const id = document.getElementById('idorId').value;
  const endpoint = mode === 'vulnerable' ? `/api/vulnerable/idor/user/${id}` : `/api/secure/idor/user/${id}`;
  const out = document.getElementById('idorOutput');
  out.textContent = 'Testing object ownership authorization...';

  try {
    const res = await fetch(endpoint);
    const data = await res.json();
    out.textContent = `HTTP ${res.status} ${res.statusText}\n\n` + JSON.stringify(data, null, 2);
  } catch (err) {
    out.textContent = 'Error: ' + err.message;
  }
}
