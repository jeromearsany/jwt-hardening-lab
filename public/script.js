// public/script.js
const out = document.getElementById('out');
const serverUrlInput = document.getElementById('serverUrl');
const loginForm = document.getElementById('loginForm');
const whoamiBtn = document.getElementById('whoamiBtn');
const adminBtn = document.getElementById('adminBtn');
const refreshBtn = document.getElementById('refreshBtn');
const clearBtn = document.getElementById('clearBtn');

function log(message) {
  if (typeof message === 'object') {
    out.textContent = JSON.stringify(message, null, 2);
  } else {
    out.textContent = message;
  }
}

function getStoredToken() {
  // Vulnerable server uses localStorage.token
  // Secure server stores access token in sessionStorage.accessToken and refresh in HttpOnly cookie
  return localStorage.getItem('token') || sessionStorage.getItem('accessToken') || '';
}

async function loginTo(server, username, password) {
  try {
    const res = await fetch(server + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // include credentials so secure server can set HttpOnly refresh cookie
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });

    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch (e) { data = text; }

    // Behavior:
    // - Vulnerable server returns { token: '...' } -> store in localStorage
    // - Secure server returns { accessToken: '...' } and sets refresh cookie -> store access in sessionStorage
    if (data && data.token) {
      localStorage.setItem('token', data.token);
      log({ note: 'Stored token in localStorage (vulnerable pattern)', token: data.token });
    } else if (data && data.accessToken) {
      sessionStorage.setItem('accessToken', data.accessToken);
      log({ note: 'Received access token (secure pattern - refresh cookie set HttpOnly)', accessToken: data.accessToken });
    } else {
      log({ status: res.status, body: data });
    }
  } catch (err) {
    log({ error: 'Network or server error', details: String(err) });
  }
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  log('Logging in...');
  const server = serverUrlInput.value.replace(/\/$/, '');
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  await loginTo(server, username, password);
});

whoamiBtn.addEventListener('click', async () => {
  const server = serverUrlInput.value.replace(/\/$/, '');
  const token = getStoredToken();
  if (!token) {
    log('No token found (check localStorage or sessionStorage).');
    return;
  }
  try {
    const res = await fetch(server + '/whoami', {
      headers: { Authorization: 'Bearer ' + token },
      credentials: 'include'
    });
    const data = await res.json();
    log({ endpoint: '/whoami', status: res.status, body: data });
  } catch (err) {
    log({ error: 'Fetch error', details: String(err) });
  }
});

adminBtn.addEventListener('click', async () => {
  const server = serverUrlInput.value.replace(/\/$/, '');
  const token = getStoredToken();
  try {
    const res = await fetch(server + '/admin', {
      method: 'GET',
      headers: { Authorization: 'Bearer ' + token },
      credentials: 'include'
    });
    // try parse JSON, else text
    const text = await res.text();
    try {
      const json = JSON.parse(text);
      log({ endpoint: '/admin', status: res.status, body: json });
    } catch (e) {
      log({ endpoint: '/admin', status: res.status, body: text });
    }
  } catch (err) {
    log({ error: 'Fetch error', details: String(err) });
  }
});

refreshBtn.addEventListener('click', async () => {
  const server = serverUrlInput.value.replace(/\/$/, '');
  try {
    const res = await fetch(server + '/refresh', {
      method: 'POST',
      credentials: 'include'
    });
    const data = await res.json();
    // secure server returns new accessToken in body and sets refresh cookie again
    if (data && data.accessToken) {
      sessionStorage.setItem('accessToken', data.accessToken);
      log({ note: 'Refreshed access token', accessToken: data.accessToken });
    } else {
      log({ status: res.status, body: data });
    }
  } catch (err) {
    log({ error: 'Fetch error', details: String(err) });
  }
});

clearBtn.addEventListener('click', () => {
  // Clear client-side stored tokens
  localStorage.removeItem('token');
  sessionStorage.removeItem('accessToken');

  // Best-effort to clear cookies by setting past expiry for current domain
  // Note: HttpOnly cookies cannot be removed from JS; they will be removed by server logout or by setting cookie with same name/path from server side.
  document.cookie.split(';').forEach(cookie => {
    const name = cookie.split('=')[0].trim();
    document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`;
  });

  log('Cleared localStorage token, sessionStorage accessToken, and attempted to clear non-HttpOnly cookies. HttpOnly cookies (e.g., refreshToken) cannot be cleared via JS.');
});
