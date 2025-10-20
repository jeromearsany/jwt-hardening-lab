// vuln-server.js  (INTENTIONALLY INSECURE — local lab only)
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = 1234;
const DB = new sqlite3.Database('./users.db');
const WEAK_SECRET = 'weak-secret'; // intentionally weak — DO NOT USE OUTSIDE LAB

// Login — issues JWT (stored by frontend in localStorage)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  DB.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'db' });
    if (!row || !bcrypt.compareSync(password, row.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    // Insecure: long expiry, weak secret (for demo)
    const token = jwt.sign({ sub: row.username, role: row.role }, WEAK_SECRET, { algorithm: 'HS256', expiresIn: '7d' });
    return res.json({ token });
  });
});

/*
  VULNERABLE /admin endpoint (DEMONSTRATION PURPOSES)
  - Accepts:
    1) Properly signed tokens verified with WEAK_SECRET (normal)
    2) Unsigned tokens where header.alg === 'none' — decoded and trusted (INTENTIONALLY INSECURE)
  This is so students can edit the token header to {"alg":"none"} and gain access in the lab.
*/
app.get('/admin', (req, res) => {
  const auth = (req.headers.authorization || '');
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'No token' });

  // 1) Try to parse header to detect "alg"
  let header;
  try {
    const parts = token.split('.');
    if (parts.length < 2) throw new Error('bad token');
    header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf8'));
  } catch (e) {
    // Malformed token header
    return res.status(401).json({ error: 'Invalid token header' });
  }

  // If header.alg === 'none', intentionally accept the payload WITHOUT verifying signature.
  // THIS IS DELIBERATELY INSECURE — only for classroom demos.
  if (header && String(header.alg).toLowerCase() === 'none') {
    try {
      // Decode payload without verification
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8'));
      // For demo: allow admin access if payload.role === 'admin'
      if (payload && payload.role === 'admin') {
        return res.json({ secret: 'VERY SENSITIVE ADMIN DATA (ACCESSED VIA alg:none DEMO)' });
      } else {
        return res.status(403).json({ error: 'Forbidden (payload role not admin)' });
      }
    } catch (e) {
      return res.status(401).json({ error: 'Invalid token payload' });
    }
  }

  // Otherwise, attempt normal verification (signed HS256 tokens)
  try {
    const decoded = jwt.verify(token, WEAK_SECRET, { algorithms: ['HS256'] });
    if (decoded.role === 'admin') return res.json({ secret: 'VERY SENSITIVE ADMIN DATA' });
    return res.status(403).json({ error: 'Forbidden' });
  } catch (e) {
    // Signature invalid or expired
    return res.status(401).json({ error: 'Invalid token (signature or expired)' });
  }
});

// Simple endpoint to fetch token payload (for student observation)
app.get('/whoami', (req, res) => {
  const auth = (req.headers.authorization || '');
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return res.json({ msg: 'no token' });
  try {
    // decode without verification for inspection only
    const complete = jwt.decode(token, { complete: true });
    return res.json({ decoded: complete });
  } catch (e) {
    return res.json({ error: 'bad token' });
  }
});

app.listen(PORT, () => console.log(`VULN server running at http://localhost:${PORT} — FOR LAB USE ONLY`));
