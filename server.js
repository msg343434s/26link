require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const db = require('./db');

const app = express();
app.set("trust proxy", true); // Required for Render

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error("JWT_SECRET missing. Set it in Render Environment.");
  process.exit(1);
}

app.use(express.json());
app.use(express.static('public'));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'interest-cohort=()');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

/* ---------------------------
   SIMPLE IN-MEMORY RATE LIMIT
---------------------------- */
const rate = new Map();
function rateLimit(limit, windowMs) {
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();

    if (!rate.has(ip)) rate.set(ip, []);
    const arr = rate.get(ip).filter(t => now - t < windowMs);
    arr.push(now);
    rate.set(ip, arr);

    if (arr.length > limit) return res.status(429).send("Too many requests");
    next();
  };
}

/* ---------------------------
   HELPERS
---------------------------- */
function generateShortKey() {
  return crypto.randomBytes(4).toString('base64url');
}

function hashUA(ua) {
  return crypto.createHash("sha256").update(ua || "").digest("hex");
}

/* ---------------------------
   CREATE SHORT LINK
---------------------------- */
app.post('/add-redirect', rateLimit(20, 60_000), async (req, res) => {
  const { destination } = req.body;
  if (!destination || !/^https?:\/\//i.test(destination)) {
    return res.status(400).json({ message: 'Invalid destination URL.' });
  }

  let key, saved = false;
  while (!saved) {
    key = generateShortKey();
    try { await db.addRedirect(key, destination); saved = true; } catch (e) {}
  }

  const url = `${req.protocol}://${req.get('host')}/${key}`;
  res.json({ redirectUrl: url });
});

/* ---------------------------
   FINAL REDIRECT (/go) — MUST BE BEFORE /:key
---------------------------- */
app.get('/go', rateLimit(60, 60_000), async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send("Missing token");

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Optional: IP/UA binding (disable for testing if needed)
    // if (decoded.ip !== req.ip) return res.status(403).send("Forbidden");
    // if (decoded.ua !== hashUA(req.headers['user-agent'])) return res.status(403).send("Forbidden");

    const row = await db.getRedirect(decoded.rid);
    if (!row) return res.status(404).send('Not found');

    return res.redirect(302, row.destination);
  } catch (e) {
    return res.status(403).send('Forbidden');
  }
});

/* ---------------------------
   CHALLENGE PAGE
---------------------------- */
app.get('/:key', rateLimit(60, 60_000), async (req, res) => {
  const key = req.params.key;

  // Block file access attempts
  if (key.includes('.') || key.length < 4) return res.status(404).send('Not found');

  const ua = req.headers['user-agent'] || '';
  if (/curl|wget|python|okhttp|scrapy|scanner|postman|headless|axios|node/i.test(ua)) {
    return res.status(404).send('Not found');
  }

  const row = await db.getRedirect(key);
  if (!row) return res.status(404).send('Not found');

  res.sendFile(path.join(__dirname, 'public', 'challenge.html'));
});

/* ---------------------------
   VERIFY HUMAN
---------------------------- */
app.post('/verify', rateLimit(30, 60_000), async (req, res) => {
  const d = req.body;

  if (!d.humanConfirmed) {
    return res.status(403).json({ ok: false });
  }

  const token = jwt.sign(
    {
      rid: d.rid,
      ip: req.ip,
      ua: hashUA(req.headers['user-agent']),
      exp: Math.floor(Date.now() / 1000) + 60
    },
    JWT_SECRET
  );

  res.json({ ok: true, token });
});


// Fallback 404
app.use((req, res) => res.status(404).send('Not found'));

// Listen on Render port
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
