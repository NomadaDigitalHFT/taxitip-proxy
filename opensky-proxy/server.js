// server.js
require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch'); // v2
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// OAuth (client credentials)
const OSK_CLIENT_ID = process.env.OSK_CLIENT_ID || process.env.OPENSKY_CLIENT_ID;
const OSK_CLIENT_SECRET = process.env.OSK_CLIENT_SECRET || process.env.OPENSKY_CLIENT_SECRET;

// Basic (usuario/contraseña de OpenSky) - opcional
const OSK_USER = process.env.OPENSKY_USERNAME || process.env.OSK_USERNAME || '';
const OSK_PASS = process.env.OPENSKY_PASSWORD || process.env.OSK_PASSWORD || '';

// Proxy secret (para rutas protegidas)
const PROXY_SECRET = process.env.PROXY_SECRET || process.env.PROXY_AUTH_SECRET;

// CORS allowlist
const allowList = (process.env.ALLOW_ORIGIN || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!allowList.length || !origin || allowList.includes(origin)) cb(null, true);
    else cb(new Error('No permitido por CORS'));
  }
}));

app.use(express.json());

// ---------- Timeout + reintentos ----------
const TOKEN_TIMEOUT_MS = Number(process.env.TOKEN_TIMEOUT_MS || 30000);       // 30s
const TOKEN_MAX_RETRIES = Number(process.env.TOKEN_MAX_RETRIES || 3);         // 3 intentos
const TOKEN_RETRY_DELAY_MS = Number(process.env.TOKEN_RETRY_DELAY_MS || 1000); // 1s

function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

async function fetchWithRetry(url, opts={}, retries=TOKEN_MAX_RETRIES) {
  let lastErr, res;
  for (let i = 0; i <= retries; i++) {
    try {
      res = await fetch(url, { ...opts, timeout: TOKEN_TIMEOUT_MS });
      return res; // devolvemos aunque sea 4xx/5xx
    } catch (err) {
      lastErr = err;
      if (i < retries) await sleep(TOKEN_RETRY_DELAY_MS);
    }
  }
  throw lastErr;
}

// ---------- Cache de token ----------
let cachedToken = null; // { access_token, expires_at }

async function fetchTokenFromOpenSky() {
  const r = await fetchWithRetry(
    'https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: OSK_CLIENT_ID,
        client_secret: OSK_CLIENT_SECRET
      })
    }
  );

  const raw = await r.text();
  let data; try { data = JSON.parse(raw); } catch { data = { raw }; }
  if (!r.ok || !data.access_token) {
    const msg = JSON.stringify(data).slice(0, 300);
    throw new Error(`OpenSky token error (status ${r.status}): ${msg}`);
  }

  const ttl = (data.expires_in || 1800) * 1000;
  cachedToken = {
    access_token: data.access_token,
    // 90% del lifetime para refrescar antes de expirar
    expires_at: Date.now() + Math.floor(ttl * 0.9),
  };
  return data.access_token;
}

async function getToken() {
  if (cachedToken && Date.now() < cachedToken.expires_at) {
    return cachedToken.access_token;
  }
  return await fetchTokenFromOpenSky();
}

// ---------- Rutas públicas ----------
app.get('/health', (_req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

app.get('/opensky/token', async (_req, res) => {
  try {
    const token = await getToken();
    res.json({ access_token: token, cached: true });
  } catch (err) {
    console.error('Error /opensky/token:', err);
    res.status(504).json({ error: 'Upstream timeout', detail: String(err) });
  }
});

// ---------- Middleware de protección (debajo de públicas) ----------
app.use((req, res, next) => {
  const secret = req.headers['x-proxy-secret'];
  if (secret !== PROXY_SECRET) return res.status(403).json({ error: 'Unauthorized' });
  next();
});

// ---------- Rutas protegidas ----------
app.get('/opensky/states', async (req, res) => {
  try {
    // Reenvía todos los query params (lamin, lamax, etc.)
    const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const url = 'https://opensky-network.org/api/states/all' + qs;

    // 1) Si viene ?token= úsalo
    // 2) Si no, usa token del caché (OAuth)
    // 3) Si no, usa Basic (si configuraste OSK_USER/PASS)
    let headers = {};
    if (req.query.token) {
      headers.Authorization = `Bearer ${req.query.token}`;
    } else {
      try {
        const t = await getToken();
        headers.Authorization = `Bearer ${t}`;
      } catch {
        if (OSK_USER && OSK_PASS) {
          headers.Authorization = 'Basic ' + Buffer.from(`${OSK_USER}:${OSK_PASS}`).toString('base64');
        } else {
          return res.status(400).json({
            error: 'Falta token (?token=) o credenciales Basic (OPENSKY_USERNAME/OPENSKY_PASSWORD)'
          });
        }
      }
    }

    const r = await fetchWithRetry(url, { headers });
    const raw = await r.text();
    try {
      const json = JSON.parse(raw);
      return res.status(r.status).json(json);
    } catch {
      return res.status(r.status).json({ raw });
    }
  } catch (err) {
    console.error('Error /opensky/states:', err);
    res.status(504).json({ error: 'Upstream timeout', detail: String(err) });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor proxy en puerto ${PORT}`);
});
