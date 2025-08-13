// server.js
require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch'); // v2
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// --- Credenciales ---
const OSK_USER  = process.env.OPENSKY_USERNAME || process.env.OSK_USERNAME || '';
const OSK_PASS  = process.env.OPENSKY_PASSWORD || process.env.OSK_PASSWORD || '';
const OSK_CLIENT_ID     = process.env.OSK_CLIENT_ID || process.env.OPENSKY_CLIENT_ID || '';
const OSK_CLIENT_SECRET = process.env.OSK_CLIENT_SECRET || process.env.OPENSKY_CLIENT_SECRET || '';
const PROXY_SECRET = process.env.PROXY_SECRET || process.env.PROXY_AUTH_SECRET;

// --- CORS ---
const allowList = (process.env.ALLOW_ORIGIN || '')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!allowList.length || !origin || allowList.includes(origin)) cb(null, true);
    else cb(new Error('No permitido por CORS'));
  }
}));

// Cabecera para identificar el backend fácilmente
app.use((_, res, next) => { res.set('x-served-by', 'taxitip-proxy'); next(); });
app.use(express.json());

// --- Config de timeout/reintentos (ajustable por ENV) ---
const TOKEN_TIMEOUT_MS     = Number(process.env.TOKEN_TIMEOUT_MS     || 30000); // 30s
const TOKEN_MAX_RETRIES    = Number(process.env.TOKEN_MAX_RETRIES    || 3);
const TOKEN_RETRY_DELAY_MS = Number(process.env.TOKEN_RETRY_DELAY_MS || 1000);

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function fetchWithRetry(url, opts = {}, retries = TOKEN_MAX_RETRIES) {
  let lastErr;
  for (let i = 0; i <= retries; i++) {
    try {
      return await fetch(url, { ...opts, timeout: TOKEN_TIMEOUT_MS });
    } catch (err) {
      lastErr = err;
      if (i < retries) await sleep(TOKEN_RETRY_DELAY_MS);
    }
  }
  throw lastErr;
}

// --- Caché de token OAuth (se usa solo si NO hay Basic) ---
let cachedToken = null; // { access_token, expires_at }
const oauthConfigured = !!(OSK_CLIENT_ID && OSK_CLIENT_SECRET);
const basicConfigured = !!(OSK_USER && OSK_PASS);

async function fetchTokenFromOpenSky() {
  if (!oauthConfigured) throw new Error('OAuth no configurado');

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
    expires_at: Date.now() + Math.floor(ttl * 0.9) // refresco al 90%
  };
  return data.access_token;
}

async function getToken() {
  if (!oauthConfigured) throw new Error('OAuth no configurado');
  if (cachedToken && Date.now() < cachedToken.expires_at) return cachedToken.access_token;
  return await fetchTokenFromOpenSky();
}

// --- RUTAS PÚBLICAS ---
app.get('/', (_req, res) => {
  res.json({
    name: 'taxitip-proxy',
    mode: basicConfigured ? 'basic' : (oauthConfigured ? 'oauth' : 'none'),
    endpoints: {
      health: '/health',
      token_public: '/opensky/token',
      states_protected: '/opensky/states (header x-proxy-secret)'
    }
  });
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// /opensky/token: solo intentará OAuth si está configurado; si hay Basic, lo avisa
app.get('/opensky/token', async (_req, res) => {
  try {
    if (basicConfigured && !oauthConfigured) {
      return res.status(503).json({
        error: 'OAuth no configurado; el proxy usa Basic. Configure OPENSKY_CLIENT_ID/SECRET si desea OAuth.'
      });
    }
    if (!oauthConfigured) {
      return res.status(503).json({ error: 'OAuth no disponible. Configure OPENSKY_CLIENT_ID/SECRET.' });
    }
    const token = await getToken();
    res.json({ access_token: token, cached: true });
  } catch (err) {
    console.error('Error /opensky/token:', err);
    res.status(504).json({ error: 'Upstream timeout o no disponible', detail: String(err) });
  }
});

// --- MIDDLEWARE DE PROTECCIÓN (debajo de las públicas) ---
app.use((req, res, next) => {
  const secret = req.headers['x-proxy-secret'];
  if (secret !== PROXY_SECRET) return res.status(403).json({ error: 'Unauthorized' });
  next();
});

// --- RUTAS PROTEGIDAS ---
app.get('/opensky/states', async (req, res) => {
  try {
    const qs  = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const url = 'https://opensky-network.org/api/states/all' + qs;

    // Prioridad:
    // 1) Si nos pasan ?token= (Bearer) → úsalo
    // 2) Si hay Basic configurado → usar Basic (evita OAuth)
    // 3) Si no hay Basic, intentar OAuth (caché o fetch)
    let headers = {};
    if (req.query.token) {
      headers.Authorization = `Bearer ${req.query.token}`;
    } else if (basicConfigured) {
      headers.Authorization = 'Basic ' + Buffer.from(`${OSK_USER}:${OSK_PASS}`).toString('base64');
    } else if (oauthConfigured) {
      const t = await getToken();
      headers.Authorization = `Bearer ${t}`;
    } else {
      return res.status(400).json({
        error: 'No hay credenciales disponibles. Configure OPENSKY_USERNAME/PASSWORD o OPENSKY_CLIENT_ID/SECRET, o pase ?token='
      });
    }

    const r = await fetchWithRetry(url, { headers });
    const raw = await r.text();
    try { res.status(r.status).json(JSON.parse(raw)); }
    catch { res.status(r.status).json({ raw }); }
  } catch (err) {
    console.error('Error /opensky/states:', err);
    res.status(504).json({ error: 'Upstream timeout', detail: String(err) });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor proxy en puerto ${PORT}`);
});
