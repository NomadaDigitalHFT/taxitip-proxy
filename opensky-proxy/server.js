require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch'); // v2
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// --- Credenciales ---
const OSK_CLIENT_ID     = process.env.OSK_CLIENT_ID     || process.env.OPENSKY_CLIENT_ID;
const OSK_CLIENT_SECRET = process.env.OSK_CLIENT_SECRET || process.env.OPENSKY_CLIENT_SECRET;
const OSK_USER          = process.env.OPENSKY_USERNAME  || process.env.OSK_USERNAME || '';
const OSK_PASS          = process.env.OPENSKY_PASSWORD  || process.env.OSK_PASSWORD || '';
const PROXY_SECRET      = process.env.PROXY_SECRET      || process.env.PROXY_AUTH_SECRET;

// --- CORS ---
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

// --- Config de timeout/reintentos (ajustable por ENV) ---
// Para /opensky/token (OAuth)
const TOKEN_TIMEOUT_MS     = Number(process.env.TOKEN_TIMEOUT_MS     || 15000);
const TOKEN_MAX_RETRIES    = Number(process.env.TOKEN_MAX_RETRIES    || 0);
const TOKEN_RETRY_DELAY_MS = Number(process.env.TOKEN_RETRY_DELAY_MS || 1000);

// Para /opensky/states (datos en vivo)
const STATES_TIMEOUT_MS    = Number(process.env.STATES_TIMEOUT_MS    || 15000);
const STATES_MAX_RETRIES   = Number(process.env.STATES_MAX_RETRIES   || 0);

const sleep = ms => new Promise(r => setTimeout(r, ms));

// Fetch con reintentos para /token
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

// Fetch con reintentos para /states
async function fetchStatesWithRetry(url, opts = {}, retries = STATES_MAX_RETRIES) {
  let lastErr;
  for (let i = 0; i <= retries; i++) {
    try {
      return await fetch(url, { ...opts, timeout: STATES_TIMEOUT_MS });
    } catch (err) {
      lastErr = err;
      if (i < retries) await sleep(TOKEN_RETRY_DELAY_MS);
    }
  }
  throw lastErr;
}

// --- Caché de token OAuth ---
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
  let data;
  try { data = JSON.parse(raw); } catch { data = { raw }; }
  if (data.access_token) {
    data.expires_at = Date.now() + ((data.expires_in || 0) * 1000);
    cachedToken = data;
  }
  return data;
}

// ------------------------
// Rutas públicas
// ------------------------
app.get('/health', (_req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// Obtener token (OAuth)
app.get('/opensky/token', async (_req, res) => {
  try {
    if (basicConfigured) {
      return res.json({ ok: true, msg: 'Usando Basic Auth, no se requiere token OAuth' });
    }
    const now = Date.now();
    if (cachedToken && cachedToken.expires_at > now + 5000) {
      return res.json(cachedToken);
    }
    const tokenData = await fetchTokenFromOpenSky();
    res.json(tokenData);
  } catch (err) {
    console.error('Error /opensky/token:', err);
    res.status(504).json({ error: 'Upstream timeout', detail: String(err) });
  }
});

// ------------------------
// Middleware protegido
// ------------------------
app.use((req, res, next) => {
  const secret = req.headers['x-proxy-secret'];
  if (secret !== PROXY_SECRET) return res.status(403).json({ error: 'Unauthorized' });
  next();
});

// ------------------------
// Rutas protegidas
// ------------------------
app.get('/opensky/states', async (req, res) => {
  try {
    const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const url = 'https://opensky-network.org/api/states/all' + qs;

    let headers = {};
    if (basicConfigured) {
      headers.Authorization = 'Basic ' + Buffer.from(`${OSK_USER}:${OSK_PASS}`).toString('base64');
    } else {
      const now = Date.now();
      if (!cachedToken || cachedToken.expires_at <= now + 5000) {
        await fetchTokenFromOpenSky();
      }
      if (!cachedToken || !cachedToken.access_token) {
        return res.status(500).json({ error: 'No se pudo obtener token OAuth' });
      }
      headers.Authorization = `Bearer ${cachedToken.access_token}`;
    }

    const r = await fetchStatesWithRetry(url, { headers });
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
