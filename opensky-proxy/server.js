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

// Basic (usuario/contraseña del sitio OpenSky)
const OSK_USER = process.env.OPENSKY_USERNAME || process.env.OSK_USERNAME || '';
const OSK_PASS = process.env.OPENSKY_PASSWORD || process.env.OSK_PASSWORD || '';

// Proxy secret (para proteger rutas privadas)
const PROXY_SECRET = process.env.PROXY_SECRET || process.env.PROXY_AUTH_SECRET;

// CORS
const allowList = (process.env.ALLOW_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!allowList.length || !origin || allowList.includes(origin)) cb(null, true);
    else cb(new Error('No permitido por CORS'));
  }
}));

app.use(express.json());

// ------------------------
// Rutas públicas
// ------------------------
app.get('/health', (_req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

app.get('/opensky/token', async (_req, res) => {
  try {
    const tokenResponse = await fetch(
      'https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: OSK_CLIENT_ID,
          client_secret: OSK_CLIENT_SECRET
        }),
        timeout: 15000 // 15s
      }
    );

    const rawText = await tokenResponse.text();
    let data;
    try { data = JSON.parse(rawText); } catch { data = { raw: rawText }; }
    res.status(tokenResponse.status).json(data);
  } catch (err) {
    console.error('Error /opensky/token:', err);
    res.status(500).json({ error: String(err) });
  }
});

// ------------------------
// Middleware de protección
// (aplica a todo lo que está debajo)
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
    // Reenvía todos los query params (lamin, lamax, etc.)
    const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const url = 'https://opensky-network.org/api/states/all' + qs;

    // Preferir Bearer si viene ?token=..., si no hay token y tienes user/pass, usa Basic
    const token = req.query.token;
    let headers = {};
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    } else if (OSK_USER && OSK_PASS) {
      headers.Authorization = 'Basic ' + Buffer.from(`${OSK_USER}:${OSK_PASS}`).toString('base64');
    } else {
      return res.status(400).json({
        error: 'Falta token (?token=) o credenciales Basic (OPENSKY_USERNAME/OPENSKY_PASSWORD)'
      });
    }

    const r = await fetch(url, { headers, timeout: 20000 }); // 20s
    const raw = await r.text();
    try {
      const json = JSON.parse(raw);
      return res.status(r.status).json(json);
    } catch {
      return res.status(r.status).json({ raw });
    }
  } catch (err) {
    console.error('Error /opensky/states:', err);
    res.status(500).json({ error: String(err) });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor proxy en puerto ${PORT}`);
});
