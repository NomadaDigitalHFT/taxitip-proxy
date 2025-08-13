require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

const OSK_CLIENT_ID = process.env.OSK_CLIENT_ID || process.env.OPENSKY_CLIENT_ID;
const OSK_CLIENT_SECRET = process.env.OSK_CLIENT_SECRET || process.env.OPENSKY_CLIENT_SECRET;
const PROXY_SECRET = process.env.PROXY_SECRET || process.env.PROXY_AUTH_SECRET;
const ALLOW_ORIGIN = (process.env.ALLOW_ORIGIN || '').split(',');

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || ALLOW_ORIGIN.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por CORS'));
    }
  }
}));

app.use(express.json());

// Middleware de autenticación
app.use((req, res, next) => {
  const secret = req.headers['x-proxy-secret'];
  if (secret !== PROXY_SECRET) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
});

// Health check
app.get('/health', (_req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// Obtener token de OpenSky
app.get('/opensky/token', async (_req, res) => {
  try {
    console.log('Solicitando token a OpenSky...');
    console.log('CLIENT_ID usado:', OSK_CLIENT_ID);

    const tokenResponse = await fetch(
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

    console.log('Respuesta recibida. Status:', tokenResponse.status);
    const rawText = await tokenResponse.text();
    console.log('Cuerpo de respuesta:', rawText);

    let data;
    try {
      data = JSON.parse(rawText);
    } catch {
      data = { raw: rawText };
    }

    res.status(tokenResponse.status).json(data);
  } catch (error) {
    console.error('Error al obtener token:', error);
    res.status(500).json({ error: error.message });
  }
});

// Obtener estados de vuelos
app.get('/opensky/states', async (req, res) => {
  try {
    const token = req.query.token;
    const url = 'https://opensky-network.org/api/states/all' +
                (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '');

    const headers = token
      ? { Authorization: `Bearer ${token}` }
      : { Authorization: 'Basic ' + Buffer.from(`${OSK_CLIENT_ID}:${OSK_CLIENT_SECRET}`).toString('base64') };

    console.log('Solicitando estados de vuelos a:', url);
    const statesResponse = await fetch(url, { headers });
    console.log('Respuesta estados. Status:', statesResponse.status);

    const data = await statesResponse.json();
    res.json(data);
  } catch (error) {
    console.error('Error al obtener datos de vuelos:', error);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor proxy en puerto ${PORT}`);
});

