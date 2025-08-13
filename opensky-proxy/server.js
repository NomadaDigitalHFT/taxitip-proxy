// server.js (reemplazo completo)

const express = require("express");
const fetch = require("node-fetch");
const https = require("https");
const cors = require("cors");
require("dotenv").config();

const app = express();

// --- Credenciales / Config ---
const OSK_USER = process.env.OPENSKY_USERNAME;
const OSK_PASS = process.env.OPENSKY_PASSWORD;
const OSK_CLIENT_ID = process.env.OPENSKY_CLIENT_ID;
const OSK_CLIENT_SECRET = process.env.OPENSKY_CLIENT_SECRET;

const PROXY_SECRET = process.env.PROXY_SECRET || "tusecretoseguro123";

// Timeouts y reintentos (valores por defecto razonables)
const TOKEN_TIMEOUT_MS       = Number(process.env.TOKEN_TIMEOUT_MS       || 15000);
const TOKEN_MAX_RETRIES      = Number(process.env.TOKEN_MAX_RETRIES      || 2);
const TOKEN_RETRY_DELAY_MS   = Number(process.env.TOKEN_RETRY_DELAY_MS   || 1000);

const STATES_TIMEOUT_MS      = Number(process.env.STATES_TIMEOUT_MS      || 30000);
const STATES_MAX_RETRIES     = Number(process.env.STATES_MAX_RETRIES     || 3);
const STATES_RETRY_BASE_MS   = Number(process.env.STATES_RETRY_DELAY_MS  || 1000);
const STATES_CACHE_MS        = Number(process.env.STATES_CACHE_MS        || 60000);

// --- Keep-Alive Agent (mejora estabilidad) ---
const httpsAgent = new https.Agent({ keepAlive: true });

// --- Utilidades ---
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const jsonOrText = async (res) => {
  const ctype = res.headers.get("content-type") || "";
  if (ctype.includes("application/json")) return res.json();
  const txt = await res.text();
  // Intenta parsear json aunque ctype no venga correcto
  try { return JSON.parse(txt); } catch { return { nonJson: true, body: txt }; }
};

// Backoff exponencial con jitter
async function fetchWithRetry(url, opts, retries, baseDelayMs, timeoutMs) {
  let attempt = 0;
  let lastErr;
  while (attempt <= retries) {
    try {
      const res = await fetch(url, {
        ...opts,
        agent: httpsAgent,
        timeout: timeoutMs,
        headers: {
          "User-Agent": "TaxiTip-OpenSky-Proxy/1.0",
          ...(opts && opts.headers ? opts.headers : {}),
        },
      });

      // Reintenta en 429/5xx
      if ([408, 429, 500, 502, 503, 504].includes(res.status)) {
        lastErr = new Error(`HTTP ${res.status}`);
        throw lastErr;
      }
      return res;
    } catch (err) {
      lastErr = err;
      if (attempt === retries) break;
      const jitter = Math.floor(Math.random() * 200);
      const delay = Math.min(15000, baseDelayMs * Math.pow(2, attempt)) + jitter;
      await sleep(delay);
    } finally {
      attempt++;
    }
  }
  throw lastErr;
}

// --- Auth helpers ---
let cachedToken = null; // { access_token, expires_at }
const oauthConfigured = !!(OSK_CLIENT_ID && OSK_CLIENT_SECRET);
const basicConfigured = !!(OSK_USER && OSK_PASS);

async function fetchTokenFromOpenSky() {
  if (!oauthConfigured) throw new Error("OAuth no configurado");

  const res = await fetchWithRetry(
    "https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: OSK_CLIENT_ID,
        client_secret: OSK_CLIENT_SECRET,
      }),
    },
    TOKEN_MAX_RETRIES,
    TOKEN_RETRY_DELAY_MS,
    TOKEN_TIMEOUT_MS
  );

  const data = await jsonOrText(res);
  if (!res.ok) throw new Error(`OAuth ${res.status}: ${JSON.stringify(data)}`);
  if (!data.access_token) throw new Error(`OAuth sin access_token: ${JSON.stringify(data)}`);

  cachedToken = {
    access_token: data.access_token,
    expires_at: Date.now() + (data.expires_in || 300) * 1000 - 5000,
  };
  return cachedToken.access_token;
}

async function getAuthHeader() {
  if (basicConfigured) {
    return "Basic " + Buffer.from(`${OSK_USER}:${OSK_PASS}`).toString("base64");
  }
  if (!cachedToken || Date.now() >= cachedToken.expires_at) {
    await fetchTokenFromOpenSky();
  }
  return `Bearer ${cachedToken.access_token}`;
}

// --- Middlewares base ---
app.use(express.json());
app.use(cors()); // habilitar CORS para llamadas desde tu frontend

// --- Endpoints públicos ---
app.get("/health", (_req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

app.get("/opensky/token", async (_req, res) => {
  try {
    if (basicConfigured) {
      return res.json({ ok: true, msg: "Usando Basic Auth, no se requiere token OAuth" });
    }
    const token = await getAuthHeader();
    res.json({ ok: true, token });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// --- Protección por secreto interno ---
app.use((req, res, next) => {
  const sec = req.headers["x-proxy-secret"];
  if (sec !== PROXY_SECRET) return res.status(403).json({ error: "Forbidden" });
  next();
});

// --- Caché de estados ---
let lastStates = null;
let lastStatesTs = 0;

// Helper de consulta
async function queryStates(query) {
  const authHeader = await getAuthHeader();
  const url = `https://opensky-network.org/api/states/all?${new URLSearchParams(query)}`;

  const res = await fetchWithRetry(
    url,
    { headers: { Authorization: authHeader } },
    STATES_MAX_RETRIES,
    STATES_RETRY_BASE_MS,
    STATES_TIMEOUT_MS
  );

  const data = await jsonOrText(res);
  if (!res.ok) throw new Error(`OpenSky ${res.status}: ${JSON.stringify(data).slice(0, 500)}`);
  return data;
}

// --- Endpoint genérico ---
app.get("/opensky/states", async (req, res) => {
  const now = Date.now();

  // Sirve caché si está fresca
  if (lastStates && now - lastStatesTs < STATES_CACHE_MS) {
    return res.json({ fromCache: true, data: lastStates, cachedAt: lastStatesTs });
  }

  try {
    const data = await queryStates(req.query);
    lastStates = data;
    lastStatesTs = now;
    res.json({ fromCache: false, data, cachedAt: lastStatesTs });
  } catch (err) {
    // Fallback a caché si existe (sirve datos obsoletos)
    if (lastStates) {
      return res.json({ fromCache: true, stale: true, data: lastStates, cachedAt: lastStatesTs, error: String(err) });
    }
    res.status(504).json({ error: "Upstream timeout", detail: String(err) });
  }
});

// --- Endpoint útil para LEPA (Palma) ---
app.get("/opensky/states/lepa", async (_req, res) => {
  // Caja pequeña de Mallorca (ajústala si lo ves necesario)
  const query = {
    lamin: "39.45",
    lomin: "2.55",
    lamax: "39.80",
    lomax: "3.35",
  };

  const now = Date.now();
  if (lastStates && now - lastStatesTs < STATES_CACHE_MS) {
    return res.json({ fromCache: true, data: lastStates, cachedAt: lastStatesTs });
  }

  try {
    const data = await queryStates(query);
    lastStates = data;
    lastStatesTs = now;
    res.json({ fromCache: false, data, cachedAt: lastStatesTs });
  } catch (err) {
    if (lastStates) {
      return res.json({ fromCache: true, stale: true, data: lastStates, cachedAt: lastStatesTs, error: String(err) });
    }
    res.status(504).json({ error: "Upstream timeout", detail: String(err) });
  }
});

// --- Start ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Proxy listening on ${PORT}`));
