import express from "express";
import fetch from "node-fetch";
import dotenv from "dotenv";
dotenv.config();

const app = express();

// --- Configuración de credenciales ---
const OSK_USER = process.env.OPENSKY_USERNAME;
const OSK_PASS = process.env.OPENSKY_PASSWORD;
const OSK_CLIENT_ID = process.env.OPENSKY_CLIENT_ID;
const OSK_CLIENT_SECRET = process.env.OPENSKY_CLIENT_SECRET;
const PROXY_SECRET = process.env.PROXY_SECRET || "tusecretoseguro123";

// --- Config de timeout/reintentos para TOKEN ---
const TOKEN_TIMEOUT_MS = Number(process.env.TOKEN_TIMEOUT_MS || 15000);
const TOKEN_MAX_RETRIES = Number(process.env.TOKEN_MAX_RETRIES || 0);
const TOKEN_RETRY_DELAY_MS = Number(process.env.TOKEN_RETRY_DELAY_MS || 1000);

// --- Config de timeout/reintentos para STATES ---
const STATES_TIMEOUT_MS = Number(process.env.STATES_TIMEOUT_MS || 15000);
const STATES_MAX_RETRIES = Number(process.env.STATES_MAX_RETRIES || 0);
const STATES_RETRY_DELAY_MS = Number(process.env.STATES_RETRY_DELAY_MS || 1000);
const STATES_CACHE_MS = Number(process.env.STATES_CACHE_MS || 60000); // 1 min caché

// --- Función genérica de reintentos ---
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function fetchWithRetry(url, opts = {}, retries = 0, delayMs = 1000) {
  let lastErr;
  for (let i = 0; i <= retries; i++) {
    try {
      return await fetch(url, { ...opts, timeout: opts.timeout || 15000 });
    } catch (err) {
      lastErr = err;
      if (i < retries) await sleep(delayMs);
    }
  }
  throw lastErr;
}

// --- Caché de token OAuth ---
let cachedToken = null; // { access_token, expires_at }
const oauthConfigured = !!(OSK_CLIENT_ID && OSK_CLIENT_SECRET);
const basicConfigured = !!(OSK_USER && OSK_PASS);

async function fetchTokenFromOpenSky() {
  if (!oauthConfigured) throw new Error("OAuth no configurado");

  const r = await fetchWithRetry(
    "https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: OSK_CLIENT_ID,
        client_secret: OSK_CLIENT_SECRET
      }),
      timeout: TOKEN_TIMEOUT_MS
    },
    TOKEN_MAX_RETRIES,
    TOKEN_RETRY_DELAY_MS
  );

  const data = await r.json();
  if (!data.access_token) throw new Error(`OAuth error: ${JSON.stringify(data)}`);

  cachedToken = {
    access_token: data.access_token,
    expires_at: Date.now() + (data.expires_in || 300) * 1000 - 5000
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

app.use(express.json());

// --- Health check ---
app.get("/health", (_req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// --- Token info ---
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

// --- Middleware de protección ---
app.use((req, res, next) => {
  const sec = req.headers["x-proxy-secret"];
  if (sec !== PROXY_SECRET) return res.status(403).json({ error: "Forbidden" });
  next();
});

// --- Caché de estados ---
let lastStates = null;
let lastStatesTs = 0;

// --- Endpoint de estados ---
app.get("/opensky/states", async (req, res) => {
  const now = Date.now();
  if (lastStates && now - lastStatesTs < STATES_CACHE_MS) {
    return res.json({ fromCache: true, data: lastStates });
  }

  try {
    const authHeader = await getAuthHeader();
    const url = `https://opensky-network.org/api/states/all?${new URLSearchParams(req.query)}`;

    const r = await fetchWithRetry(
      url,
      {
        headers: { Authorization: authHeader },
        timeout: STATES_TIMEOUT_MS
      },
      STATES_MAX_RETRIES,
      STATES_RETRY_DELAY_MS
    );

    const data = await r.json();
    lastStates = data;
    lastStatesTs = now;

    res.json({ fromCache: false, data });
  } catch (err) {
    if (lastStates) {
      res.json({ fromCache: true, stale: true, data: lastStates });
    } else {
      res.status(504).json({ error: "Upstream timeout", detail: String(err) });
    }
  }
});

// --- Start ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Proxy listening on ${PORT}`));
