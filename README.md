# taxitip-proxy

Backend mínimo (proxy de OpenSky) para desplegar en Render.

## Despliegue en Render
- **Root Directory**: `opensky-proxy`
- **Build Command**: `npm install`
- **Start Command**: `npm start`
- **Environment Variables**:
  - `OPENSKY_USERNAME`
  - `OPENSKY_PASSWORD`
  - `INTERNAL_BEARER_SECRET`

## Endpoints
- `GET /health` → estado del servicio
- `GET /flights` (protección Bearer) → consulta `states/all` y filtra por zona LEPA

### Ejemplo de prueba
```bash
# Health
curl -s https://TU-SERVICIO.onrender.com/health

# Flights (requiere bearer)
curl -s "https://TU-SERVICIO.onrender.com/flights" \
  -H "Authorization: Bearer TU_SECRETO_INTERNO"
