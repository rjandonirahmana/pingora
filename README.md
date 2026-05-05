# kinetic-proxy

Reverse proxy berbasis [Pingora](https://github.com/cloudflare/pingora) sebagai pengganti Nginx untuk stack Kinetic.

## Arsitektur

```
Internet :443/:80
    │
    ▼
kinetic-proxy  (Pingora)
    ├── /api/*   ──→ backend  (Axum, :8080)
    ├── /ws/*    ──→ backend  (Axum, :8080) — WebSocket passthrough
    └── /*       ──→ frontend (Leptos SPA, :3000)
```

## Fitur

| Fitur | Keterangan |
|---|---|
| **Routing** | Path-prefix: `/api` & `/ws` → backend, sisanya → frontend |
| **TLS termination** | Cert PEM (Let's Encrypt / Certbot) langsung di Pingora |
| **HTTP → HTTPS redirect** | Port 80 auto-redirect ke 443 jika TLS aktif |
| **CORS otomatis** | Inject header CORS di semua response `/api/*` |
| **OPTIONS preflight** | Dijawab langsung tanpa menyentuh upstream |
| **WebSocket** | Upgrade passthrough ke backend (chat `/ws/*`) |
| **Security headers** | X-Content-Type-Options, X-Frame-Options, dsb |
| **Cache static** | `immutable` 1 tahun untuk `/static/`, `.wasm`, `.js` |
| **Request ID** | `X-Request-Id` diinjeksikan ke upstream & dikembalikan ke client |
| **Real IP forwarding** | `X-Real-IP`, `X-Forwarded-For` |
| **Konfigurasi fleksibel** | `config.yaml` + ENV override |

## Quick start

### Development (plain HTTP)

```bash
# Jalankan backend dan frontend dulu:
# Terminal 1: cd backend && cargo run
# Terminal 2: cd frontend && trunk serve

# Jalankan proxy:
PROXY_LISTEN="0.0.0.0:8090" \
PROXY_BACKEND="127.0.0.1:8080" \
PROXY_FRONTEND="127.0.0.1:3000" \
cargo run
```

Akses di http://localhost:8090

### Produksi (TLS)

```bash
# 1. Issue sertifikat dengan certbot
certbot certonly --standalone -d yourdomain.com

# 2. Edit config.yaml — uncomment tls_cert & tls_key, ganti domain

# 3. Build release
cargo build --release

# 4. Jalankan (butuh CAP_NET_BIND_SERVICE atau root untuk port <1024)
sudo ./target/release/kinetic-proxy
```

### Systemd service

```ini
[Unit]
Description=Kinetic Proxy
After=network.target

[Service]
ExecStart=/opt/kinetic/kinetic-proxy
WorkingDirectory=/opt/kinetic
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
User=kinetic

[Install]
WantedBy=multi-user.target
```

## Konfigurasi

### config.yaml

```yaml
listen_addr:       "0.0.0.0:443"
backend_addr:      "127.0.0.1:8080"
frontend_addr:     "127.0.0.1:3000"
tls_cert:          "/etc/letsencrypt/live/domain.com/fullchain.pem"
tls_key:           "/etc/letsencrypt/live/domain.com/privkey.pem"
cors_origins:
  - "https://yourdomain.com"
rate_limit_rps:    200
upstream_pool_size: 64
```

### ENV override

| ENV | Default | Keterangan |
|---|---|---|
| `PROXY_LISTEN` | `0.0.0.0:80` | Alamat listen |
| `PROXY_BACKEND` | `127.0.0.1:8080` | Upstream backend |
| `PROXY_FRONTEND` | `127.0.0.1:3000` | Upstream frontend |
| `PROXY_TLS_CERT` | — | Path cert PEM |
| `PROXY_TLS_KEY` | — | Path key PEM |
| `PROXY_RATE_LIMIT_RPS` | `200` | Rate limit per IP |

## Routing rules

```
/api/health        → backend  (health check)
/api/auth/*        → backend
/api/events/*      → backend
/api/orders/*      → backend
/api/tickets/*     → backend
/api/merchant/*    → backend
/api/variants/*    → backend
/ws/*              → backend  (WebSocket chat)
/                  → frontend (SPA)
/events/*          → frontend (SPA route)
/explore           → frontend (SPA route)
/static/*.wasm     → frontend (di-cache 1 tahun)
/static/*.js       → frontend (di-cache 1 tahun)
```

## Perbandingan dengan Nginx

| | Nginx | kinetic-proxy |
|---|---|---|
| Bahasa | C | Rust |
| Memory safety | Tidak | Ya (borrow checker) |
| Konfigurasi | nginx.conf (DSL) | YAML + ENV |
| Hot reload | `nginx -s reload` | Restart (Pingora mendukung graceful) |
| WebSocket | Manual upgrade | Otomatis (Pingora handles) |
| Async | Event loop C | Tokio async/await |
| Modifikasi mudah | Perlu module Lua/C | Rust code biasa |
