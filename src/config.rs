//! Konfigurasi kinetic-proxy.
//!
//! Prioritas: ENV > config.yaml > default.
//!
//! FIX dari original:
//!   - Hapus image_addr (field lama :3902 yang tidak dipakai, menyesatkan)
//!   - Hapus upstream_pool_size (tidak dipakai di UpstreamPool)
//!   - Tambah doc comment yang jelas untuk masing-masing field

use serde::Deserialize;
use std::fs;

/// Konfigurasi utama proxy.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    // ── Listener ──────────────────────────────────────────────────────────────
    /// Alamat listen HTTPS, e.g. "0.0.0.0:443"
    #[serde(default = "default_listen")]
    pub listen_addr: String,

    /// Alamat listen HTTP untuk redirect → HTTPS, e.g. "0.0.0.0:80"
    #[serde(default = "default_http_redirect_addr")]
    pub http_redirect_addr: String,

    // ── Domain ────────────────────────────────────────────────────────────────
    /// Domain SPA frontend, e.g. "ulala.space"
    #[serde(default = "default_web_domain")]
    pub web_domain: String,

    /// Domain API backend + image, e.g. "ulalaapi.store"
    #[serde(default = "default_api_domain")]
    pub api_domain: String,

    // ── Upstream ──────────────────────────────────────────────────────────────
    /// Upstream Axum backend (REST + WebSocket), e.g. "127.0.0.1:8080"
    #[serde(default = "default_backend")]
    pub backend_addr: String,

    /// Upstream Leptos / static-web-server frontend, e.g. "127.0.0.1:3100"
    /// ulala.space/* → sini
    #[serde(default = "default_frontend")]
    pub frontend_addr: String,

    // ── TLS ───────────────────────────────────────────────────────────────────
    /// Sertifikat TLS untuk web_domain (fullchain.pem)
    /// WAJIB diset agar browser bisa akses ulala.space via HTTPS.
    /// Tanpa ini proxy berjalan plain HTTP di :443 → browser reject.
    pub tls_cert_web: Option<String>,

    /// Private key TLS untuk web_domain (privkey.pem)
    pub tls_key_web: Option<String>,

    /// Sertifikat TLS untuk api_domain (fullchain.pem)
    pub tls_cert_api: Option<String>,

    /// Private key TLS untuk api_domain (privkey.pem)
    pub tls_key_api: Option<String>,

    // ── CORS ──────────────────────────────────────────────────────────────────
    /// Origin yang diizinkan untuk /api/* di api_domain
    #[serde(default = "default_cors_origins")]
    pub cors_origins: Vec<String>,

    /// Origin tambahan untuk development local — tidak aktif di production.
    /// Contoh: ["http://localhost:3000", "http://localhost:5173"]
    #[serde(default)]
    pub dev_origins: Vec<String>,

    // ── Cache ─────────────────────────────────────────────────────────────────
    /// Berapa hari cache header untuk /image/* (0 = nonaktif)
    #[serde(default = "default_image_cache_days")]
    pub image_cache_days: u32,

    // ── Rate limit ────────────────────────────────────────────────────────────
    /// Max req/detik per IP (0 = nonaktif)
    #[serde(default = "default_rate_limit")]
    pub rate_limit_rps: u64,

    // ── RustFS ────────────────────────────────────────────────────────────────
    /// Upstream RustFS S3 API, e.g. "127.0.0.1:9000"
    /// Route: ulalaapi.store/image/* dan image.ulalaapi.store/*
    #[serde(default = "default_rustfs_s3")]
    pub rustfs_s3_address: String,

    /// Upstream RustFS Web Console, e.g. "127.0.0.1:9001"
    /// Route: ui.ulalaapi.store/*
    #[serde(default = "default_rustfs_ui")]
    pub rustfs_ui_address: String,

    /// Subdomain untuk RustFS S3 storage, e.g. "image.ulalaapi.store"
    #[serde(default = "default_image_subdomain")]
    pub image_subdomain: String,

    /// Subdomain untuk RustFS Web Console, e.g. "ui.ulalaapi.store"
    #[serde(default = "default_ui_subdomain")]
    pub ui_subdomain: String,
}

impl Config {
    pub fn load() -> Self {
        // 1. Baca config.yaml
        let mut cfg: Config = if let Ok(content) = fs::read_to_string("config.yaml") {
            serde_yaml::from_str(&content).unwrap_or_else(|e| {
                tracing::warn!("Gagal parse config.yaml: {e}. Pakai default.");
                Config::default()
            })
        } else {
            Config::default()
        };

        // 2. ENV override (prioritas lebih tinggi dari file)
        if let Ok(v) = std::env::var("PROXY_LISTEN") {
            cfg.listen_addr = v;
        }
        if let Ok(v) = std::env::var("PROXY_BACKEND") {
            cfg.backend_addr = v;
        }
        if let Ok(v) = std::env::var("PROXY_FRONTEND") {
            cfg.frontend_addr = v;
        }
        if let Ok(v) = std::env::var("PROXY_TLS_CERT_WEB") {
            cfg.tls_cert_web = Some(v);
        }
        if let Ok(v) = std::env::var("PROXY_TLS_KEY_WEB") {
            cfg.tls_key_web = Some(v);
        }
        if let Ok(v) = std::env::var("PROXY_TLS_CERT_API") {
            cfg.tls_cert_api = Some(v);
        }
        if let Ok(v) = std::env::var("PROXY_TLS_KEY_API") {
            cfg.tls_key_api = Some(v);
        }
        if let Ok(v) = std::env::var("PROXY_RATE_LIMIT_RPS") {
            cfg.rate_limit_rps = v.parse().unwrap_or(cfg.rate_limit_rps);
        }

        cfg
    }

    /// Apakah TLS dikonfigurasi (minimal cert web).
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert_web.is_some() && self.tls_key_web.is_some()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_addr: default_listen(),
            http_redirect_addr: default_http_redirect_addr(),
            web_domain: default_web_domain(),
            api_domain: default_api_domain(),
            backend_addr: default_backend(),
            frontend_addr: default_frontend(),
            tls_cert_web: None,
            tls_key_web: None,
            tls_cert_api: None,
            tls_key_api: None,
            cors_origins: default_cors_origins(),
            dev_origins: Vec::new(),
            image_cache_days: default_image_cache_days(),
            rate_limit_rps: default_rate_limit(),
            rustfs_s3_address: default_rustfs_s3(),
            rustfs_ui_address: default_rustfs_ui(),
            ui_subdomain: default_ui_subdomain(),
            image_subdomain: default_image_subdomain(),
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0:443".into()
}
fn default_http_redirect_addr() -> String {
    "0.0.0.0:80".into()
}
fn default_web_domain() -> String {
    "localhost".into()
}
fn default_api_domain() -> String {
    "localhost".into()
}
fn default_backend() -> String {
    "127.0.0.1:8080".into()
}
fn default_frontend() -> String {
    "127.0.0.1:3100".into()
}
fn default_cors_origins() -> Vec<String> {
    vec!["*".into()]
}
fn default_image_cache_days() -> u32 {
    30
}
fn default_rate_limit() -> u64 {
    200
}
fn default_rustfs_ui() -> String {
    "127.0.0.1:9001".into()
}
fn default_rustfs_s3() -> String {
    "127.0.0.1:9000".into()
}
fn default_ui_subdomain() -> String {
    "ui.ulalaapi.store".into()
}
fn default_image_subdomain() -> String {
    "image.ulalaapi.store".into()
}
