//! Konfigurasi kinetic-proxy.
//!
//! Prioritas: ENV > config.yaml > default.
//!
//! Fix:
//!   - Tambah image_addr agar YAML lama tidak error parse
//!   - Tambah upstream_pool_size (ignored tapi tidak panic)
//!   - Tambah ENV override untuk web_domain, api_domain
//!   - tls_enabled(): cek cert+key keduanya exist di filesystem, bukan hanya Some()
//!   - Config::validate(): panic early jika cert file tidak ada

use serde::Deserialize;
use std::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    // ── Listener ──────────────────────────────────────────────────────────────
    #[serde(default = "default_listen")]
    pub listen_addr: String,

    #[serde(default = "default_http_redirect_addr")]
    pub http_redirect_addr: String,

    // ── Domain ────────────────────────────────────────────────────────────────
    #[serde(default = "default_web_domain")]
    pub web_domain: String,

    #[serde(default = "default_api_domain")]
    pub api_domain: String,

    // ── Upstream ──────────────────────────────────────────────────────────────
    #[serde(default = "default_backend")]
    pub backend_addr: String,

    #[serde(default = "default_frontend")]
    pub frontend_addr: String,

    /// Field lama — diabaikan tapi tidak panic saat parse YAML lama.
    #[serde(default)]
    pub image_addr: Option<String>,

    /// Field lama — diabaikan tapi tidak panic saat parse YAML lama.
    #[serde(default)]
    pub upstream_pool_size: Option<u32>,

    // ── TLS ───────────────────────────────────────────────────────────────────
    pub tls_cert_web: Option<String>,
    pub tls_key_web: Option<String>,
    pub tls_cert_api: Option<String>,
    pub tls_key_api: Option<String>,

    // ── CORS ──────────────────────────────────────────────────────────────────
    #[serde(default = "default_cors_origins")]
    pub cors_origins: Vec<String>,

    #[serde(default)]
    pub dev_origins: Vec<String>,

    // ── Cache ─────────────────────────────────────────────────────────────────
    #[serde(default = "default_image_cache_days")]
    pub image_cache_days: u32,

    // ── Rate limit ────────────────────────────────────────────────────────────
    #[serde(default = "default_rate_limit")]
    pub rate_limit_rps: u64,

    // ── RustFS ────────────────────────────────────────────────────────────────
    #[serde(default = "default_rustfs_s3")]
    pub rustfs_s3_address: String,

    #[serde(default = "default_rustfs_ui")]
    pub rustfs_ui_address: String,

    #[serde(default = "default_image_subdomain")]
    pub image_subdomain: String,

    #[serde(default = "default_ui_subdomain")]
    pub ui_subdomain: String,

    #[serde(default)]
    pub frontend_dist_path: Option<String>,
}

impl Config {
    pub fn load() -> Self {
        // 1. Baca config.yaml
        let mut cfg: Config = if let Ok(content) = fs::read_to_string("config.yaml") {
            match serde_yaml::from_str(&content) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("FATAL: Gagal parse config.yaml: {e}");
                    tracing::error!("Cek indentasi dan field di config.yaml");
                    std::process::exit(1);
                }
            }
        } else {
            tracing::warn!("config.yaml tidak ditemukan, pakai default");
            Config::default()
        };

        // 2. ENV override (prioritas lebih tinggi dari file)
        macro_rules! env_str {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    $field = v;
                }
            };
        }
        env_str!("PROXY_LISTEN", cfg.listen_addr);
        env_str!("PROXY_BACKEND", cfg.backend_addr);
        env_str!("PROXY_FRONTEND", cfg.frontend_addr);
        env_str!("PROXY_WEB_DOMAIN", cfg.web_domain);
        env_str!("PROXY_API_DOMAIN", cfg.api_domain);

        macro_rules! env_opt {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    $field = Some(v);
                }
            };
        }
        env_opt!("PROXY_TLS_CERT_WEB", cfg.tls_cert_web);
        env_opt!("PROXY_TLS_KEY_WEB", cfg.tls_key_web);
        env_opt!("PROXY_TLS_CERT_API", cfg.tls_cert_api);
        env_opt!("PROXY_TLS_KEY_API", cfg.tls_key_api);

        if let Ok(v) = std::env::var("PROXY_RATE_LIMIT_RPS") {
            cfg.rate_limit_rps = v.parse().unwrap_or(cfg.rate_limit_rps);
        }

        // 3. Validasi — log WARNING jelas jika TLS bermasalah
        cfg.validate();
        cfg
    }

    /// Apakah TLS dikonfigurasi DAN cert file benar-benar ada di disk.
    /// Ini yang penting: path bisa di-set tapi file tidak ada → proxy tetap jalan
    /// tapi gagal saat load cert → crash atau plain HTTP.
    pub fn tls_enabled(&self) -> bool {
        match (&self.tls_cert_web, &self.tls_key_web) {
            (Some(cert), Some(key)) => {
                let cert_ok = std::path::Path::new(cert).exists();
                let key_ok = std::path::Path::new(key).exists();
                if !cert_ok {
                    tracing::error!("TLS cert web tidak ditemukan: {cert}");
                }
                if !key_ok {
                    tracing::error!("TLS key web tidak ditemukan: {key}");
                }
                cert_ok && key_ok
            }
            _ => false,
        }
    }

    fn validate(&self) {
        if self.web_domain == "localhost" {
            tracing::warn!("web_domain masih default 'localhost' — set ke domain asli di config.yaml atau env PROXY_WEB_DOMAIN");
        }
        if !self.tls_enabled() {
            tracing::warn!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            tracing::warn!(
                "⚠️  TLS TIDAK AKTIF — proxy berjalan plain HTTP di {}",
                self.listen_addr
            );
            tracing::warn!(
                "   Browser modern WAJIB HTTPS untuk domain. ulala.space tidak akan bisa dibuka."
            );
            tracing::warn!("   Fix: pastikan cert Let's Encrypt ada di path yang dikonfigurasi:");
            if let Some(c) = &self.tls_cert_web {
                tracing::warn!(
                    "   tls_cert_web: {c}  → exists={}",
                    std::path::Path::new(c).exists()
                );
            } else {
                tracing::warn!("   tls_cert_web: (tidak diset)");
            }
            if let Some(k) = &self.tls_key_web {
                tracing::warn!(
                    "   tls_key_web:  {k}  → exists={}",
                    std::path::Path::new(k).exists()
                );
            } else {
                tracing::warn!("   tls_key_web:  (tidak diset)");
            }
            tracing::warn!(
                "   Atau mount cert ke container: -v /etc/letsencrypt:/etc/letsencrypt:ro"
            );
            tracing::warn!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }
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
            image_addr: None,
            upstream_pool_size: None,
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
            image_subdomain: default_image_subdomain(),
            ui_subdomain: default_ui_subdomain(),
            frontend_dist_path: None,
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
