//! Upstream selector — memilih backend, frontend, atau image berdasarkan
//! kombinasi Host header + path, sesuai konfigurasi nginx dua-domain:
//!
//!  ulala.space        /* → Frontend (static-web-server :3100)
//!  ulalaapi.store     /api/ws/* → Backend  (:8080, WebSocket)
//!  ulalaapi.store     /api/*    → Backend  (:8080, REST)
//!  ulalaapi.store     /image/*  → Image    (:3902, Garage S3, strip prefix)
//!  ulalaapi.store     /*        → Backend  (:8080, fallback)

use crate::config::Config;

/// Kemana request harus diteruskan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upstream {
    /// Axum REST + WebSocket (:8080)
    Backend,
    /// Leptos SPA / static-web-server (:3100)
    Frontend,
    /// Garage S3 web — path /image/* di-strip menjadi /* (:3902)
    Image,
}

impl Upstream {
    /// Tentukan upstream dari Host request dan path.
    ///
    /// Aturan (first-match):
    ///  - Host = web_domain  → Frontend (semua path)
    ///  - Host = api_domain  → Image    jika path /image/*
    ///  - Host = api_domain  → Backend  sisanya (/api/*, /api/ws/*, fallback)
    pub fn for_request(host: &str, path: &str, cfg: &Config) -> Self {
        let host_bare = host.split(':').next().unwrap_or(host); // buang port jika ada

        let is_web = host_bare == cfg.web_domain
            || host_bare == format!("www.{}", cfg.web_domain);
        let is_api = host_bare == cfg.api_domain
            || host_bare == format!("www.{}", cfg.api_domain);

        if is_web {
            return Upstream::Frontend;
        }

        if is_api {
            if path.starts_with("/image/") || path == "/image" {
                return Upstream::Image;
            }
            return Upstream::Backend;
        }

        // Fallback: jika tidak dikenal, teruskan ke frontend
        Upstream::Frontend
    }

    /// Apakah path ini adalah WebSocket endpoint?
    /// Gunakan selain cek header Upgrade, untuk set timeout yang tepat.
    pub fn is_ws_path(path: &str) -> bool {
        path.starts_with("/api/ws/") || path == "/api/ws"
    }

    /// Kembalikan addr host:port untuk upstream ini.
    pub fn addr<'a>(&self, cfg: &'a Config) -> &'a str {
        match self {
            Upstream::Backend  => &cfg.backend_addr,
            Upstream::Frontend => &cfg.frontend_addr,
            Upstream::Image    => &cfg.image_addr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> Config {
        Config {
            web_domain: "ulala.space".into(),
            api_domain: "ulalaapi.store".into(),
            ..Config::default()
        }
    }

    #[test]
    fn web_domain_always_frontend() {
        let cfg = test_cfg();
        assert_eq!(Upstream::for_request("ulala.space", "/", &cfg),              Upstream::Frontend);
        assert_eq!(Upstream::for_request("ulala.space", "/events/slug", &cfg),   Upstream::Frontend);
        assert_eq!(Upstream::for_request("www.ulala.space", "/api/", &cfg),      Upstream::Frontend);
    }

    #[test]
    fn api_domain_backend() {
        let cfg = test_cfg();
        assert_eq!(Upstream::for_request("ulalaapi.store", "/api/events", &cfg),    Upstream::Backend);
        assert_eq!(Upstream::for_request("ulalaapi.store", "/api/auth/login", &cfg),Upstream::Backend);
        assert_eq!(Upstream::for_request("ulalaapi.store", "/api/ws/", &cfg),       Upstream::Backend);
        assert_eq!(Upstream::for_request("ulalaapi.store", "/api/health", &cfg),    Upstream::Backend);
        // fallback
        assert_eq!(Upstream::for_request("ulalaapi.store", "/unknown", &cfg),       Upstream::Backend);
    }

    #[test]
    fn api_domain_image() {
        let cfg = test_cfg();
        assert_eq!(Upstream::for_request("ulalaapi.store", "/image/", &cfg),         Upstream::Image);
        assert_eq!(Upstream::for_request("ulalaapi.store", "/image/banner.jpg", &cfg),Upstream::Image);
        assert_eq!(Upstream::for_request("ulalaapi.store", "/image", &cfg),           Upstream::Image);
    }

    #[test]
    fn ws_path_detection() {
        assert!(Upstream::is_ws_path("/api/ws/"));
        assert!(Upstream::is_ws_path("/api/ws/room/123"));
        assert!(Upstream::is_ws_path("/api/ws"));
        assert!(!Upstream::is_ws_path("/api/events"));
        assert!(!Upstream::is_ws_path("/ws/old"));
    }

    #[test]
    fn with_port_in_host() {
        let cfg = test_cfg();
        // Host header kadang sertakan port, e.g. "ulala.space:443"
        assert_eq!(Upstream::for_request("ulala.space:443", "/", &cfg), Upstream::Frontend);
        assert_eq!(Upstream::for_request("ulalaapi.store:443", "/api/me", &cfg), Upstream::Backend);
    }
}
