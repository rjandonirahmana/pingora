//! Upstream selector — memilih backend, frontend, image, atau rustfs berdasarkan
//! kombinasi Host header + path:
//!
//!  ulala.space              /*        → Frontend (static-web-server :3100)
//!  ulalaapi.store           /api/*    → Backend (:8080, REST & WebSocket)
//!  ulalaapi.store           /image/*  → RustFS3 (:9000, strip "/image" prefix)
//!  image.ulalaapi.store     /*        → RustFS3 (:9000, no prefix strip)
//!  ui.ulalaapi.store        /*        → RustFSUI (:9001, console dashboard)
//!  ulalaapi.store           /*        → Backend (:8080, fallback)

use crate::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upstream {
    /// Axum REST + WebSocket (:8080)
    Backend,
    /// Leptos SPA / static-web-server (:3100)
    Frontend,
    /// RustFS S3 Storage (:9000)
    ///   - via subdomain image.ulalaapi.store/* (no strip)
    ///   - via path ulalaapi.store/image/* (strip "/image" prefix, handled di router.rs)
    ///   - via path ulala.space/image/* (strip "/image" prefix, handled di router.rs)
    RustFS3,
    /// RustFS Web Console (:9001) — via subdomain ui.ulalaapi.store
    RustFSUI,
    /// PPM AFM — app Leptos SSR terpisah (satu binary: SSR + /api-fn + /pkg +
    /// /api/rfid + SSE) via subdomain ppm.ulala.space → 127.0.0.1:3200.
    Ppm,
    /// Panel admin WhatsApp (:3000) — host sendiri, semua path.
    WaAdmin,
}

impl Upstream {
    /// Tentukan upstream dari Host request dan path.
    ///
    /// Aturan (first-match):
    ///  1. Host = web_domain + /api/ws/*   → Backend (WebSocket)
    ///  2. Host = web_domain + /api/*       → Backend (REST)
    ///  3. Host = web_domain + /image/*   → RustFS3 (path-based, strip di proxy.rs)
    ///  4. Host = web_domain               → Frontend (semua path lain)
    ///  5. Host = image_subdomain          → RustFS3 (S3 storage via subdomain)
    ///  6. Host = ui_subdomain             → RustFSUI (Console via subdomain)
    ///  7. Host = api_domain + /image/*    → RustFS3 (backward compat, path-based)
    ///  8. Host = api_domain + /api/*      → Backend (REST & WebSocket)
    ///  9. Host = api_domain               → Backend (fallback)
    pub fn for_request(host: &str, path: &str, cfg: &Config) -> Self {
        let host_bare = host.split(':').next().unwrap_or(host);

        // 1-4. Web domain (ulala.space)
        let is_web = is_domain_match(host_bare, &cfg.web_domain);
        if is_web {
            // 1. WebSocket
            if Self::is_ws_path(path) {
                return Upstream::Backend;
            }

            // 2. REST API
            if path.starts_with("/api/") || path == "/api" {
                return Upstream::Backend;
            }

            // 3. Image / S3 path-based — same-domain image serving
            if path.starts_with("/image/") || path == "/image" {
                return Upstream::RustFS3;
            }

            // 4. Fallback: Frontend (SPA / static)
            return Upstream::Frontend;
        }

        // 5. RustFS S3 via subdomain (image.ulalaapi.store)
        if host_bare == cfg.image_subdomain {
            return Upstream::RustFS3;
        }

        // 6. RustFS Console via subdomain (ui.ulalaapi.store)
        if host_bare == cfg.ui_subdomain {
            return Upstream::RustFSUI;
        }

        // 7-9. API domain (ulalaapi.store)
        let is_api = is_domain_match(host_bare, &cfg.api_domain);

        if is_api {
            // 7. Backward compat: /image/* → RustFS3 (strip akan dilakukan di proxy.rs)
            if path.starts_with("/image/") || path == "/image" {
                return Upstream::RustFS3;
            }

            // 8. REST API & WebSocket
            if path.starts_with("/api/") || path == "/api" {
                return Upstream::Backend;
            }

            // 9. Fallback api domain → Backend
            return Upstream::Backend;
        }

        // Fallback umum: frontend
        Upstream::Frontend
    }

    /// Apakah path ini adalah WebSocket endpoint?
    pub fn is_ws_path(path: &str) -> bool {
        path.starts_with("/api/ws/") || path == "/api/ws"
    }

    /// Kembalikan addr host:port untuk upstream ini.
    pub fn addr<'a>(&self, cfg: &'a Config) -> &'a str {
        match self {
            Upstream::Backend => &cfg.backend_addr,
            Upstream::Frontend => &cfg.frontend_addr,
            Upstream::RustFS3 => &cfg.rustfs_s3_address,
            Upstream::RustFSUI => &cfg.rustfs_ui_address,
            Upstream::Ppm => &cfg.ppm_addr,
            Upstream::WaAdmin => &cfg.wa_admin_addr,
        }
    }
}

// Zero-alloc domain match — sama dengan router.rs, copy di sini untuk upstream.rs
// yang tidak punya akses ke router module.
#[inline]
fn is_domain_match(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() == domain.len() + 4 && host.starts_with("www.") && host.ends_with(domain))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> Config {
        Config {
            web_domain: "ulala.space".into(),
            api_domain: "ulalaapi.store".into(),
            image_subdomain: "image.ulalaapi.store".into(),
            ui_subdomain: "ui.ulalaapi.store".into(),
            backend_addr: "127.0.0.1:8080".into(),
            frontend_addr: "127.0.0.1:3100".into(),
            rustfs_s3_address: "127.0.0.1:9000".into(),
            rustfs_ui_address: "127.0.0.1:9001".into(),
            ..Config::default()
        }
    }

    #[test]
    fn web_domain_frontend_routes() {
        let cfg = test_cfg();
        assert_eq!(
            Upstream::for_request("ulala.space", "/", &cfg),
            Upstream::Frontend
        );
        assert_eq!(
            Upstream::for_request("ulala.space", "/events/slug", &cfg),
            Upstream::Frontend
        );
        assert_eq!(
            Upstream::for_request("www.ulala.space", "/explore", &cfg),
            Upstream::Frontend
        );
    }

    // ── web_domain exception tests (konsisten dengan router.rs) ───────────────

    #[test]
    fn web_domain_api_routes_to_backend() {
        let cfg = test_cfg();
        assert_eq!(
            Upstream::for_request("ulala.space", "/api/orders", &cfg),
            Upstream::Backend,
            "/api/* di web_domain harus ke Backend"
        );
        assert_eq!(
            Upstream::for_request("ulala.space", "/api/auth/login", &cfg),
            Upstream::Backend
        );
    }

    #[test]
    fn web_domain_ws_routes_to_backend() {
        let cfg = test_cfg();
        assert_eq!(
            Upstream::for_request("ulala.space", "/api/ws/chat", &cfg),
            Upstream::Backend,
            "/api/ws/* di web_domain harus ke Backend"
        );
        assert_eq!(
            Upstream::for_request("www.ulala.space", "/api/ws/", &cfg),
            Upstream::Backend
        );
    }

    #[test]
    fn web_domain_image_routes_to_rustfs3() {
        let cfg = test_cfg();
        assert_eq!(
            Upstream::for_request("ulala.space", "/image/photo.jpg", &cfg),
            Upstream::RustFS3,
            "/image/* di web_domain harus ke RustFS3"
        );
        assert_eq!(
            Upstream::for_request("ulala.space", "/image/bucket/file.png", &cfg),
            Upstream::RustFS3
        );
        assert_eq!(
            Upstream::for_request("www.ulala.space", "/image/", &cfg),
            Upstream::RustFS3
        );
    }

    #[test]
    fn rustfs_subdomain_routing() {
        let cfg = test_cfg();
        // image subdomain → RustFS3 (semua path, TANPA strip)
        assert_eq!(
            Upstream::for_request("image.ulalaapi.store", "/", &cfg),
            Upstream::RustFS3
        );
        assert_eq!(
            Upstream::for_request("image.ulalaapi.store", "/mybucket/photo.jpg", &cfg),
            Upstream::RustFS3
        );
        // ui subdomain → RustFSUI
        assert_eq!(
            Upstream::for_request("ui.ulalaapi.store", "/", &cfg),
            Upstream::RustFSUI
        );
        assert_eq!(
            Upstream::for_request("ui.ulalaapi.store", "/dashboard", &cfg),
            Upstream::RustFSUI
        );
    }

    #[test]
    fn api_domain_path_based_image_backward_compat() {
        let cfg = test_cfg();
        // ulalaapi.store/image/* → RustFS3 (backward compat, strip akan dilakukan di proxy.rs)
        assert_eq!(
            Upstream::for_request("ulalaapi.store", "/image/photo.jpg", &cfg),
            Upstream::RustFS3
        );
        assert_eq!(
            Upstream::for_request("ulalaapi.store", "/image/bucket/file.png", &cfg),
            Upstream::RustFS3
        );
    }

    #[test]
    fn api_domain_backend() {
        let cfg = test_cfg();
        assert_eq!(
            Upstream::for_request("ulalaapi.store", "/api/events", &cfg),
            Upstream::Backend
        );
        assert_eq!(
            Upstream::for_request("ulalaapi.store", "/api/auth/login", &cfg),
            Upstream::Backend
        );
        assert_eq!(
            Upstream::for_request("ulalaapi.store", "/api/ws/", &cfg),
            Upstream::Backend
        );
        assert_eq!(
            Upstream::for_request("ulalaapi.store", "/api/ws/chat", &cfg),
            Upstream::Backend
        );
        // fallback
        assert_eq!(
            Upstream::for_request("ulalaapi.store", "/unknown", &cfg),
            Upstream::Backend
        );
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
    fn host_with_port() {
        let cfg = test_cfg();
        assert_eq!(
            Upstream::for_request("ulala.space:443", "/", &cfg),
            Upstream::Frontend
        );
        assert_eq!(
            Upstream::for_request("ulala.space:443", "/api/me", &cfg),
            Upstream::Backend
        );
        assert_eq!(
            Upstream::for_request("ulala.space:443", "/image/photo.jpg", &cfg),
            Upstream::RustFS3
        );
        assert_eq!(
            Upstream::for_request("image.ulalaapi.store:443", "/mybucket/file.jpg", &cfg),
            Upstream::RustFS3
        );
        assert_eq!(
            Upstream::for_request("ui.ulalaapi.store:443", "/", &cfg),
            Upstream::RustFSUI
        );
        assert_eq!(
            Upstream::for_request("ulalaapi.store:443", "/api/me", &cfg),
            Upstream::Backend
        );
    }

    #[test]
    fn strip_image_prefix_only_for_path_based() {
        // Validasi bahwa routing subdomain tidak akan ter-strip.
        // strip_image_prefix logic ada di proxy.rs, tapi kita validasi bahwa
        // subdomain image. menghasilkan Upstream::RustFS3 dengan path yang benar.
        let cfg = test_cfg();
        let host = "image.ulalaapi.store";
        let path = "/mybucket/photo.jpg";
        let upstream = Upstream::for_request(host, path, &cfg);
        assert_eq!(upstream, Upstream::RustFS3);
        // path TIDAK mengandung "/image/" jadi strip_image_prefix akan false di proxy.rs
        assert!(!path.starts_with("/image/"));
    }
}
