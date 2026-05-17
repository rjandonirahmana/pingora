//! Router — pure function, zero side-effect, zero allocation.
//!
//! Fix:
//!   [BUG] ulala.space/api/* sebelumnya selalu routing ke Frontend (static-web-server).
//!   FE yang di-build dengan KINETIC_API_BASE_URL=/api (relative, default) akan
//!   mengirim semua XHR ke ulala.space/api/... → static-web-server → 404.
//!   Fix: tambahkan /api/* dan /api/ws/* handling sebelum fallback ke Frontend.
//!   Sekarang FE cukup di-build dengan default KINETIC_API_BASE_URL=/api — tidak
//!   perlu hardcode IP atau domain API terpisah.
//!
//! Rule (first-match):
//!   1. web_domain + /api/ws/*               → Backend (WebSocket, same-domain WS)
//!   2. web_domain + /api/*                  → Backend (REST, relative URL support)
//!   3. web_domain                            → Frontend
//!   4. image_subdomain                      → RustFS3 (no strip)
//!   5. ui_subdomain                         → RustFSUI
//!   6. api_domain + /image/*               → RustFS3 (strip "/image")
//!   7. api_domain + /api/ws/*              → Backend (WebSocket)
//!   8. api_domain + /api/*                 → Backend (REST)
//!   9. api_domain                           → Backend (fallback)
//!  10. *                                    → Frontend (fallback)

use crate::config::Config;
use crate::upstream::Upstream;

// ─── RouteDecision ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct RouteDecision {
    pub upstream: Upstream,
    pub strip_prefix: Option<&'static str>,
    pub is_ws: bool,
    pub is_static: bool,
}

// ─── Pure router ──────────────────────────────────────────────────────────────

#[inline]
pub fn route(host: &str, path: &str, cfg: &Config) -> RouteDecision {
    let host = bare_host(host);

    // ── 1-3. Web domain (ulala.space) ─────────────────────────────────────────
    if is_web_domain(host, cfg) {
        // BUG FIX: /api/ws/* → Backend WebSocket.
        // Tanpa ini, WS dari FE (relative wss://) tidak pernah sampai ke Axum.
        if is_ws_path(path) {
            return RouteDecision {
                upstream: Upstream::Backend,
                strip_prefix: None,
                is_ws: true,
                is_static: false,
            };
        }

        // BUG FIX: /api/* → Backend REST.
        // FE default build: KINETIC_API_BASE_URL=/api → semua XHR ke /api/...
        // Sebelumnya: semua path ulala.space → Frontend → static-web-server 404.
        // Sekarang: /api/* di web domain di-proxy ke Axum sama seperti api_domain.
        if path.starts_with("/api/") || path == "/api" {
            return RouteDecision {
                upstream: Upstream::Backend,
                strip_prefix: None,
                is_ws: false,
                is_static: false,
            };
        }

        // Semua path lain → SPA / static asset
        return RouteDecision {
            upstream: Upstream::Frontend,
            strip_prefix: None,
            is_ws: false,
            is_static: is_static_path(path),
        };
    }

    // ── 4. Object storage via subdomain (image.ulalaapi.store) ───────────────
    if host == cfg.image_subdomain.as_str() {
        return RouteDecision {
            upstream: Upstream::RustFS3,
            strip_prefix: None,
            is_ws: false,
            is_static: false,
        };
    }

    // ── 5. Storage console via subdomain (ui.ulalaapi.store) ─────────────────
    if host == cfg.ui_subdomain.as_str() {
        return RouteDecision {
            upstream: Upstream::RustFSUI,
            strip_prefix: None,
            is_ws: false,
            is_static: false,
        };
    }

    // ── 6-9. API domain (ulalaapi.store) ──────────────────────────────────────
    if is_api_domain(host, cfg) {
        // 6. /image/* → S3 (strip "/image")
        if path.starts_with("/image/") || path == "/image" {
            return RouteDecision {
                upstream: Upstream::RustFS3,
                strip_prefix: Some("/image"),
                is_ws: false,
                is_static: false,
            };
        }

        // 7. WebSocket
        if is_ws_path(path) {
            return RouteDecision {
                upstream: Upstream::Backend,
                strip_prefix: None,
                is_ws: true,
                is_static: false,
            };
        }

        // 8. REST API
        if path.starts_with("/api/") || path == "/api" {
            return RouteDecision {
                upstream: Upstream::Backend,
                strip_prefix: None,
                is_ws: false,
                is_static: false,
            };
        }

        // 9. Fallback api domain
        return RouteDecision {
            upstream: Upstream::Backend,
            strip_prefix: None,
            is_ws: false,
            is_static: false,
        };
    }

    // ── 10. Fallback global ───────────────────────────────────────────────────
    RouteDecision {
        upstream: Upstream::Frontend,
        strip_prefix: None,
        is_ws: false,
        is_static: is_static_path(path),
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

#[inline]
fn bare_host(host: &str) -> &str {
    crate::proxy::transform::strip_port(host)
}

#[inline]
fn is_web_domain(host: &str, cfg: &Config) -> bool {
    host == cfg.web_domain.as_str()
        || (host.len() == cfg.web_domain.len() + 4
            && host.starts_with("www.")
            && host.ends_with(cfg.web_domain.as_str()))
}

#[inline]
fn is_api_domain(host: &str, cfg: &Config) -> bool {
    host == cfg.api_domain.as_str()
        || (host.len() == cfg.api_domain.len() + 4
            && host.starts_with("www.")
            && host.ends_with(cfg.api_domain.as_str()))
}

#[inline]
fn is_ws_path(path: &str) -> bool {
    path.starts_with("/api/ws/") || path == "/api/ws"
}

#[inline]
fn is_static_path(path: &str) -> bool {
    path.starts_with("/static/")
        || path.ends_with(".wasm")
        || path.ends_with(".js")
        || path.ends_with(".mjs")
        || path.ends_with(".css")
        || path.ends_with(".ico")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".webp")
        || path.ends_with(".svg")
        || path.ends_with(".woff")
        || path.ends_with(".woff2")
        || path.ends_with(".ttf")
        || path.ends_with(".map")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            web_domain: "ulala.space".into(),
            api_domain: "ulalaapi.store".into(),
            image_subdomain: "image.ulalaapi.store".into(),
            ui_subdomain: "ui.ulalaapi.store".into(),
            ..Config::default()
        }
    }

    #[test]
    fn frontend_routes() {
        let c = cfg();
        assert_eq!(route("ulala.space", "/", &c).upstream, Upstream::Frontend);
        assert_eq!(
            route("www.ulala.space", "/events/slug", &c).upstream,
            Upstream::Frontend
        );
        assert_eq!(
            route("ulala.space:443", "/static/app.js", &c).upstream,
            Upstream::Frontend
        );
        assert!(route("ulala.space", "/static/app.js", &c).is_static);
    }

    // ── BUG FIX tests ─────────────────────────────────────────────────────────

    #[test]
    fn web_domain_api_routes_to_backend() {
        // FE di-build dengan KINETIC_API_BASE_URL=/api (relative, default).
        // /api/* pada ulala.space HARUS ke Backend, bukan Frontend.
        let c = cfg();
        let d = route("ulala.space", "/api/orders", &c);
        assert_eq!(d.upstream, Upstream::Backend, "/api/* harus ke Backend");
        assert!(!d.is_ws);
        assert!(!d.is_static);
    }

    #[test]
    fn web_domain_ws_routes_to_backend() {
        let c = cfg();
        let d = route("ulala.space", "/api/ws/chat", &c);
        assert_eq!(d.upstream, Upstream::Backend);
        assert!(d.is_ws, "/api/ws/* harus is_ws=true");
    }

    #[test]
    fn web_domain_spa_routes_to_frontend() {
        // Non-API paths tetap ke Frontend
        let c = cfg();
        assert_eq!(
            route("ulala.space", "/explore", &c).upstream,
            Upstream::Frontend
        );
        assert_eq!(
            route("ulala.space", "/orders/123", &c).upstream,
            Upstream::Frontend
        );
    }

    #[test]
    fn subdomain_routes() {
        let c = cfg();
        let img = route("image.ulalaapi.store", "/bucket/photo.jpg", &c);
        assert_eq!(img.upstream, Upstream::RustFS3);
        assert!(img.strip_prefix.is_none());

        let ui = route("ui.ulalaapi.store", "/dashboard", &c);
        assert_eq!(ui.upstream, Upstream::RustFSUI);
    }

    #[test]
    fn api_domain_image_strip() {
        let c = cfg();
        let d = route("ulalaapi.store", "/image/photo.jpg", &c);
        assert_eq!(d.upstream, Upstream::RustFS3);
        assert_eq!(d.strip_prefix, Some("/image"));
    }

    #[test]
    fn api_domain_ws() {
        let c = cfg();
        let d = route("ulalaapi.store", "/api/ws/chat", &c);
        assert_eq!(d.upstream, Upstream::Backend);
        assert!(d.is_ws);
    }

    #[test]
    fn api_domain_rest() {
        let c = cfg();
        let d = route("ulalaapi.store", "/api/events", &c);
        assert_eq!(d.upstream, Upstream::Backend);
        assert!(!d.is_ws);
    }

    #[test]
    fn deterministic() {
        let c = cfg();
        for _ in 0..1000 {
            let a = route("ulalaapi.store", "/api/events", &c);
            let b = route("ulalaapi.store", "/api/events", &c);
            assert_eq!(a.upstream, b.upstream);
            assert_eq!(a.is_ws, b.is_ws);
        }
    }
}
