//! Router — pure function, zero side-effect, zero allocation.
//!
//! Cloudflare-style: routing adalah fungsi deterministik yang:
//!   - Tidak log apapun
//!   - Tidak allocate String baru (pakai &str dari header langsung)
//!   - Tidak baca network / disk
//!   - Return RouteDecision yang langsung bisa dipakai semua layer
//!
//! Fix dari original:
//!   - is_static_path(): tambah extensi gambar/font umum (.png, .jpg, .webp, .woff2, dll)
//!     agar cache header "public, max-age=31536000" di-set untuk asset frontend
//!
//! Rule (first-match):
//!   1. web_domain                       → Frontend
//!   2. image_subdomain                  → RustFS3 (no strip)
//!   3. ui_subdomain                     → RustFSUI
//!   4. api_domain + /image/*            → RustFS3 (strip "/image")
//!   5. api_domain + /api/ws/*           → Backend (WebSocket)
//!   6. api_domain + /api/*              → Backend (REST)
//!   7. api_domain                       → Backend (fallback)
//!   8. *                                → Frontend (fallback)

use crate::config::Config;
use crate::upstream::Upstream;

// ─── RouteDecision ────────────────────────────────────────────────────────────

/// Hasil routing — immutable, dibuat sekali per request.
#[derive(Debug, Clone, Copy)]
pub struct RouteDecision {
    pub upstream: Upstream,
    /// Prefix yang di-strip dari path sebelum forward ke upstream.
    /// `None` = tidak ada stripping.
    pub strip_prefix: Option<&'static str>,
    /// Apakah request ini WebSocket?
    pub is_ws: bool,
    /// Apakah path ini asset static?
    pub is_static: bool,
}

// ─── Pure router ─────────────────────────────────────────────────────────────

/// Entry point router — dipanggil tepat sekali per request.
///
/// Semua parameter adalah &str (reference ke data yang sudah ada di heap),
/// tidak ada allocation baru.
#[inline]
pub fn route(host: &str, path: &str, cfg: &Config) -> RouteDecision {
    let host = bare_host(host);

    // ── 1. Frontend (ulala.space / www.ulala.space) ───────────────────────────
    if is_web_domain(host, cfg) {
        return RouteDecision {
            upstream: Upstream::Frontend,
            strip_prefix: None,
            is_ws: false,
            is_static: is_static_path(path),
        };
    }

    // ── 2. Object storage via subdomain (image.ulalaapi.store) ───────────────
    if host == cfg.image_subdomain.as_str() {
        return RouteDecision {
            upstream: Upstream::RustFS3,
            strip_prefix: None, // path langsung ke S3, tidak di-strip
            is_ws: false,
            is_static: false,
        };
    }

    // ── 3. Storage console via subdomain (ui.ulalaapi.store) ─────────────────
    if host == cfg.ui_subdomain.as_str() {
        return RouteDecision {
            upstream: Upstream::RustFSUI,
            strip_prefix: None,
            is_ws: false,
            is_static: false,
        };
    }

    // ── 4-7. API domain (ulalaapi.store) ──────────────────────────────────────
    if is_api_domain(host, cfg) {
        // 4. /image/* → S3 (backward compat, strip "/image" prefix)
        if path.starts_with("/image/") || path == "/image" {
            return RouteDecision {
                upstream: Upstream::RustFS3,
                strip_prefix: Some("/image"),
                is_ws: false,
                is_static: false,
            };
        }

        // 5. WebSocket
        if is_ws_path(path) {
            return RouteDecision {
                upstream: Upstream::Backend,
                strip_prefix: None,
                is_ws: true,
                is_static: false,
            };
        }

        // 6. REST API
        if path.starts_with("/api/") || path == "/api" {
            return RouteDecision {
                upstream: Upstream::Backend,
                strip_prefix: None,
                is_ws: false,
                is_static: false,
            };
        }

        // 7. Fallback api domain
        return RouteDecision {
            upstream: Upstream::Backend,
            strip_prefix: None,
            is_ws: false,
            is_static: false,
        };
    }

    // ── 8. Fallback global ────────────────────────────────────────────────────
    RouteDecision {
        upstream: Upstream::Frontend,
        strip_prefix: None,
        is_ws: false,
        is_static: is_static_path(path),
    }
}

// ─── Helpers (inline, zero alloc) ────────────────────────────────────────────

/// Strip port dari host header: "ulala.space:443" → "ulala.space"
#[inline]
fn bare_host(host: &str) -> &str {
    host.split(':').next().unwrap_or(host)
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

    #[test]
    fn subdomain_routes() {
        let c = cfg();
        let img = route("image.ulalaapi.store", "/bucket/photo.jpg", &c);
        assert_eq!(img.upstream, Upstream::RustFS3);
        assert!(img.strip_prefix.is_none(), "subdomain tidak boleh strip");

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
        // Router harus return hasil yang sama untuk input sama
        let c = cfg();
        for _ in 0..1000 {
            let a = route("ulalaapi.store", "/api/events", &c);
            let b = route("ulalaapi.store", "/api/events", &c);
            assert_eq!(a.upstream, b.upstream);
            assert_eq!(a.is_ws, b.is_ws);
        }
    }
}
