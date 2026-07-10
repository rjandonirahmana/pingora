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
//! Fix (brotli/gzip):
//!   is_static_path sekarang juga mengenali .br dan .gz extension agar
//!   request ke pre-compressed variant mendapat cache policy dan MIME yang benar.
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

        // ⬇️⬇️⬇️ TAMBAH INI ⬇️⬇️⬇️
        if path.starts_with("/image/") || path == "/image" {
            return RouteDecision {
                upstream: Upstream::RustFS3,
                strip_prefix: Some("/image"), // strip "/image" agar path ke S3 bersih
                is_ws: false,
                is_static: false,
            };
        }
        // ⬆️⬆️⬆️ TAMBAH INI ⬆️⬆️⬆️

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

/// True bila `host` adalah salah satu domain yang KITA layani (web/api +
/// subdomain storage). Dipakai untuk menolak scanner internet yang mengirim
/// Host asing (IP mentah, domain phishing) — tanpa ini rule fallback global
/// (#10) meneruskannya ke Frontend :3100, membuang koneksi backend & memicu
/// circuit breaker. Header `Host` yang kosong/hilang juga bukan host kita.
#[inline]
pub fn is_known_host(host: &str, cfg: &Config) -> bool {
    let host = bare_host(host);
    !host.is_empty()
        && (is_web_domain(host, cfg)
            || is_api_domain(host, cfg)
            || host == cfg.image_subdomain.as_str()
            || host == cfg.ui_subdomain.as_str())
}

#[inline]
fn is_ws_path(path: &str) -> bool {
    // Chat lama memakai prefix `/api/ws/`. Signaling live (WebRTC) & meet (zoom)
    // memakai prefix `/ws/` langsung di app:
    //   - live   : `/ws/live/publish`, `/ws/live/subscribe`, `/ws/lives`
    //   - meet   : `/ws/meet/{room_id}`  (konferensi P2P mesh + waiting room)
    // Semua harus di-upgrade WebSocket dan diteruskan ke Backend — tanpa baris
    // `/ws/` ini, signaling jatuh ke Frontend (static-web-server) dan koneksi WS
    // tidak pernah terbentuk.
    //
    // Catatan media (penting — TIDAK ada port tambahan di pingora):
    //   - LIVE memakai SFU: media mengalir lewat UDP (SFU :4000) langsung ke
    //     server. Buka UDP port SFU di firewall + set SFU_PUBLIC_IP.
    //   - MEET memakai P2P mesh: media mengalir LANGSUNG antar-browser (lewat
    //     STUN/TURN), tidak melewati server sama sekali. Pingora hanya mem-proxy
    //     signaling (`/ws/meet`) + REST (`/api/meet`, `/api/rtc/ice`). TURN, bila
    //     dipakai, adalah server coturn terpisah (UDP 3478) — bukan urusan pingora
    //     (HTTP/TCP) yang memang tak bisa mem-proxy UDP.
    path.starts_with("/api/ws/")
        || path == "/api/ws"
        || path.starts_with("/ws/")
        || path == "/ws"
}

/// Deteksi apakah path adalah file static (punya ekstensi yang dikenal).
///
/// FIX (brotli/gzip): Tambahkan .br dan .gz variant agar request ke
/// pre-compressed file mendapat:
///   - Cache policy yang benar (immutable bukan no-store)
///   - Content-type di-set dari nama file asli (lihat transform.rs)
///   - Tidak di-404 oleh is_static guard di mod.rs
///
/// Kenapa penting:
///   static-web-server (MODE A) transparently serve .br/.gz via content negotiation
///   → URL tetap /app.wasm tapi response bisa brotli-encoded.
///   Tapi kalau ada client yang request /app.wasm.br langsung (rare, tapi valid),
///   Pingora harus treat itu sebagai static file, bukan SPA route.
#[inline]
fn is_static_path(path: &str) -> bool {
    path.starts_with("/static/")
        // WASM dan pre-compressed variants
        || path.ends_with(".wasm")
        || path.ends_with(".wasm.br")
        || path.ends_with(".wasm.gz")
        // JavaScript dan pre-compressed variants
        || path.ends_with(".js")
        || path.ends_with(".js.br")
        || path.ends_with(".js.gz")
        || path.ends_with(".mjs")
        || path.ends_with(".mjs.br")
        || path.ends_with(".mjs.gz")
        // CSS dan pre-compressed variants
        || path.ends_with(".css")
        || path.ends_with(".css.br")
        || path.ends_with(".css.gz")
        // Icons dan images
        || path.ends_with(".ico")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".webp")
        || path.ends_with(".avif")
        || path.ends_with(".svg")
        // Fonts
        || path.ends_with(".woff")
        || path.ends_with(".woff2")
        || path.ends_with(".ttf")
        // Source maps
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
    fn web_domain_live_ws_routes_to_backend() {
        let c = cfg();
        // Signaling live (prefix /ws/) harus ke Backend sebagai WebSocket.
        for p in ["/ws/lives", "/ws/live/publish/room1", "/ws/live/subscribe/room1"] {
            let d = route("ulala.space", p, &c);
            assert_eq!(d.upstream, Upstream::Backend, "{p} harus ke Backend");
            assert!(d.is_ws, "{p} harus is_ws=true");
            assert!(!d.is_static);
        }
    }

    #[test]
    fn api_domain_live_ws_routes_to_backend() {
        let c = cfg();
        let d = route("ulalaapi.store", "/ws/live/subscribe/room1", &c);
        assert_eq!(d.upstream, Upstream::Backend);
        assert!(d.is_ws);
    }

    #[test]
    fn meet_ws_routes_to_backend() {
        let c = cfg();
        // Signaling meet (zoom P2P) — prefix /ws/ → Backend WebSocket, kedua domain.
        for host in ["ulala.space", "ulalaapi.store"] {
            let d = route(host, "/ws/meet/meet_abc123", &c);
            assert_eq!(d.upstream, Upstream::Backend, "{host} /ws/meet harus Backend");
            assert!(d.is_ws, "{host} /ws/meet harus is_ws=true");
            assert!(!d.is_static);
        }
    }

    #[test]
    fn meet_rest_routes_to_backend() {
        let c = cfg();
        // REST meet + endpoint ICE server — prefix /api/ → Backend (bukan WS).
        for host in ["ulala.space", "ulalaapi.store"] {
            for p in ["/api/meet/rooms", "/api/meet/rooms/meet_abc123", "/api/rtc/ice"] {
                let d = route(host, p, &c);
                assert_eq!(d.upstream, Upstream::Backend, "{host} {p} harus Backend");
                assert!(!d.is_ws, "{host} {p} bukan WS");
                assert!(!d.is_static);
            }
        }
    }

    #[test]
    fn web_domain_spa_routes_to_frontend() {
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

    // ── Brotli/Gzip is_static tests ───────────────────────────────────────────

    #[test]
    fn wasm_br_is_static() {
        let c = cfg();
        // .wasm.br harus is_static = true
        assert!(route("ulala.space", "/app_bg.wasm.br", &c).is_static);
        assert!(route("ulala.space", "/app_bg.wasm.gz", &c).is_static);
        assert!(route("ulala.space", "/app.js.br", &c).is_static);
        assert!(route("ulala.space", "/style.css.gz", &c).is_static);
    }

    #[test]
    fn wasm_br_routes_to_frontend() {
        let c = cfg();
        assert_eq!(
            route("ulala.space", "/app_bg.wasm.br", &c).upstream,
            Upstream::Frontend
        );
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

    #[test]
    fn known_host_allowlist() {
        let c = cfg();
        // Host sah — semua domain yang kita layani.
        assert!(is_known_host("ulala.space", &c));
        assert!(is_known_host("www.ulala.space", &c));
        assert!(is_known_host("ulala.space:443", &c));
        assert!(is_known_host("ulalaapi.store", &c));
        assert!(is_known_host("image.ulalaapi.store", &c));
        assert!(is_known_host("ui.ulalaapi.store", &c));
        // Host scanner — harus ditolak.
        assert!(!is_known_host("77.237.242.1", &c));
        assert!(!is_known_host("web2.serviciodepaginasweb.cl", &c));
        assert!(!is_known_host("", &c));
        assert!(!is_known_host("evil.com", &c));
        // Bukan subdomain sah kita.
        assert!(!is_known_host("api.ulala.space.evil.com", &c));
    }

    #[test]
    fn web_domain_image_strip() {
        let c = cfg();
        let d = route("ulala.space", "/image/bucket/photo.jpg", &c);
        assert_eq!(
            d.upstream,
            Upstream::RustFS3,
            "/image/* di web_domain harus ke RustFS3"
        );
        assert_eq!(d.strip_prefix, Some("/image"));
        assert!(!d.is_static);
    }
}
