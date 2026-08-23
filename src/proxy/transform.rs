//! Transform layer — modifikasi request & response header.
//!
//! Changelog:
//!   [prev] resolve_origin() → pub, apply_cache() u64 cast, HSTS TLS-only
//!   [prev] is_static path-based, cache SPA no-store, COOP/COEP, x-forwarded-proto dynamic
//!   [review] CORS wildcard+credentials guard (SPEC BUG — browser reject wildcard+creds)
//!   [review] IPv6 host parsing (split(':') pecah "[::1]:8080" jadi "[" bukan "[::1]")
//!   [review] Hapus x-xss-protection (deprecated, pernah buka vuln di IE/Edge)
//!   [review] JS MIME: text/javascript (RFC 9239, bukan application/javascript)
//!   [review] content-disposition skip untuk SVG/HTML (XSS vector kalau inline)
//!   [review] apply_cache buffer: ganti manual slice copy dengan format string yg aman
//!   [review] Tambah Content-Security-Policy baseline untuk frontend
//!   [fix] Tambah MIME type untuk .br dan .gz pre-compressed files
//!   [fix] mime_from_path untuk .br/.gz: MIME dari inner extension (e.g. .wasm.br → application/wasm)
//!         sehingga Content-Type benar kalau ada yang request file compressed langsung

use pingora_http::{RequestHeader, ResponseHeader};

use crate::config::Config;
use crate::proxy::context::{RequestCtx, RouteKind};

// ─── MIME map ─────────────────────────────────────────────────────────────────

/// Resolve MIME type dari path file.
///
/// FIX (brotli/gzip): untuk path yang berakhir .br atau .gz,
/// strip suffix tersebut terlebih dahulu sehingga MIME type diambil
/// dari ekstensi file aslinya.
///
/// Contoh:
///   /app_bg.wasm.br  → strip ".br"  → /app_bg.wasm → "application/wasm"
///   /style.css.gz    → strip ".gz"  → /style.css   → "text/css"
///   /app_bg.wasm     → langsung     →               → "application/wasm"
#[inline]
pub fn mime_from_path(path: &str) -> Option<&'static str> {
    // Strip .br / .gz suffix dulu sebelum resolve MIME.
    // Ini penting agar request ke /app.wasm.br dapat Content-Type: application/wasm
    // bukan Content-Type: application/x-br yang tidak dikenal browser.
    let effective_path = if path.ends_with(".br") {
        &path[..path.len() - 3] // strip ".br"
    } else if path.ends_with(".gz") {
        &path[..path.len() - 3] // strip ".gz"
    } else {
        path
    };

    let ext = effective_path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");

    match_ext_ci(ext)
}

fn match_ext_ci(ext: &str) -> Option<&'static str> {
    match ext {
        e if e.eq_ignore_ascii_case("png") => Some("image/png"),
        e if e.eq_ignore_ascii_case("jpg") || e.eq_ignore_ascii_case("jpeg") => Some("image/jpeg"),
        e if e.eq_ignore_ascii_case("gif") => Some("image/gif"),
        e if e.eq_ignore_ascii_case("webp") => Some("image/webp"),
        e if e.eq_ignore_ascii_case("svg") => Some("image/svg+xml"),
        e if e.eq_ignore_ascii_case("avif") => Some("image/avif"),
        e if e.eq_ignore_ascii_case("ico") => Some("image/x-icon"),
        e if e.eq_ignore_ascii_case("bmp") => Some("image/bmp"),
        e if e.eq_ignore_ascii_case("tiff") || e.eq_ignore_ascii_case("tif") => Some("image/tiff"),
        e if e.eq_ignore_ascii_case("mp4") => Some("video/mp4"),
        e if e.eq_ignore_ascii_case("webm") => Some("video/webm"),
        e if e.eq_ignore_ascii_case("mov") => Some("video/quicktime"),
        e if e.eq_ignore_ascii_case("avi") => Some("video/x-msvideo"),
        e if e.eq_ignore_ascii_case("mkv") => Some("video/x-matroska"),
        e if e.eq_ignore_ascii_case("mp3") => Some("audio/mpeg"),
        e if e.eq_ignore_ascii_case("ogg") => Some("audio/ogg"),
        e if e.eq_ignore_ascii_case("wav") => Some("audio/wav"),
        e if e.eq_ignore_ascii_case("flac") => Some("audio/flac"),
        e if e.eq_ignore_ascii_case("m4a") => Some("audio/mp4"),
        e if e.eq_ignore_ascii_case("pdf") => Some("application/pdf"),
        e if e.eq_ignore_ascii_case("txt") => Some("text/plain; charset=utf-8"),
        e if e.eq_ignore_ascii_case("json") => Some("application/json"),
        e if e.eq_ignore_ascii_case("xml") => Some("application/xml"),
        e if e.eq_ignore_ascii_case("csv") => Some("text/csv"),
        e if e.eq_ignore_ascii_case("html") => Some("text/html; charset=utf-8"),
        e if e.eq_ignore_ascii_case("css") => Some("text/css"),
        // REVIEW: text/javascript per RFC 9239 (bukan application/javascript yang legacy)
        e if e.eq_ignore_ascii_case("js") || e.eq_ignore_ascii_case("mjs") => {
            Some("text/javascript")
        }
        // WASM MUST be application/wasm — browser tolak instantiasi kalau salah MIME
        e if e.eq_ignore_ascii_case("wasm") => Some("application/wasm"),
        e if e.eq_ignore_ascii_case("woff") => Some("font/woff"),
        e if e.eq_ignore_ascii_case("woff2") => Some("font/woff2"),
        e if e.eq_ignore_ascii_case("ttf") => Some("font/ttf"),
        _ => None,
    }
}

// ─── Helper: strip port dari host, handle IPv6 ───────────────────────────────

/// Strip port dari host header dengan benar untuk IPv4, hostname, dan IPv6.
///
/// REVIEW FIX: `split(':').next()` pecah IPv6 literal:
///   "[::1]:8080" → "[" bukan "[::1]"
///
/// Behavior:
///   "ulala.space:443"  → "ulala.space"
///   "ulala.space"      → "ulala.space"
///   "[::1]:8080"       → "[::1]"
///   "[::1]"            → "[::1]"
///   "192.168.1.1:3000" → "192.168.1.1"
#[inline]
pub fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        // IPv6 literal — port ada setelah ']', format: "[addr]:port" atau "[addr]"
        let bracket_end = host.find(']').map(|i| i + 1).unwrap_or(host.len());
        &host[..bracket_end]
    } else {
        // IPv4 atau hostname — ambil bagian sebelum ':'
        host.split(':').next().unwrap_or(host)
    }
}

// ─── Request transform ────────────────────────────────────────────────────────

pub fn apply_request(
    upstream_req: &mut RequestHeader,
    ctx: &RequestCtx,
    cfg: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ── 1. Strip path prefix ──────────────────────────────────────────────────
    if let Some(prefix) = ctx.strip_prefix {
        let path = upstream_req.uri.path();
        let stripped = path.strip_prefix(prefix).unwrap_or("/");
        let stripped = if stripped.is_empty() { "/" } else { stripped };

        let new_uri = match upstream_req.uri.query() {
            None => http::Uri::builder().path_and_query(stripped).build()?,
            Some(q) => {
                let pq = format!("{}?{}", stripped, q);
                http::Uri::builder().path_and_query(pq.as_str()).build()?
            }
        };
        upstream_req.set_uri(new_uri);
    }

    // ── 2. Host header ────────────────────────────────────────────────────────
    use crate::upstream::Upstream;
    // REVIEW FIX: pakai strip_port() yang handle IPv6 dengan benar
    let host_val = match ctx.upstream {
        Upstream::RustFS3 | Upstream::RustFSUI => strip_port(&ctx.host),
        _ => ctx.upstream.addr(cfg),
    };
    upstream_req.insert_header("host", host_val)?;

    // ── 3. Forwarding headers ─────────────────────────────────────────────────
    let id_buf = ctx.id_hex_buf();
    upstream_req.insert_header("x-request-id", id_buf.as_str())?;
    let proto = if cfg.tls_enabled() { "https" } else { "http" };
    upstream_req.insert_header("x-forwarded-proto", proto)?;
    upstream_req.insert_header("x-forwarded-host", ctx.host.as_str())?;

    if !ctx.client_ip_str.is_empty() {
        upstream_req.insert_header("x-real-ip", ctx.client_ip_str.as_str())?;
        upstream_req.append_header("x-forwarded-for", ctx.client_ip_str.as_str())?;
    }

    Ok(())
}

// ─── Response transform ───────────────────────────────────────────────────────

pub fn apply_response(
    upstream_resp: &mut ResponseHeader,
    ctx: &RequestCtx,
    cfg: &Config,
    origin: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    apply_cors(upstream_resp, ctx, cfg, origin)?;
    apply_cache(upstream_resp, ctx, cfg)?;

    // Override content-type hanya untuk actual static asset files (punya ekstensi).
    // SPA routes (ctx.is_static = false) biarkan upstream set content-type-nya.
    //
    // FIX (brotli): mime_from_path sekarang aware .br/.gz suffix — kalau ctx.path
    // adalah "/app.wasm.br", MIME yang di-set tetap "application/wasm" (benar),
    // bukan "application/x-br" atau unknown.
    if ctx.is_static || ctx.is_object {
        if let Some(mime) = mime_from_path(&ctx.path) {
            upstream_resp.insert_header("content-type", mime)?;
        }

        // REVIEW FIX: content-disposition: inline hanya untuk tipe binary yang aman.
        // SVG bisa contain <script> → inline di same-origin = eksekusi JS = XSS vector.
        // HTML juga bisa eksekusi script. JS/CSS sudah ada MIME enforcement.
        // Binary assets (image raster, font, audio, video, wasm) aman di-inline.
        let path_lower = ctx.path.to_ascii_lowercase();

        // Untuk .br/.gz path, check ekstensi file aslinya
        let effective_lower = if path_lower.ends_with(".br") {
            &path_lower[..path_lower.len() - 3]
        } else if path_lower.ends_with(".gz") {
            &path_lower[..path_lower.len() - 3]
        } else {
            &path_lower
        };

        let ext = effective_lower
            .rsplit('.')
            .next()
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("");

        let safe_for_inline = matches!(
            ext,
            "wasm"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "avif"
                | "ico"
                | "bmp"
                | "tiff"
                | "tif"
                | "woff"
                | "woff2"
                | "ttf"
                | "mp4"
                | "webm"
                | "mp3"
                | "wav"
                | "flac"
                | "ogg"
                | "m4a"
                | "mov"
        );
        if safe_for_inline {
            upstream_resp.insert_header("content-disposition", "inline")?;
        }
    }

    // ── Security headers ──────────────────────────────────────────────────────
    upstream_resp.insert_header("x-content-type-options", "nosniff")?;
    upstream_resp.insert_header("x-frame-options", "SAMEORIGIN")?;
    upstream_resp.insert_header("referrer-policy", "strict-origin-when-cross-origin")?;
    if cfg.tls_enabled() {
        upstream_resp.insert_header(
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        )?;
    }
    upstream_resp.insert_header(
        "permissions-policy",
        "geolocation=(), microphone=(), camera=()",
    )?;

    // Content-Security-Policy untuk frontend Leptos WASM.
    //
    // BUG FIX (COEP require-corp dihapus):
    //   COEP: require-corp mewajibkan SEMUA cross-origin resource punya header
    //   "Cross-Origin-Resource-Policy: cross-origin". Google Fonts tidak set header ini.
    //   Akibat: browser blok font CSS → font gagal load → bisa cascade ke render error.
    //   COEP hanya diperlukan kalau WASM pakai SharedArrayBuffer/Atomics (threading Rayon).
    //   Leptos ticketing app tidak perlu ini → hapus.
    //
    // BUG FIX (CSP style-src & font-src):
    //   CSP sebelumnya: style-src 'self' → blok fonts.googleapis.com.
    //   CSP sebelumnya: font-src 'self' → blok fonts.gstatic.com.
    //   Fix: tambahkan kedua domain ke directive masing-masing.
    //
    // BUG FIX (CSP script-src 'unsafe-inline' — ROOT CAUSE blank page via domain):
    //   CSP sebelumnya: script-src 'self' 'wasm-unsafe-eval' → blok inline <script>.
    //   Trunk inject <script type="module"> langsung ke index.html saat build.
    //   Tanpa 'unsafe-inline' di script-src, browser refuse eksekusi inline script tsb.
    //   Akibat: app tidak pernah init → blank page via domain, WORKS via IP:port (no CSP).
    //   Fix: tambahkan 'unsafe-inline' ke script-src.
    //
    // BUG FIX (CSP/COOP scope — hanya untuk HTML page):
    //   CSP dan COOP sebelumnya di-set ke SEMUA frontend response termasuk .wasm/.js/.css.
    //   Browser abaikan CSP pada non-HTML, tapi salah scope → boros bandwidth, membingungkan.
    //   Fix: CSP + COOP hanya di-set kalau !ctx.is_static (→ index.html / SPA route).
    //   CORP tetap di-set untuk semua assets (melindungi dari cross-origin embed).
    //
    // CSP notes:
    //   'wasm-unsafe-eval'  — WASM instantiation, CSP Level 3 (bukan broad 'unsafe-eval')
    //   'unsafe-inline'     — Trunk inject <script type="module"> DAN <style> tag di runtime.
    //                         WAJIB ada di script-src, bukan hanya style-src!
    //                         Tanpa ini: browser blok inline <script> Trunk → app tidak pernah
    //                         init → blank page via domain (CSP aktif), tapi WORKS via IP:port
    //                         (tidak ada CSP). Ini root cause utama "domain tidak bisa dibuka".
    //   connect-src         — fetch/WS ke API domain
    //
    // BUG FIX (image.ulalaapi.store ke-blok CSP — ROOT CAUSE image blank di ulala.space):
    //   CSP sebelumnya: img-src ... https://{api}  → cuma cover APEX "ulalaapi.store".
    //   Image disajikan dari SUBDOMAIN "image.ulalaapi.store". Di CSP, host-source
    //   "https://ulalaapi.store" TIDAK mencakup subdomain-nya. Akibat: browser blok
    //   semua <img> ke image.ulalaapi.store secara diam-diam → gambar blank, padahal
    //   request-nya valid (akses langsung ke URL-nya jalan normal).
    //   Fix: img-src pakai "https:" (izinkan SEMUA image HTTPS) supaya image dari
    //   RustFS subdomain DAN sumber luar (avatar OAuth, CDN eksternal, gambar event
    //   dari luar) sama-sama kebuka. img-src relatif low-risk: image tidak bisa
    //   eksekusi script. Kalau mau lebih ketat, ganti "https:" jadi daftar domain
    //   eksplisit, mis: https://*.{api} https://lh3.googleusercontent.com ...
    //   connect-src tetap dibatasi ke API domain + subdomainnya (lebih sensitif).
    if matches!(ctx.route, RouteKind::Static) {
        // CSP dan COOP hanya relevan untuk HTML page (index.html), bukan untuk
        // .wasm/.js/.css asset. Browser memang abaikan CSP pada non-HTML resource,
        // tapi lebih clean dan hemat bandwidth kalau tidak di-set ke asset files.
        //
        // is_static=false → route SPA (/, /explore, /events) → upstream serve index.html
        // is_static=true  → file asset (.wasm, .js, .css, .png, ...) → tidak perlu CSP
        if !ctx.is_static {
            // Pakai CSP yang sudah di-precompute saat startup (config.rs).
            // Fallback build inline hanya kalau csp_header kosong (mis. Config
            // dikonstruksi manual di test tanpa lewat load()).
            if cfg.csp_header.is_empty() {
                let csp = crate::config::build_csp_header(&cfg.api_domain);
                upstream_resp.insert_header("content-security-policy", csp.as_str())?;
            } else {
                upstream_resp.insert_header("content-security-policy", cfg.csp_header.as_str())?;
            }
            // COOP: same-origin hanya bermakna untuk HTML page (window isolation).
            // Tidak ada efek pada .wasm/.js response, jadi scope ke is_static=false saja.
            // COEP: DIHAPUS (lihat komentar di atas).
            upstream_resp.insert_header("cross-origin-opener-policy", "same-origin")?;
        }

        // CORP tetap untuk semua frontend assets (is_static=true maupun false):
        // melindungi resource dari di-embed oleh halaman cross-origin.
        upstream_resp.insert_header("cross-origin-resource-policy", "same-origin")?;
    }

    let id_buf = ctx.id_hex_buf();
    let mut elapsed_buf = itoa::Buffer::new();
    upstream_resp.insert_header("x-request-id", id_buf.as_str())?;
    upstream_resp.insert_header("x-served-by", "kinetic-proxy")?;
    upstream_resp.insert_header("x-elapsed-ms", elapsed_buf.format(ctx.elapsed_ms()))?;

    Ok(())
}

// ─── CORS ─────────────────────────────────────────────────────────────────────

fn apply_cors(
    resp: &mut ResponseHeader,
    ctx: &RequestCtx,
    cfg: &Config,
    origin: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::upstream::Upstream;

    let origin = match origin {
        Some(o) if !o.is_empty() => o,
        _ => return Ok(()),
    };

    let allowed = resolve_origin(origin, cfg);

    match ctx.upstream {
        Upstream::Backend => {
            if ctx.is_api {
                resp.insert_header("vary", "origin")?;
                resp.insert_header("access-control-allow-origin", allowed)?;
                if allowed != "*" {
                    resp.insert_header("access-control-allow-credentials", "true")?;
                }
                resp.insert_header(
                    "access-control-allow-methods",
                    "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                )?;
                resp.insert_header(
                    "access-control-allow-headers",
                    "authorization, content-type, x-request-id, x-app-token",
                )?;
                resp.insert_header(
                    "access-control-expose-headers",
                    "x-request-id, x-elapsed-ms",
                )?;
                resp.insert_header("access-control-max-age", "86400")?;
            }
        }
        Upstream::RustFS3 => {
            resp.insert_header("vary", "origin")?;
            resp.insert_header("access-control-allow-origin", allowed)?;
            if allowed != "*" {
                resp.insert_header("access-control-allow-credentials", "true")?;
            }
            resp.insert_header(
                "access-control-allow-methods",
                "GET, HEAD, PUT, DELETE, OPTIONS",
            )?;
            resp.insert_header(
                "access-control-allow-headers",
                "authorization, range, content-type, x-amz-date, x-amz-content-sha256",
            )?;
            resp.insert_header("access-control-max-age", "3600")?;
        }
        _ => {}
    }

    Ok(())
}

/// Resolve origin untuk CORS — return origin yang di-allow atau fallback.
pub fn resolve_origin<'a>(origin: &'a str, cfg: &'a Config) -> &'a str {
    if cfg.cors_origins.iter().any(|o| o == "*") {
        return origin;
    }
    if cfg.cors_origins.iter().any(|o| o == origin) {
        return origin;
    }
    if cfg.dev_origins.iter().any(|o| o == origin) {
        return origin;
    }
    cfg.cors_origins.first().map(|s| s.as_str()).unwrap_or("*")
}

// ─── Cache ────────────────────────────────────────────────────────────────────

fn apply_cache(
    resp: &mut ResponseHeader,
    ctx: &RequestCtx,
    cfg: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match ctx.route {
        RouteKind::Static => {
            if ctx.is_static {
                // Bundle Leptos di /pkg/ (e-ticketing.js / .wasm) TIDAK content-hashed
                // — namanya stabil antar-deploy. `immutable` di file non-hashed = BUG:
                // setelah deploy, browser tetap pakai JS/WASM lama dari cache padahal
                // index.html (no-store) sudah baru → mismatch → hydration crash
                // ("is not a function"). App memang set `no-cache` di /pkg/ (lihat
                // pkg_no_cache di main.rs); proxy WAJIB menghormatinya, bukan menimpa
                // dengan immutable. Revalidasi murah (304, tanpa body) via ETag.
                if ctx.path.starts_with("/pkg/") {
                    resp.insert_header("cache-control", "no-cache, must-revalidate")?;
                } else {
                    // Static asset lain (punya ekstensi) — immutable.
                    // Berlaku juga untuk .br/.gz variant (is_static_path cover keduanya).
                    resp.insert_header("cache-control", "public, max-age=31536000, immutable")?;
                }
            } else {
                // SPA route (/, /explore, dll) → serve index.html
                // HARUS no-store: browser fetch ulang → dapat hash bundle terbaru
                resp.insert_header("cache-control", "no-cache, no-store, must-revalidate")?;
            }
        }
        RouteKind::Object => {
            let max_age = (cfg.image_cache_days as u64).saturating_mul(86_400);
            let cache_val = format!("public, max-age={max_age}");
            resp.insert_header("cache-control", cache_val.as_str())?;
        }
        RouteKind::Api | RouteKind::Websocket => {
            resp.insert_header("cache-control", "no-store")?;
        }
        RouteKind::Dashboard => {
            resp.insert_header("cache-control", "no-cache, must-revalidate")?;
        }
        // PPM kelola Cache-Control sendiri (immutable /pkg ber-hash, no-cache HTML)
        // — proxy JANGAN menimpa.
        RouteKind::Ppm | RouteKind::WaAdmin | RouteKind::Gitea => {}
    }
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── strip_port ────────────────────────────────────────────────────────────

    #[test]
    fn strip_port_ipv4_with_port() {
        assert_eq!(strip_port("192.168.1.1:3000"), "192.168.1.1");
    }

    #[test]
    fn strip_port_hostname_with_port() {
        assert_eq!(strip_port("ulala.space:443"), "ulala.space");
        assert_eq!(strip_port("ulala.space"), "ulala.space");
    }

    #[test]
    fn strip_port_ipv6_was_broken_before() {
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
        assert_eq!(strip_port("[2001:db8::1]:443"), "[2001:db8::1]");
    }

    // ── resolve_origin ────────────────────────────────────────────────────────

    fn test_cfg(cors: &[&str], dev: &[&str]) -> crate::config::Config {
        crate::config::Config {
            cors_origins: cors.iter().map(|s| s.to_string()).collect(),
            dev_origins: dev.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn wildcard_config_returns_origin_not_star() {
        let cfg = test_cfg(&["*"], &[]);
        let result = resolve_origin("https://example.com", &cfg);
        assert_eq!(result, "https://example.com");
        assert_ne!(result, "*");
    }

    #[test]
    fn known_origin_returned_as_is() {
        let cfg = test_cfg(&["https://ulala.space"], &[]);
        assert_eq!(
            resolve_origin("https://ulala.space", &cfg),
            "https://ulala.space"
        );
    }

    #[test]
    fn unknown_origin_gets_first_cors() {
        let cfg = test_cfg(&["https://ulala.space"], &[]);
        assert_eq!(
            resolve_origin("https://attacker.com", &cfg),
            "https://ulala.space"
        );
    }

    #[test]
    fn empty_cors_fallback_to_star() {
        let cfg = test_cfg(&[], &[]);
        assert_eq!(resolve_origin("https://x.com", &cfg), "*");
    }

    // ── MIME ──────────────────────────────────────────────────────────────────

    #[test]
    fn wasm_mime_correct() {
        assert_eq!(mime_from_path("/app-abc123.wasm"), Some("application/wasm"));
        assert_eq!(mime_from_path("/app.WASM"), Some("application/wasm"));
    }

    #[test]
    fn js_mime_rfc9239() {
        assert_eq!(mime_from_path("/app.js"), Some("text/javascript"));
        assert_eq!(mime_from_path("/module.mjs"), Some("text/javascript"));
    }

    #[test]
    fn mime_strips_query() {
        assert_eq!(mime_from_path("/app.js?v=xyz"), Some("text/javascript"));
        assert_eq!(mime_from_path("/style.css?hash=abc"), Some("text/css"));
    }

    // ── FIX: MIME untuk .br dan .gz pre-compressed files ──────────────────────

    #[test]
    fn wasm_br_gets_wasm_mime() {
        // .wasm.br → strip .br → resolve dari .wasm → application/wasm
        assert_eq!(
            mime_from_path("/app_bg.wasm.br"),
            Some("application/wasm"),
            ".wasm.br harus dapat MIME application/wasm, bukan unknown"
        );
    }

    #[test]
    fn wasm_gz_gets_wasm_mime() {
        assert_eq!(
            mime_from_path("/app_bg.wasm.gz"),
            Some("application/wasm"),
            ".wasm.gz harus dapat MIME application/wasm"
        );
    }

    #[test]
    fn js_br_gets_js_mime() {
        assert_eq!(
            mime_from_path("/app.js.br"),
            Some("text/javascript"),
            ".js.br harus dapat MIME text/javascript"
        );
    }

    #[test]
    fn css_gz_gets_css_mime() {
        assert_eq!(
            mime_from_path("/style.css.gz"),
            Some("text/css"),
            ".css.gz harus dapat MIME text/css"
        );
    }

    #[test]
    fn br_without_known_inner_ext_returns_none() {
        // File .unknown.br → inner ext "unknown" → None
        assert_eq!(mime_from_path("/data.unknown.br"), None);
    }
}
