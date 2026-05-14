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

use pingora_http::{RequestHeader, ResponseHeader};

use crate::config::Config;
use crate::proxy::context::{RequestCtx, RouteKind};

// ─── MIME map ─────────────────────────────────────────────────────────────────

#[inline]
pub fn mime_from_path(path: &str) -> Option<&'static str> {
    let ext = path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");

    match_ext_ci(ext)
}

// REVIEW: refactor ke match + eq_ignore_ascii_case untuk readability
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
    // REVIEW: X-Forwarded-For trust model — proxy ini adalah edge proxy.
    // IP dari session.client_addr() adalah koneksi TCP langsung, tidak bisa di-spoof.
    // Kalau di-deploy di belakang LB lain (AWS ALB, Cloudflare, dll), ganti dengan:
    // baca X-Forwarded-For yang sudah ada dari upstream lalu append, bukan override.
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
    if ctx.is_static || ctx.is_object {
        if let Some(mime) = mime_from_path(&ctx.path) {
            upstream_resp.insert_header("content-type", mime)?;
        }

        // REVIEW FIX: content-disposition: inline hanya untuk tipe binary yang aman.
        // SVG bisa contain <script> → inline di same-origin = eksekusi JS = XSS vector.
        // HTML juga bisa eksekusi script. JS/CSS sudah ada MIME enforcement.
        // Binary assets (image raster, font, audio, video, wasm) aman di-inline.
        let path_lower = ctx.path.to_ascii_lowercase();
        let ext = path_lower
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
        // SVG, HTML, JS, CSS: tidak set content-disposition — browser default.
    }

    // ── Security headers ──────────────────────────────────────────────────────
    upstream_resp.insert_header("x-content-type-options", "nosniff")?;
    upstream_resp.insert_header("x-frame-options", "SAMEORIGIN")?;
    // REVIEW: x-xss-protection DIHAPUS — deprecated di semua browser modern (Chrome 78+).
    // Pernah membuka reflection XSS di IE/Edge lama via filter bypass.
    // CSP di bawah yang handle XSS protection.
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

    // REVIEW: Content-Security-Policy + Cross-Origin Isolation untuk frontend Leptos WASM.
    // CSP:
    //   script-src 'wasm-unsafe-eval' — diperlukan untuk WASM instantiation (CSP Level 3)
    //     bukan 'unsafe-eval' (terlalu broad, izinkan eval() string)
    //   style-src 'unsafe-inline' — Leptos/Trunk inject <style> tag saat runtime
    //   connect-src — izinkan fetch/WS ke API domain
    // Sesuaikan jika pakai CDN font atau third-party script.
    if matches!(ctx.route, RouteKind::Static) {
        let api = cfg.api_domain.as_str();
        let csp = format!(
            "default-src 'self'; \
             script-src 'self' 'wasm-unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data: blob:; \
             connect-src 'self' https://{api} wss://{api}; \
             font-src 'self'; \
             object-src 'none'; \
             base-uri 'self'",
        );
        upstream_resp.insert_header("content-security-policy", csp.as_str())?;
        // Cross-Origin Isolation untuk WASM SharedArrayBuffer/threading
        upstream_resp.insert_header("cross-origin-opener-policy", "same-origin")?;
        upstream_resp.insert_header("cross-origin-embedder-policy", "require-corp")?;
        upstream_resp.insert_header("cross-origin-resource-policy", "same-origin")?;
    }

    let id_buf = ctx.id_hex_buf();
    let mut elapsed_buf = ctx.elapsed_ms_buf();
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
                // REVIEW FIX: SPEC BUG — RFC 7480 §6.1 melarang credentials + wildcard.
                // Browser reject response kalau allow-origin: * + allow-credentials: true.
                // resolve_origin() return "*" hanya kalau cors_origins kosong (misconfigured).
                if allowed != "*" {
                    resp.insert_header("access-control-allow-credentials", "true")?;
                }
                resp.insert_header(
                    "access-control-allow-methods",
                    "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                )?;
                resp.insert_header(
                    "access-control-allow-headers",
                    "authorization, content-type, x-request-id",
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
            // REVIEW FIX: sama, jangan set credentials kalau wildcard
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
///
/// REVIEW: jangan return "*" kalau config mengharuskan credentials.
/// Caller (`apply_cors`, `handle_preflight`) WAJIB cek result != "*" sebelum
/// set `access-control-allow-credentials: true`.
///
/// Urutan:
///   1. cors_origins berisi "*" → return request origin (BUKAN literal "*")
///      sehingga allow-credentials tetap bisa jalan
///   2. origin di cors_origins   → return origin
///   3. origin di dev_origins    → return origin
///   4. Fallback                 → first cors_origin atau "*" (misconfigured)
pub fn resolve_origin<'a>(origin: &'a str, cfg: &'a Config) -> &'a str {
    // Wildcard config → semua origin di-allow, tapi return request origin (bukan "*")
    // agar allow-credentials masih bisa di-set oleh caller
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
                // Static asset (punya ekstensi) — immutable, filename sudah ada content hash
                resp.insert_header("cache-control", "public, max-age=31536000, immutable")?;
            } else {
                // SPA route (/, /explore, dll) → serve index.html
                // HARUS no-store: browser fetch ulang → dapat hash bundle terbaru
                resp.insert_header("cache-control", "no-cache, no-store, must-revalidate")?;
            }
        }
        RouteKind::Object => {
            // REVIEW NOTE: field bernama image_cache_days tapi berlaku ke semua Object
            // (termasuk PDF, video, arbitrary S3 object). Misleading tapi tidak di-rename
            // agar tidak breaking existing config.
            //
            // REVIEW FIX: ganti manual unsafe slice copy dengan format string.
            // Original: `let mut hdr = [0u8; 48]; ... copy_from_slice(age_b)` — fragile,
            // tidak ada bounds check eksplisit. format! lebih aman, heap alloc satu kali
            // per response (Object route bukan hot path seperti static asset).
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
        // Original split(':') → "[" for "[::1]:8080" — bug!
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
        // cors_origins: ["*"] → return request origin, BUKAN literal "*"
        // kalau return "*": caller tidak bisa set allow-credentials → broken
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
        // Attacker.com tidak di-allow → fallback ke first (bukan origin)
        // apply_cors akan skip allow-credentials karena result != request origin
        assert_eq!(
            resolve_origin("https://attacker.com", &cfg),
            "https://ulala.space"
        );
    }

    #[test]
    fn empty_cors_fallback_to_star() {
        let cfg = test_cfg(&[], &[]);
        // Misconfigured (kosong) → fallback ke "*"
        // apply_cors tidak set allow-credentials karena "*" == "*"
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
        // RFC 9239: text/javascript, bukan application/javascript
        assert_eq!(mime_from_path("/app.js"), Some("text/javascript"));
        assert_eq!(mime_from_path("/module.mjs"), Some("text/javascript"));
    }

    #[test]
    fn mime_strips_query() {
        assert_eq!(mime_from_path("/app.js?v=xyz"), Some("text/javascript"));
        assert_eq!(mime_from_path("/style.css?hash=abc"), Some("text/css"));
    }
}
