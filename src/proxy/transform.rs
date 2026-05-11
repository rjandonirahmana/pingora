//! Transform layer — modifikasi request & response header.
//!
//! Fix dari original:
//!   - resolve_origin(): dijadikan pub agar bisa dipakai di mod.rs (handle_preflight fix)
//!   - apply_cache(): cast image_cache_days ke u64 sebelum multiply (fix u32 overflow)
//!   - apply_response(): HSTS hanya di-inject jika TLS aktif

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

fn match_ext_ci(ext: &str) -> Option<&'static str> {
    let eq = |a: &str, b: &str| {
        a.len() == b.len()
            && a.bytes()
                .zip(b.bytes())
                .all(|(x, y)| x.to_ascii_lowercase() == y)
    };

    if eq(ext, "png") {
        return Some("image/png");
    }
    if eq(ext, "jpg") || eq(ext, "jpeg") {
        return Some("image/jpeg");
    }
    if eq(ext, "gif") {
        return Some("image/gif");
    }
    if eq(ext, "webp") {
        return Some("image/webp");
    }
    if eq(ext, "svg") {
        return Some("image/svg+xml");
    }
    if eq(ext, "avif") {
        return Some("image/avif");
    }
    if eq(ext, "ico") {
        return Some("image/x-icon");
    }
    if eq(ext, "bmp") {
        return Some("image/bmp");
    }
    if eq(ext, "tiff") || eq(ext, "tif") {
        return Some("image/tiff");
    }
    if eq(ext, "mp4") {
        return Some("video/mp4");
    }
    if eq(ext, "webm") {
        return Some("video/webm");
    }
    if eq(ext, "mov") {
        return Some("video/quicktime");
    }
    if eq(ext, "avi") {
        return Some("video/x-msvideo");
    }
    if eq(ext, "mkv") {
        return Some("video/x-matroska");
    }
    if eq(ext, "mp3") {
        return Some("audio/mpeg");
    }
    if eq(ext, "ogg") {
        return Some("audio/ogg");
    }
    if eq(ext, "wav") {
        return Some("audio/wav");
    }
    if eq(ext, "flac") {
        return Some("audio/flac");
    }
    if eq(ext, "m4a") {
        return Some("audio/mp4");
    }
    if eq(ext, "pdf") {
        return Some("application/pdf");
    }
    if eq(ext, "txt") {
        return Some("text/plain; charset=utf-8");
    }
    if eq(ext, "json") {
        return Some("application/json");
    }
    if eq(ext, "xml") {
        return Some("application/xml");
    }
    if eq(ext, "csv") {
        return Some("text/csv");
    }
    if eq(ext, "html") {
        return Some("text/html; charset=utf-8");
    }
    if eq(ext, "css") {
        return Some("text/css");
    }
    if eq(ext, "js") || eq(ext, "mjs") {
        return Some("application/javascript");
    }
    if eq(ext, "wasm") {
        return Some("application/wasm");
    }
    if eq(ext, "woff") {
        return Some("font/woff");
    }
    if eq(ext, "woff2") {
        return Some("font/woff2");
    }
    if eq(ext, "ttf") {
        return Some("font/ttf");
    }
    None
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
    let host_val = match ctx.upstream {
        Upstream::RustFS3 | Upstream::RustFSUI => ctx.host.split(':').next().unwrap_or(&ctx.host),
        _ => ctx.upstream.addr(cfg),
    };
    upstream_req.insert_header("host", host_val)?;

    // ── 3. Forwarding headers ─────────────────────────────────────────────────
    let id_buf = ctx.id_hex_buf();
    upstream_req.insert_header("x-request-id", id_buf.as_str())?;
    upstream_req.insert_header("x-forwarded-proto", "https")?;
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

    if ctx.is_object {
        if let Some(mime) = mime_from_path(&ctx.path) {
            upstream_resp.insert_header("content-type", mime)?;
        }
        upstream_resp.insert_header("content-disposition", "inline")?;
    }

    // Security headers — &'static str, no alloc
    upstream_resp.insert_header("x-content-type-options", "nosniff")?;
    upstream_resp.insert_header("x-frame-options", "SAMEORIGIN")?;
    upstream_resp.insert_header("x-xss-protection", "1; mode=block")?;
    upstream_resp.insert_header("referrer-policy", "strict-origin-when-cross-origin")?;
    // FIX: HSTS hanya di-inject jika TLS aktif.
    // Di plain HTTP browser ignore HSTS, tapi lebih bersih dan tidak menyesatkan client.
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
                resp.insert_header("access-control-allow-credentials", "true")?;
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
            resp.insert_header("access-control-allow-credentials", "true")?;
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

/// FIX: dijadikan `pub` agar bisa dipakai di mod.rs untuk validasi preflight CORS.
///
/// Resolve origin — zero alloc fast path: return &str dari origin atau cors_origins.
///
/// Urutan pengecekan:
///   1. cors_origins berisi "*"    → allow (wildcard)
///   2. origin di cors_origins     → allow (production list)
///   3. origin di dev_origins      → allow (localhost dev: 3000, 5173, dll)
///   4. Tidak match                → fallback ke first cors_origin atau "*"
pub fn resolve_origin<'a>(origin: &'a str, cfg: &'a Config) -> &'a str {
    if cfg.cors_origins.iter().any(|o| o == "*" || o == origin) {
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
            resp.insert_header("cache-control", "public, max-age=31536000, immutable")?;
        }
        RouteKind::Object => {
            // FIX: cast ke u64 SEBELUM multiply untuk cegah u32 overflow.
            // image_cache_days=50_000 → 50_000 * 86_400 = 4.32e9 > u32::MAX (4.29e9).
            // Di debug: panic. Di release: wrap ke nilai kecil → cache header salah.
            let max_age = (cfg.image_cache_days as u64).saturating_mul(86_400);
            let mut nbuf = itoa::Buffer::new();
            let age_str = nbuf.format(max_age);
            let mut hdr = [0u8; 48];
            let prefix = b"public, max-age=";
            let age_b = age_str.as_bytes();
            hdr[..prefix.len()].copy_from_slice(prefix);
            hdr[prefix.len()..prefix.len() + age_b.len()].copy_from_slice(age_b);
            let hdr_str = std::str::from_utf8(&hdr[..prefix.len() + age_b.len()])
                .unwrap_or("public, max-age=2592000");
            resp.insert_header("cache-control", hdr_str)?;
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
