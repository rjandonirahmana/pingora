//! Transform layer — modifikasi request & response header.
//!
//! Dipisah dari proxy core supaya mudah di-test & di-extend.
//! Semua fungsi pure atau near-pure (minimal side effect).

use pingora_http::{RequestHeader, ResponseHeader};

use crate::config::Config;
use crate::proxy::context::{RequestCtx, RouteKind};

// ─── MIME map ─────────────────────────────────────────────────────────────────

/// Return MIME type dari ekstensi path.
/// Inline + match table = compiler bisa optimize jadi jump table.
#[inline]
pub fn mime_from_path(path: &str) -> Option<&'static str> {
    let ext = path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .to_lowercase();

    // Diperluas dari sebelumnya — cover semua format umum
    match ext.as_str() {
        // Gambar
        "png"           => Some("image/png"),
        "jpg" | "jpeg"  => Some("image/jpeg"),
        "gif"           => Some("image/gif"),
        "webp"          => Some("image/webp"),
        "svg"           => Some("image/svg+xml"),
        "avif"          => Some("image/avif"),
        "ico"           => Some("image/x-icon"),
        "bmp"           => Some("image/bmp"),
        "tiff" | "tif"  => Some("image/tiff"),
        // Video
        "mp4"           => Some("video/mp4"),
        "webm"          => Some("video/webm"),
        "mov"           => Some("video/quicktime"),
        "avi"           => Some("video/x-msvideo"),
        "mkv"           => Some("video/x-matroska"),
        // Audio
        "mp3"           => Some("audio/mpeg"),
        "ogg"           => Some("audio/ogg"),
        "wav"           => Some("audio/wav"),
        "flac"          => Some("audio/flac"),
        "m4a"           => Some("audio/mp4"),
        // Dokumen
        "pdf"           => Some("application/pdf"),
        "txt"           => Some("text/plain; charset=utf-8"),
        "json"          => Some("application/json"),
        "xml"           => Some("application/xml"),
        "csv"           => Some("text/csv"),
        // Web
        "html"          => Some("text/html; charset=utf-8"),
        "css"           => Some("text/css"),
        "js" | "mjs"    => Some("application/javascript"),
        "wasm"          => Some("application/wasm"),
        // Font
        "woff"          => Some("font/woff"),
        "woff2"         => Some("font/woff2"),
        "ttf"           => Some("font/ttf"),
        _               => None,
    }
}

// ─── Request transform ────────────────────────────────────────────────────────

/// Modifikasi request sebelum dikirim ke upstream.
///
/// Urutan operasi:
///   1. Strip path prefix (kalau ada)
///   2. Set Host header (sesuai upstream type)
///   3. Set forwarding headers
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

        let new_pq = match upstream_req.uri.query() {
            Some(q) => format!("{}?{}", stripped, q),
            None    => stripped.to_string(),
        };

        let new_uri = http::Uri::builder()
            .path_and_query(new_pq.as_str())
            .build()?;
        upstream_req.set_uri(new_uri);
    }

    // ── 2. Host header ────────────────────────────────────────────────────────
    // RustFS: preserve original host (virtual-host routing & CSRF protection)
    // Semua lain: set ke upstream addr
    use crate::upstream::Upstream;
    let host_val = match ctx.upstream {
        Upstream::RustFS3 | Upstream::RustFSUI => {
            ctx.host.split(':').next().unwrap_or(&ctx.host).to_string()
        }
        _ => ctx.upstream.addr(cfg).to_string(),
    };
    upstream_req.insert_header("host", &host_val)?;

    // ── 3. Forwarding headers ─────────────────────────────────────────────────
    upstream_req.insert_header("x-request-id",       &ctx.id_hex())?;
    upstream_req.insert_header("x-forwarded-proto",  "https")?;
    upstream_req.insert_header("x-forwarded-host",   &ctx.host)?;

    if !ctx.client_ip_str.is_empty() {
        upstream_req.insert_header("x-real-ip",       &ctx.client_ip_str)?;
        upstream_req.append_header("x-forwarded-for", &ctx.client_ip_str)?;
    }

    Ok(())
}

// ─── Response transform ───────────────────────────────────────────────────────

/// Modifikasi response sebelum dikembalikan ke client.
///
/// Pipeline:
///   1. CORS
///   2. Cache headers (per RouteKind)
///   3. Content-Type + Content-Disposition (untuk object storage)
///   4. Security headers (semua response)
///   5. Metadata headers (request ID, served-by)
pub fn apply_response(
    upstream_resp: &mut ResponseHeader,
    ctx: &RequestCtx,
    cfg: &Config,
    origin: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ── 1. CORS ───────────────────────────────────────────────────────────────
    apply_cors(upstream_resp, ctx, cfg, origin)?;

    // ── 2. Cache ──────────────────────────────────────────────────────────────
    apply_cache(upstream_resp, ctx, cfg)?;

    // ── 3. Content-Type + Content-Disposition (object storage) ───────────────
    if ctx.is_object {
        if let Some(mime) = mime_from_path(&ctx.path) {
            upstream_resp.insert_header("content-type", mime)?;
        }
        // SELALU inline — ini fix utama masalah download.
        // insert_header() di Pingora REPLACE header upstream yang mungkin "attachment".
        upstream_resp.insert_header("content-disposition", "inline")?;
    }

    // ── 4. Security headers ───────────────────────────────────────────────────
    upstream_resp.insert_header("x-content-type-options",            "nosniff")?;
    upstream_resp.insert_header("x-frame-options",                   "SAMEORIGIN")?;
    upstream_resp.insert_header("x-xss-protection",                  "1; mode=block")?;
    upstream_resp.insert_header("referrer-policy",                   "strict-origin-when-cross-origin")?;
    upstream_resp.insert_header("strict-transport-security",         "max-age=31536000; includeSubDomains")?;
    upstream_resp.insert_header("permissions-policy",                "geolocation=(), microphone=(), camera=()")?;

    // ── 5. Metadata ───────────────────────────────────────────────────────────
    upstream_resp.insert_header("x-request-id", &ctx.id_hex())?;
    upstream_resp.insert_header("x-served-by",  "kinetic-proxy")?;
    upstream_resp.insert_header("x-elapsed-ms", &ctx.elapsed_ms().to_string())?;

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
        _ => return Ok(()), // tidak ada Origin header → skip CORS
    };

    let allowed = resolve_origin(origin, cfg);

    match ctx.upstream {
        Upstream::Backend => {
            if ctx.is_api {
                resp.insert_header("access-control-allow-origin",      &allowed)?;
                resp.insert_header("access-control-allow-credentials", "true")?;
                resp.insert_header("access-control-allow-methods",     "GET, POST, PUT, PATCH, DELETE, OPTIONS")?;
                resp.insert_header("access-control-allow-headers",     "authorization, content-type, x-request-id")?;
                resp.insert_header("access-control-expose-headers",    "x-request-id, x-elapsed-ms")?;
                resp.insert_header("access-control-max-age",           "86400")?;
            }
        }
        Upstream::RustFS3 => {
            resp.insert_header("access-control-allow-origin",      &allowed)?;
            resp.insert_header("access-control-allow-credentials", "true")?;
            resp.insert_header("access-control-allow-methods",     "GET, HEAD, PUT, DELETE, OPTIONS")?;
            resp.insert_header("access-control-allow-headers",     "authorization, range, content-type, x-amz-date, x-amz-content-sha256")?;
            resp.insert_header("access-control-max-age",           "3600")?;
        }
        _ => {}
    }

    Ok(())
}

fn resolve_origin(origin: &str, cfg: &Config) -> String {
    if cfg.cors_origins.iter().any(|o| o == "*" || o == origin) {
        origin.to_string()
    } else {
        cfg.cors_origins.first().cloned().unwrap_or_else(|| "*".into())
    }
}

// ─── Cache ────────────────────────────────────────────────────────────────────

fn apply_cache(
    resp: &mut ResponseHeader,
    ctx: &RequestCtx,
    cfg: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cache = match ctx.route {
        RouteKind::Static => {
            // Immutable static assets — 1 tahun
            "public, max-age=31536000, immutable"
        }
        RouteKind::Object => {
            // Image/video — configurable (default 30 hari)
            return {
                let max_age = cfg.image_cache_days as u64 * 86_400;
                resp.insert_header("cache-control", &format!("public, max-age={}", max_age))?;
                Ok(())
            };
        }
        RouteKind::Api | RouteKind::Websocket => {
            // API — no cache
            "no-store"
        }
        RouteKind::Dashboard => {
            // Console UI — revalidate
            "no-cache, must-revalidate"
        }
    };

    resp.insert_header("cache-control", cache)?;
    Ok(())
}
