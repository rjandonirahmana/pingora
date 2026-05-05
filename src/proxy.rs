//! Implementasi KineticProxy — inti reverse proxy dua-domain.
//!
//! Routing:
//!
//!  ulala.space              /*        → Frontend :3100 (SPA fallback otomatis)
//!  ulalaapi.store           /api/ws/* → Backend  :8080 (WebSocket, timeout 3600s)
//!  ulalaapi.store           /api/*    → Backend  :8080 (REST)
//!  ulalaapi.store           /image/*  → RustFS3  :9000 (strip "/image" prefix)
//!  image.ulalaapi.store     /*        → RustFS3  :9000 (subdomain, NO strip)
//!  ui.ulalaapi.store        /*        → RustFSUI :9001
//!  ulalaapi.store           /*        → Backend  :8080 (fallback)
//!
//! TLS:
//!  Port 443 — SNI callback memilih cert ulala.space vs ulalaapi.store secara
//!  otomatis berdasarkan SNI handshake.
//!
//! HTTP → HTTPS redirect di-handle oleh RedirectProxy (lihat main.rs).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pingora_core::prelude::*;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::ErrorType;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};

use crate::config::Config;
use crate::upstream::Upstream;

// ─── Timeout constants ────────────────────────────────────────────────────────

const WS_TIMEOUT_SECS: u64 = 3600;
const REST_CONN_TIMEOUT_SECS: u64 = 30;
const REST_READ_TIMEOUT_SECS: u64 = 60;
const REST_WRITE_TIMEOUT_SECS: u64 = 30;

// ─── Per-request context ─────────────────────────────────────────────────────

pub struct RequestCtx {
    pub upstream: Upstream,
    pub request_id: String,
    /// true HANYA untuk path-based routing: ulalaapi.store/image/* → RustFS3
    /// false untuk subdomain: image.ulalaapi.store/* (path sudah benar, tidak perlu strip)
    pub strip_image_prefix: bool,
    /// Original Host header dari client (preserve untuk RustFS virtual-host & CSRF)
    pub original_host: String,
}

// ─── Main proxy ──────────────────────────────────────────────────────────────

pub struct KineticProxy {
    cfg: Arc<Config>,
}

#[async_trait]
impl ProxyHttp for KineticProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            upstream: Upstream::Frontend,
            request_id: String::new(),
            strip_image_prefix: false,
            original_host: String::new(),
        }
    }

    // ── 1. Pilih upstream ─────────────────────────────────────────────────────
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let req = session.req_header();
        let path = req.uri.path().to_string();
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        ctx.original_host = host.to_string();
        ctx.upstream = Upstream::for_request(host, &path, &self.cfg);
        ctx.request_id = new_request_id();

        // FIX: strip_image_prefix HANYA untuk path-based routing di api_domain.
        // Subdomain image.ulalaapi.store punya path langsung (/bucket/file.jpg),
        // strip "/image" di sana akan merusak semua request (path jadi "/").
        let host_bare = host.split(':').next().unwrap_or(host);
        ctx.strip_image_prefix = ctx.upstream == Upstream::RustFS3
            && host_bare != self.cfg.image_subdomain.as_str()
            && path.starts_with("/image/");

        let addr = ctx.upstream.addr(&self.cfg).to_string();

        let upgrade_is_ws = req
            .headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
        let is_ws = upgrade_is_ws || Upstream::is_ws_path(&path);

        tracing::debug!(
            "[{}] {} {} host={} upstream={:?} ws={} strip={}",
            ctx.request_id,
            req.method,
            path,
            host,
            ctx.upstream,
            is_ws,
            ctx.strip_image_prefix,
        );

        let mut peer = HttpPeer::new(&addr, false, String::new());

        if is_ws {
            peer.options.connection_timeout = Some(Duration::from_secs(WS_TIMEOUT_SECS));
            peer.options.read_timeout = Some(Duration::from_secs(WS_TIMEOUT_SECS));
            peer.options.write_timeout = Some(Duration::from_secs(WS_TIMEOUT_SECS));
        } else {
            peer.options.connection_timeout = Some(Duration::from_secs(REST_CONN_TIMEOUT_SECS));
            peer.options.read_timeout = Some(Duration::from_secs(REST_READ_TIMEOUT_SECS));
            peer.options.write_timeout = Some(Duration::from_secs(REST_WRITE_TIMEOUT_SECS));
        }

        Ok(Box::new(peer))
    }

    // ── 2. Modifikasi request sebelum dikirim ke upstream ─────────────────────
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // ── Strip prefix /image → / (hanya untuk path-based api_domain routing) ─
        if ctx.strip_image_prefix {
            let path = upstream_request.uri.path();
            // /image/foo.jpg → /foo.jpg  |  /image → /
            let stripped = path.strip_prefix("/image").unwrap_or("/");
            let stripped = if stripped.is_empty() { "/" } else { stripped };

            let new_pq = match upstream_request.uri.query() {
                Some(q) => format!("{}?{}", stripped, q),
                None => stripped.to_string(),
            };

            let new_uri = http::Uri::builder()
                .path_and_query(new_pq.as_str())
                .build()
                .map_err(|e| {
                    pingora_core::Error::explain(
                        pingora_core::ErrorType::InternalError,
                        format!("URI rebuild gagal: {e}"),
                    )
                })?;
            upstream_request.set_uri(new_uri);
        }

        // ── Host header ───────────────────────────────────────────────────────
        // FIX: Untuk RustFS S3 dan UI Console, preserve original Host dari client:
        //   - S3: virtual-host style bucket routing butuh host yang benar
        //   - Console: MinIO/RustFS cek Host header untuk CSRF protection
        // Untuk upstream lain: set ke upstream addr (standar reverse proxy)
        let host_value = match ctx.upstream {
            Upstream::RustFS3 | Upstream::RustFSUI => {
                // Strip port, karena upstream lokal tidak butuh port eksternal
                ctx.original_host
                    .split(':')
                    .next()
                    .unwrap_or(&ctx.original_host)
                    .to_string()
            }
            _ => ctx.upstream.addr(&self.cfg).to_string(),
        };
        upstream_request.insert_header("host", &host_value)?;

        // ── Forwarding headers ────────────────────────────────────────────────
        upstream_request.insert_header("x-request-id", &ctx.request_id)?;
        upstream_request.insert_header("x-forwarded-proto", "https")?;

        if let Some(client_ip) = session.client_addr().map(|a| a.to_string()) {
            upstream_request.insert_header("x-real-ip", &client_ip)?;
            upstream_request.append_header("x-forwarded-for", &client_ip)?;
        }

        Ok(())
    }

    // ── 3. Modifikasi response sebelum dikembalikan ke client ─────────────────
    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let path = session.req_header().uri.path().to_string();

        // ── CORS untuk api_domain /api/* ──────────────────────────────────────
        if ctx.upstream == Upstream::Backend && path.starts_with("/api") {
            let origin = session
                .req_header()
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("*");

            let allowed_origin = if self
                .cfg
                .cors_origins
                .iter()
                .any(|o| o == "*" || o == origin)
            {
                origin.to_string()
            } else {
                self.cfg
                    .cors_origins
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "*".into())
            };

            upstream_response.insert_header("access-control-allow-origin", &allowed_origin)?;
            upstream_response.insert_header("access-control-allow-credentials", "true")?;
            upstream_response.insert_header(
                "access-control-allow-methods",
                "GET, POST, PUT, PATCH, DELETE, OPTIONS",
            )?;
            upstream_response.insert_header(
                "access-control-allow-headers",
                "authorization, content-type, x-request-id",
            )?;
            upstream_response.insert_header("access-control-max-age", "86400")?;
        }

        // ── CORS untuk RustFS S3 (browser fetch/upload dari ulala.space) ──────
        if ctx.upstream == Upstream::RustFS3 {
            let origin = session
                .req_header()
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if !origin.is_empty() {
                let allowed_origin = if self
                    .cfg
                    .cors_origins
                    .iter()
                    .any(|o| o == "*" || o == origin)
                {
                    origin.to_string()
                } else {
                    self.cfg
                        .cors_origins
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "*".into())
                };
                upstream_response.insert_header("access-control-allow-origin", &allowed_origin)?;
                upstream_response.insert_header("access-control-allow-credentials", "true")?;
                upstream_response
                    .insert_header("access-control-allow-methods", "GET, HEAD, PUT, OPTIONS")?;
                upstream_response.insert_header(
                    "access-control-allow-headers",
                    "authorization, range, content-type",
                )?;
            }
        }

        // ── Cache headers untuk RustFS S3 ─────────────────────────────────────
        if ctx.upstream == Upstream::RustFS3 && self.cfg.image_cache_days > 0 {
            let max_age = self.cfg.image_cache_days as u64 * 86_400;
            upstream_response
                .insert_header("cache-control", &format!("public, max-age={}", max_age))?;
        }

        // ── Cache untuk static assets frontend ────────────────────────────────
        if ctx.upstream == Upstream::Frontend
            && (path.starts_with("/static/") || path.ends_with(".wasm") || path.ends_with(".js"))
        {
            upstream_response
                .insert_header("cache-control", "public, max-age=31536000, immutable")?;
        }

        // ── Security headers ──────────────────────────────────────────────────
        upstream_response.insert_header("x-content-type-options", "nosniff")?;
        upstream_response.insert_header("x-frame-options", "SAMEORIGIN")?;
        upstream_response.insert_header("x-xss-protection", "1; mode=block")?;
        upstream_response.insert_header("referrer-policy", "strict-origin-when-cross-origin")?;

        upstream_response.insert_header("x-request-id", &ctx.request_id)?;
        upstream_response.insert_header("x-served-by", "kinetic-proxy")?;

        Ok(())
    }

    // ── 4. Preflight OPTIONS ───────────────────────────────────────────────────
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let method = session.req_header().method.clone();
        let path = session.req_header().uri.path().to_string();

        if method == http::Method::OPTIONS && path.starts_with("/api") {
            let origin = session
                .req_header()
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("*")
                .to_string();

            let mut resp = ResponseHeader::build(http::StatusCode::NO_CONTENT, None)?;
            resp.insert_header("access-control-allow-origin", &origin)?;
            resp.insert_header("access-control-allow-credentials", "true")?;
            resp.insert_header(
                "access-control-allow-methods",
                "GET, POST, PUT, PATCH, DELETE, OPTIONS",
            )?;
            resp.insert_header(
                "access-control-allow-headers",
                "authorization, content-type, x-request-id",
            )?;
            resp.insert_header("access-control-max-age", "86400")?;
            resp.insert_header("content-length", "0")?;

            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
        }

        Ok(false)
    }

    // ── 5. Error handling ─────────────────────────────────────────────────────
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        _ctx: &mut Self::CTX,
        mut e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        tracing::error!("Gagal konek ke upstream: {e}");
        e.set_retry(false);
        e
    }

    fn error_while_proxy(
        &self,
        _peer: &HttpPeer,
        session: &mut Session,
        mut e: Box<pingora_core::Error>,
        ctx: &mut Self::CTX,
        _client_reused: bool,
    ) -> Box<pingora_core::Error> {
        tracing::warn!(
            "[{}] Proxy error: {} uri={:?}",
            ctx.request_id,
            e,
            session.req_header().uri
        );

        match e.etype {
            ErrorType::ConnectTimedout
            | ErrorType::ConnectError
            | ErrorType::ConnectRefused
            | ErrorType::ConnectProxyFailure => {
                e.set_retry(true);
            }
            _ => {
                e.set_retry(false);
            }
        }

        e
    }
}

// ─── HTTP → HTTPS Redirect proxy ─────────────────────────────────────────────

pub struct RedirectProxy;

#[async_trait]
impl ProxyHttp for RedirectProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let path = req.uri.path();
        let qs = req
            .uri
            .query()
            .map(|q| format!("?{}", q))
            .unwrap_or_default();

        let location = format!("https://{}{}{}", host, path, qs);

        let mut resp = ResponseHeader::build(http::StatusCode::MOVED_PERMANENTLY, None)?;
        resp.insert_header("location", &location)?;
        resp.insert_header("content-length", "0")?;

        session.write_response_header(Box::new(resp), true).await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        unreachable!("RedirectProxy tidak punya upstream")
    }
}

// ─── Factory ──────────────────────────────────────────────────────────────────

pub fn build_proxy_service(
    cfg: &Config,
    server: &mut Server,
) -> impl pingora_core::services::Service {
    let proxy = KineticProxy {
        cfg: Arc::new(cfg.clone()),
    };
    let mut svc = http_proxy_service(&server.configuration, proxy);

    if cfg.tls_enabled() {
        let cert_web = cfg.tls_cert_web.as_deref().unwrap();
        let key_web = cfg.tls_key_web.as_deref().unwrap();

        let mut tls = pingora_core::listeners::tls::TlsSettings::intermediate(cert_web, key_web)
            .expect("Gagal load TLS cert web");

        // SNI callback: pilih cert api untuk api_domain dan semua subdomain-nya.
        // PENTING: tls_cert_api harus wildcard cert (*.ulalaapi.store) agar
        // mencakup image.ulalaapi.store, ui.ulalaapi.store, dll.
        if let (Some(cert_api), Some(key_api)) = (cfg.tls_cert_api.clone(), cfg.tls_key_api.clone())
        {
            use openssl::ssl::{NameType, SslAcceptor, SslFiletype, SslMethod};

            let mut api_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
                .expect("API SslAcceptor builder gagal");
            api_builder
                .set_certificate_chain_file(&cert_api)
                .expect("Gagal load cert API");
            api_builder
                .set_private_key_file(&key_api, SslFiletype::PEM)
                .expect("Gagal load key API");
            let api_ctx = api_builder.build().into_context();

            let api_domain_owned = cfg.api_domain.clone();

            tls.set_servername_callback(move |ssl, _alert| {
                if let Some(sni) = ssl.servername(NameType::HOST_NAME) {
                    // Match api_domain dan semua subdomain-nya
                    let matches = sni == api_domain_owned
                        || sni == format!("www.{}", api_domain_owned)
                        || sni.ends_with(&format!(".{}", api_domain_owned));

                    if matches {
                        ssl.set_ssl_context(&api_ctx)
                            .map_err(|_| openssl::ssl::SniError::NOACK)?;
                    }
                }
                Ok(())
            });

            tracing::info!("SNI TLS: web_cert={cert_web}, api_cert={cert_api}");
        }

        svc.add_tls_with_settings(&cfg.listen_addr, None, tls);
        tracing::info!("HTTPS listener: {}", cfg.listen_addr);
    } else {
        svc.add_tcp(&cfg.listen_addr);
        tracing::info!("HTTP listener (no TLS): {}", cfg.listen_addr);
    }

    svc
}

pub fn build_redirect_service(
    cfg: &Config,
    server: &mut Server,
) -> impl pingora_core::services::Service {
    let redirect = RedirectProxy;
    let mut svc = http_proxy_service(&server.configuration, redirect);
    svc.add_tcp(&cfg.http_redirect_addr);
    tracing::info!("HTTP redirect listener: {}", cfg.http_redirect_addr);
    svc
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn new_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = ts.as_secs() & 0xffff_ffff;
    let nanos = ts.subsec_nanos();
    // Kombinasikan secs + nanos + noise untuk menghindari collision
    let noise: u32 = (nanos ^ nanos.wrapping_mul(0x9e37_79b9)) & 0xffff;
    format!("{:08x}{:08x}{:04x}", secs, nanos, noise)
}
