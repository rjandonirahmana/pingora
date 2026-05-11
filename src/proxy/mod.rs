//! proxy/ — Cloudflare-style layered proxy pipeline.
//!
//! Fix dari original:
//!   - handle_preflight(): origin di-validate lewat resolve_origin() (fix CORS bypass)
//!   - request_filter(): tambah /health endpoint handler (fix Docker healthcheck)
//!   - build_proxy_service(): tambah log warning jika TLS tidak dikonfigurasi

pub mod context;
pub mod policy;
pub mod router;
pub mod transform;
pub mod upstream_pool;

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use pingora_core::prelude::*;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::ErrorType;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};
use smol_str::SmolStr;

use crate::config::Config;
use crate::upstream::Upstream;

use self::context::RequestCtx;
use self::policy::{PolicyError, PolicyLayer};
use self::transform::resolve_origin;
use self::upstream_pool::{Backend, UpstreamPool};

// ─── ProxyState ───────────────────────────────────────────────────────────────

pub struct ProxyState {
    pub cfg: Arc<Config>,
    pub policy: Arc<PolicyLayer>,
    pub backend_pool: Arc<UpstreamPool>,
    pub frontend_pool: Arc<UpstreamPool>,
    pub s3_pool: Arc<UpstreamPool>,
    pub ui_pool: Arc<UpstreamPool>,
}

impl ProxyState {
    fn pool_for(&self, upstream: Upstream) -> &Arc<UpstreamPool> {
        match upstream {
            Upstream::Backend => &self.backend_pool,
            Upstream::Frontend => &self.frontend_pool,
            Upstream::RustFS3 => &self.s3_pool,
            Upstream::RustFSUI => &self.ui_pool,
        }
    }
}

// ─── KineticProxy ─────────────────────────────────────────────────────────────

pub struct KineticProxy {
    state: Arc<ProxyState>,
    // OnceLock: cleanup task di-spawn tepat sekali saat request pertama masuk,
    // yaitu saat Pingora runtime sudah aktif. tokio::spawn() sebelum runtime = panic.
    cleanup_spawned: Arc<OnceLock<()>>,
}

#[async_trait]
impl ProxyHttp for KineticProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    // ── Phase 1: Request filter — routing + policy ────────────────────────────
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // Spawn cleanup task tepat sekali saat request pertama — Pingora runtime sudah aktif.
        if self.cleanup_spawned.set(()).is_ok() {
            let rate_limiter = Arc::clone(&self.state.policy.rate_limiter);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    rate_limiter.cleanup();
                    tracing::debug!("Rate limiter active IPs: {}", rate_limiter.active_count());
                }
            });
        }

        let req = session.req_header();
        let method = req.method.clone();
        let path = req.uri.path().to_string();
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // FIX: Health check endpoint — handle sebelum routing, return 200 OK langsung.
        // Diperlukan untuk Docker HEALTHCHECK dan load balancer probe.
        if path == "/health" || path == "/healthz" {
            let mut resp = ResponseHeader::build(http::StatusCode::OK, None)?;
            resp.insert_header("content-type", "text/plain")?;
            resp.insert_header("content-length", "2")?;
            resp.insert_header("x-served-by", "kinetic-proxy")?;
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(bytes::Bytes::from_static(b"ok")), true)
                .await?;
            return Ok(true);
        }

        let client_ip: Option<IpAddr> = session
            .client_addr()
            .and_then(|addr| addr.to_string().parse::<std::net::SocketAddr>().ok())
            .map(|sa| sa.ip());

        let decision = router::route(&host, &path, &self.state.cfg);

        *ctx = RequestCtx::new(decision, host, path.clone(), method.clone(), client_ip);

        tracing::debug!(
            id       = ctx.id_hex(),
            method   = %method,
            path     = %path,
            upstream = ?ctx.upstream,
            route    = ?ctx.route,
            ws       = ctx.is_ws,
        );

        if method == http::Method::OPTIONS && ctx.is_api {
            return self.handle_preflight(session, ctx).await;
        }

        // Sync apply — tidak perlu .await karena DashMap
        match self.state.policy.apply(ctx) {
            Ok(()) => Ok(false),
            Err(err) => {
                tracing::warn!(id = ctx.id_hex(), "Policy reject: {:?}", err);
                self.reject(session, &err).await?;
                Ok(true)
            }
        }
    }

    // ── Phase 2: Pilih upstream ───────────────────────────────────────────────
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let pool = self.state.pool_for(ctx.upstream);
        let backend = pool.next().ok_or_else(|| {
            pingora_core::Error::explain(ErrorType::InternalError, "no available backend in pool")
        })?;

        // SmolStr::new() — stack-allocated untuk addr pendek
        ctx.backend_addr = SmolStr::new(&backend.addr);

        let t = ctx.timeout;
        let mut peer = HttpPeer::new(backend.addr.as_str(), false, String::new());
        peer.options.connection_timeout = Some(Duration::from_secs(t.connect_secs));
        peer.options.read_timeout = Some(Duration::from_secs(t.read_secs));
        peer.options.write_timeout = Some(Duration::from_secs(t.write_secs));

        Ok(Box::new(peer))
    }

    // ── Phase 3: Transform request ────────────────────────────────────────────
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_req: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        transform::apply_request(upstream_req, ctx, &self.state.cfg).map_err(|e| {
            pingora_core::Error::explain(
                ErrorType::InternalError,
                format!("request transform: {e}"),
            )
        })?;
        Ok(())
    }

    // ── Phase 4: Transform response ───────────────────────────────────────────
    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_resp: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(backend) = self.state.pool_for(ctx.upstream).find(&ctx.backend_addr) {
            backend.breaker.record_success();
        }

        let origin = session
            .req_header()
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok());

        transform::apply_response(upstream_resp, ctx, &self.state.cfg, origin).map_err(|e| {
            pingora_core::Error::explain(
                ErrorType::InternalError,
                format!("response transform: {e}"),
            )
        })?;

        tracing::info!(
            id      = ctx.id_hex(),
            status  = upstream_resp.status.as_u16(),
            elapsed = ctx.elapsed_ms(),
            route   = ?ctx.route,
            backend = %ctx.backend_addr,
        );

        Ok(())
    }

    // ── Phase 5: Error handling ───────────────────────────────────────────────
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        tracing::error!(
            id      = ctx.id_hex(),
            backend = %ctx.backend_addr,
            "Gagal connect ke upstream"
        );

        if let Some(backend) = self.state.pool_for(ctx.upstream).find(&ctx.backend_addr) {
            backend.breaker.record_failure();
        }

        ctx.attempts += 1;
        e.set_retry(ctx.attempts < 2);
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
            id      = ctx.id_hex(),
            backend = %ctx.backend_addr,
            uri     = ?session.req_header().uri,
            "Proxy error: {}", e,
        );

        if let Some(backend) = self.state.pool_for(ctx.upstream).find(&ctx.backend_addr) {
            backend.breaker.record_failure();
        }

        match e.etype {
            ErrorType::ConnectTimedout
            | ErrorType::ConnectError
            | ErrorType::ConnectRefused
            | ErrorType::ConnectProxyFailure => {
                ctx.attempts += 1;
                e.set_retry(ctx.attempts < 2);
            }
            _ => {
                e.set_retry(false);
            }
        }
        e
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

impl KineticProxy {
    // FIX: origin di-validate lewat resolve_origin() — tidak echo semua origin
    async fn handle_preflight(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        let origin_str = session
            .req_header()
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("*")
            .to_string();

        // FIX: validate origin lewat resolve_origin, bukan echo langsung
        let allowed = resolve_origin(&origin_str, &self.state.cfg).to_owned();

        let id_buf = ctx.id_hex_buf();
        let mut resp = ResponseHeader::build(http::StatusCode::NO_CONTENT, None)?;
        resp.insert_header("vary", "origin")?;
        resp.insert_header("access-control-allow-origin", allowed.as_str())?;
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
        resp.insert_header("x-request-id", id_buf.as_str())?;

        session.write_response_header(Box::new(resp), true).await?;
        Ok(true)
    }

    async fn reject(&self, session: &mut Session, err: &PolicyError) -> Result<()> {
        let (status, headers) = PolicyLayer::error_response(err);
        let mut resp = ResponseHeader::build(status, None)?;
        for (k, v) in headers {
            resp.insert_header(*k, *v)?;
        }
        // Body — small format!, satu kali per reject (rare path)
        let body: bytes::Bytes = match err {
            PolicyError::RateLimited { retry_after_secs } => {
                // Set retry-after header dengan itoa
                let mut nbuf = itoa::Buffer::new();
                resp.insert_header("retry-after", nbuf.format(*retry_after_secs))?;
                bytes::Bytes::from(format!(
                    r#"{{"error":"rate_limited","retry_after":{}}}"#,
                    retry_after_secs
                ))
            }
            PolicyError::BlockedIp => bytes::Bytes::from_static(br#"{"error":"forbidden"}"#),
            PolicyError::SuspiciousRequest(reason) => bytes::Bytes::from(format!(
                r#"{{"error":"bad_request","reason":"{}"}}"#,
                reason
            )),
        };
        let mut lbuf = itoa::Buffer::new();
        resp.insert_header("content-length", lbuf.format(body.len()))?;
        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(body), true).await?;
        Ok(())
    }
}

// ─── HTTP → HTTPS Redirect ────────────────────────────────────────────────────

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
        resp.insert_header("location", location.as_str())?;
        resp.insert_header("content-length", "0")?;
        resp.insert_header("x-served-by", "kinetic-proxy")?;

        session.write_response_header(Box::new(resp), true).await?;
        Ok(true)
    }

    async fn upstream_peer(&self, _: &mut Session, _: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        unreachable!()
    }
}

// ─── Factory ──────────────────────────────────────────────────────────────────

pub fn build_proxy_service(
    cfg: &Config,
    server: &mut Server,
) -> impl pingora_core::services::Service {
    let cfg_arc = Arc::new(cfg.clone());

    let policy = Arc::new(PolicyLayer::new(cfg.rate_limit_rps));

    // NOTE: rustfs_s3_address dipakai untuk s3_pool.
    // image_addr di Config adalah field lama (Garage S3 :3902) — tidak dipakai.
    // Jika perlu Garage, ganti rustfs_s3_address → image_addr di config.yaml.
    let state = Arc::new(ProxyState {
        cfg: Arc::clone(&cfg_arc),
        policy,
        backend_pool: Arc::new(UpstreamPool::single(cfg.backend_addr.clone())),
        frontend_pool: Arc::new(UpstreamPool::single(cfg.frontend_addr.clone())),
        s3_pool: Arc::new(UpstreamPool::single(cfg.rustfs_s3_address.clone())),
        ui_pool: Arc::new(UpstreamPool::single(cfg.rustfs_ui_address.clone())),
    });

    let proxy = KineticProxy {
        state,
        cleanup_spawned: Arc::new(OnceLock::new()),
    };
    let mut svc = http_proxy_service(&server.configuration, proxy);

    if cfg.tls_enabled() {
        let cert_web = cfg.tls_cert_web.as_deref().unwrap();
        let key_web = cfg.tls_key_web.as_deref().unwrap();

        let mut tls = pingora_core::listeners::tls::TlsSettings::intermediate(cert_web, key_web)
            .expect("Gagal load TLS cert web");

        if let (Some(cert_api), Some(key_api)) = (cfg.tls_cert_api.clone(), cfg.tls_key_api.clone())
        {
            use openssl::ssl::{NameType, SslAcceptor, SslFiletype, SslMethod};

            let mut api_builder =
                SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("API SslAcceptor gagal");
            api_builder
                .set_certificate_chain_file(&cert_api)
                .expect("cert API");
            api_builder
                .set_private_key_file(&key_api, SslFiletype::PEM)
                .expect("key API");
            let api_ctx = api_builder.build().into_context();

            // Pre-compute SNI match strings SEKALI saat startup — zero alloc per handshake.
            let api_domain: Box<str> = cfg.api_domain.as_str().into();
            let api_domain_www = format!("www.{}", cfg.api_domain).into_boxed_str();
            let api_domain_sub = format!(".{}", cfg.api_domain).into_boxed_str();
            tls.set_servername_callback(move |ssl, _| {
                if let Some(sni) = ssl.servername(NameType::HOST_NAME) {
                    let matches = sni == &*api_domain
                        || sni == &*api_domain_www
                        || sni.ends_with(&*api_domain_sub);
                    if matches {
                        ssl.set_ssl_context(&api_ctx)
                            .map_err(|_| openssl::ssl::SniError::NOACK)?;
                    }
                }
                Ok(())
            });
            tracing::info!("SNI TLS: web={cert_web}, api={cert_api}");
        }

        svc.add_tls_with_settings(&cfg.listen_addr, None, tls);
        tracing::info!("HTTPS :443 ready");
    } else {
        // FIX: Warning jelas jika TLS tidak dikonfigurasi — ini mungkin penyebab
        // ulala.space tidak bisa diakses (browser expect HTTPS tapi dapat HTTP)
        tracing::warn!(
            "⚠️  TLS TIDAK DIKONFIGURASI — proxy berjalan sebagai plain HTTP di {}",
            cfg.listen_addr
        );
        tracing::warn!(
            "   Set tls_cert_web + tls_key_web di config.yaml atau env PROXY_TLS_CERT_WEB / PROXY_TLS_KEY_WEB"
        );
        svc.add_tcp(&cfg.listen_addr);
        tracing::info!("HTTP (no TLS) {} ready", cfg.listen_addr);
    }

    svc
}

pub fn build_redirect_service(
    cfg: &Config,
    server: &mut Server,
) -> impl pingora_core::services::Service {
    let mut svc = http_proxy_service(&server.configuration, RedirectProxy);
    svc.add_tcp(&cfg.http_redirect_addr);
    tracing::info!("HTTP redirect :80 ready");
    svc
}
