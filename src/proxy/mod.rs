//! proxy/ — Cloudflare-style layered proxy pipeline.
//!
//! Layer (urutan eksekusi):
//!   Client → [TLS] → [Router] → [Context] → [Policy] → [Upstream]
//!          ← [Transform Response] ← [Upstream Response] ←

pub mod context;
pub mod policy;
pub mod router;
pub mod transform;
pub mod upstream_pool;

use std::net::IpAddr;
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

use self::context::RequestCtx;
use self::policy::{PolicyError, PolicyLayer};
use self::upstream_pool::{Backend, UpstreamPool};

// ─── ProxyState ───────────────────────────────────────────────────────────────

pub struct ProxyState {
    pub cfg:           Arc<Config>,
    pub policy:        Arc<PolicyLayer>,
    // FIX: UpstreamPool sekarang benar-benar dipakai — circuit breaker aktif
    pub backend_pool:  Arc<UpstreamPool>,
    pub frontend_pool: Arc<UpstreamPool>,
    pub s3_pool:       Arc<UpstreamPool>,
    pub ui_pool:       Arc<UpstreamPool>,
}

impl ProxyState {
    fn pool_for(&self, upstream: Upstream) -> &Arc<UpstreamPool> {
        match upstream {
            Upstream::Backend  => &self.backend_pool,
            Upstream::Frontend => &self.frontend_pool,
            Upstream::RustFS3  => &self.s3_pool,
            Upstream::RustFSUI => &self.ui_pool,
        }
    }
}

// ─── KineticProxy ─────────────────────────────────────────────────────────────

pub struct KineticProxy {
    state: Arc<ProxyState>,
}

#[async_trait]
impl ProxyHttp for KineticProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    // ── Phase 1: Request filter — routing + policy ────────────────────────────
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        let req    = session.req_header();
        let method = req.method.clone();
        let path   = req.uri.path().to_string();
        let host   = req.headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // ── FIX: Client IP parsing yang aman untuk IPv4 & IPv6 ───────────────
        // Sebelumnya: split(':').next() → SALAH untuk [::1]:port
        // Sekarang: parse sebagai SocketAddr dulu, lalu ambil .ip()
        let client_ip: Option<IpAddr> = session
            .client_addr()
            .and_then(|addr| addr.to_string().parse::<std::net::SocketAddr>().ok())
            .map(|sa| sa.ip());

        // ── Router (pure function) ────────────────────────────────────────────
        let decision = router::route(&host, &path, &self.state.cfg);

        // ── Build context ─────────────────────────────────────────────────────
        *ctx = RequestCtx::new(decision, host, path.clone(), method.clone(), client_ip);

        tracing::debug!(
            id       = ctx.id_hex(),
            method   = %method,
            path     = %path,
            upstream = ?ctx.upstream,
            route    = ?ctx.route,
            ws       = ctx.is_ws,
        );

        // ── CORS Preflight ────────────────────────────────────────────────────
        if method == http::Method::OPTIONS && ctx.is_api {
            return self.handle_preflight(session, ctx).await;
        }

        // ── Policy ────────────────────────────────────────────────────────────
        match self.state.policy.apply(ctx).await {
            Ok(())   => Ok(false),
            Err(err) => {
                tracing::warn!(id = ctx.id_hex(), "Policy reject: {:?}", err);
                self.reject(session, &err).await?;
                Ok(true)
            }
        }
    }

    // ── Phase 2: Pilih upstream — pakai UpstreamPool + circuit breaker ────────
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let pool    = self.state.pool_for(ctx.upstream);
        let backend = pool.next().ok_or_else(|| {
            pingora_core::Error::explain(
                ErrorType::InternalError,
                "no available backend in pool",
            )
        })?;

        // Simpan addr backend yang dipilih ke ctx supaya bisa dicatat di error handler
        ctx.backend_addr = backend.addr.clone();

        let t = ctx.timeout;
        let mut peer = HttpPeer::new(&backend.addr, false, String::new());
        peer.options.connection_timeout = Some(Duration::from_secs(t.connect_secs));
        peer.options.read_timeout       = Some(Duration::from_secs(t.read_secs));
        peer.options.write_timeout      = Some(Duration::from_secs(t.write_secs));

        Ok(Box::new(peer))
    }

    // ── Phase 3: Transform request ────────────────────────────────────────────
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_req: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        transform::apply_request(upstream_req, ctx, &self.state.cfg)
            .map_err(|e| pingora_core::Error::explain(
                ErrorType::InternalError,
                format!("request transform: {e}"),
            ))?;
        Ok(())
    }

    // ── Phase 4: Transform response ───────────────────────────────────────────
    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_resp: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Catat sukses ke circuit breaker
        if let Some(backend) = self.state.pool_for(ctx.upstream).find(&ctx.backend_addr) {
            backend.breaker.record_success();
        }

        let origin = session.req_header()
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok());

        transform::apply_response(upstream_resp, ctx, &self.state.cfg, origin)
            .map_err(|e| pingora_core::Error::explain(
                ErrorType::InternalError,
                format!("response transform: {e}"),
            ))?;

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

        // Catat failure ke circuit breaker
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
            _ => { e.set_retry(false); }
        }
        e
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

impl KineticProxy {
    async fn handle_preflight(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        let origin = session.req_header()
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("*")
            .to_string();

        let mut resp = ResponseHeader::build(http::StatusCode::NO_CONTENT, None)?;
        resp.insert_header("access-control-allow-origin",      &origin)?;
        resp.insert_header("access-control-allow-credentials", "true")?;
        resp.insert_header("access-control-allow-methods",     "GET, POST, PUT, PATCH, DELETE, OPTIONS")?;
        resp.insert_header("access-control-allow-headers",     "authorization, content-type, x-request-id")?;
        resp.insert_header("access-control-max-age",           "86400")?;
        resp.insert_header("content-length",                   "0")?;
        resp.insert_header("x-request-id",                     &ctx.id_hex())?;

        session.write_response_header(Box::new(resp), true).await?;
        Ok(true)
    }

    async fn reject(&self, session: &mut Session, err: &PolicyError) -> Result<()> {
        let (status, headers) = PolicyLayer::error_response(err);
        let mut resp = ResponseHeader::build(status, None)?;
        for (k, v) in &headers {
            resp.insert_header(*k, v.as_str())?;
        }
        let body = match err {
            PolicyError::RateLimited { retry_after_secs } =>
                format!(r#"{{"error":"rate_limited","retry_after":{}}}"#, retry_after_secs),
            PolicyError::BlockedIp =>
                r#"{"error":"forbidden"}"#.into(),
            PolicyError::SuspiciousRequest(reason) =>
                format!(r#"{{"error":"bad_request","reason":"{}"}}"#, reason),
        };
        resp.insert_header("content-length", &body.len().to_string())?;
        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(bytes::Bytes::from(body)), true).await?;
        Ok(())
    }
}

// ─── HTTP → HTTPS Redirect ────────────────────────────────────────────────────

pub struct RedirectProxy;

#[async_trait]
impl ProxyHttp for RedirectProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX { () }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let req  = session.req_header();
        let host = req.headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
        let path = req.uri.path();
        let qs   = req.uri.query().map(|q| format!("?{}", q)).unwrap_or_default();

        let location = format!("https://{}{}{}", host, path, qs);
        let mut resp = ResponseHeader::build(http::StatusCode::MOVED_PERMANENTLY, None)?;
        resp.insert_header("location",       &location)?;
        resp.insert_header("content-length", "0")?;
        resp.insert_header("x-served-by",    "kinetic-proxy")?;

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
    let state = Arc::new(ProxyState {
        cfg:           Arc::new(cfg.clone()),
        policy:        Arc::new(PolicyLayer::new(cfg.rate_limit_rps)),
        backend_pool:  Arc::new(UpstreamPool::single(cfg.backend_addr.clone())),
        frontend_pool: Arc::new(UpstreamPool::single(cfg.frontend_addr.clone())),
        s3_pool:       Arc::new(UpstreamPool::single(cfg.rustfs_s3_address.clone())),
        ui_pool:       Arc::new(UpstreamPool::single(cfg.rustfs_ui_address.clone())),
    });

    let proxy = KineticProxy { state };
    let mut svc = http_proxy_service(&server.configuration, proxy);

    if cfg.tls_enabled() {
        let cert_web = cfg.tls_cert_web.as_deref().unwrap();
        let key_web  = cfg.tls_key_web.as_deref().unwrap();

        let mut tls = pingora_core::listeners::tls::TlsSettings::intermediate(cert_web, key_web)
            .expect("Gagal load TLS cert web");

        if let (Some(cert_api), Some(key_api)) = (cfg.tls_cert_api.clone(), cfg.tls_key_api.clone()) {
            use openssl::ssl::{NameType, SslAcceptor, SslFiletype, SslMethod};

            let mut api_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
                .expect("API SslAcceptor gagal");
            api_builder.set_certificate_chain_file(&cert_api).expect("cert API");
            api_builder.set_private_key_file(&key_api, SslFiletype::PEM).expect("key API");
            let api_ctx = api_builder.build().into_context();

            let api_domain = cfg.api_domain.clone();
            tls.set_servername_callback(move |ssl, _| {
                if let Some(sni) = ssl.servername(NameType::HOST_NAME) {
                    let matches = sni == api_domain
                        || sni == format!("www.{}", api_domain)
                        || sni.ends_with(&format!(".{}", api_domain));
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
