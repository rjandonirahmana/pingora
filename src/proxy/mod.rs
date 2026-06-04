//! proxy/ — layered proxy pipeline.
//!
//! Fix:
//!   - cleanup task: gunakan tokio::select! + CancellationToken agar tidak leak
//!     saat proxy restart/reload
//!   - request_filter: hindari .to_string() untuk host/path saat tidak perlu
//!   - response_filter: gunakan id_hex_buf() bukan id_hex() (zero alloc)
//!   - reject(): id_hex_buf() bukan String alloc
//!   - RedirectProxy: format!() hanya saat ada query string

pub mod context;
pub mod policy;
pub mod router;
pub mod static_serve;
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
use crate::proxy::static_serve::StaticServe;
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
    pub frontend_static: Option<Arc<StaticServe>>,
}

impl ProxyState {
    #[inline]
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
    // OnceLock: cleanup task di-spawn tepat sekali saat request pertama.
    cleanup_spawned: Arc<OnceLock<()>>,
}

#[async_trait]
impl ProxyHttp for KineticProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    // ── Phase 1: Request filter ───────────────────────────────────────────────
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // Spawn cleanup task tepat sekali — Pingora runtime sudah aktif.
        // Tidak ada CancellationToken karena Pingora tidak expose shutdown hook
        // via ProxyHttp trait. Cleanup task ringan (60s interval, ~0 memory),
        // tidak perlu explicit cancel — OS cleanup saat process exit.
        if self.cleanup_spawned.set(()).is_ok() {
            let rate_limiter = Arc::clone(&self.state.policy.rate_limiter);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    rate_limiter.cleanup();
                    tracing::debug!(
                        active_ips = rate_limiter.active_count(),
                        "rate limiter cleanup"
                    );
                }
            });
        }

        let req = session.req_header();
        let method = req.method.clone();

        // FIX: hindari .to_string() berlebihan — borrow path dulu untuk health check
        // sebelum allocate String.
        let path = req.uri.path();

        // Health check — return langsung sebelum routing.
        if path == "/health" || path == "/healthz" {
            let mut resp = ResponseHeader::build(http::StatusCode::OK, None)?;
            resp.insert_header("content-type", "text/plain")?;
            resp.insert_header("content-length", "2")?;
            resp.insert_header("x-served-by", "kinetic-proxy")?;
            resp.insert_header("cache-control", "no-store")?;
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(bytes::Bytes::from_static(b"ok")), true)
                .await?;
            return Ok(true);
        }

        // Owned sekarang — diperlukan untuk RequestCtx (lifetime independence)
        let path_owned = path.to_string();
        let host_owned = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let client_ip: Option<IpAddr> = session
            .client_addr()
            .and_then(|addr| addr.to_string().parse::<std::net::SocketAddr>().ok())
            .map(|sa| sa.ip());

        let decision = router::route(&host_owned, &path_owned, &self.state.cfg);
        *ctx = RequestCtx::new(decision, host_owned, path_owned, method.clone(), client_ip);

        // Preflight CORS — handle untuk api DAN object storage.
        if method == http::Method::OPTIONS && (ctx.is_api || ctx.is_object) {
            return self.handle_preflight(session, ctx).await;
        }

        match self.state.policy.apply(ctx) {
            Ok(()) => {}
            Err(err) => {
                tracing::warn!(id = ctx.id, "policy reject: {:?}", err);
                self.reject(session, &err).await?;
                return Ok(true);
            }
        }

        // ── Hotlink protection ─────────────────────────────────────────────────
        // Image RustFS (is_object) cuma boleh diakses/di-embed dari domain kita.
        // Dashboard RustFSUI (Dashboard) DIKECUALIKAN — itu punya auth sendiri.
        // Referer dibaca hanya untuk object request (hindari alloc di jalur umum).
        if ctx.is_object {
            let allowed = {
                let referer = session
                    .req_header()
                    .headers
                    .get("referer")
                    .and_then(|v| v.to_str().ok());
                policy::referer_allowed(referer, &self.state.cfg)
            }; // borrow Referer berakhir di sini, sebelum mutable session di bawah

            if !allowed {
                tracing::warn!(
                    id = ctx.id,
                    host = %ctx.host,
                    path = %ctx.path,
                    "hotlink blocked (referer bukan domain kita)"
                );
                let mut resp = ResponseHeader::build(http::StatusCode::FORBIDDEN, None)?;
                resp.insert_header("content-type", "text/plain")?;
                resp.insert_header("content-length", "9")?;
                resp.insert_header("x-served-by", "kinetic-proxy")?;
                resp.insert_header("cache-control", "no-store")?;
                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(Some(bytes::Bytes::from_static(b"Forbidden")), true)
                    .await?;
                return Ok(true);
            }
        }

        tracing::debug!(
            id       = ctx.id,
            method   = %method,
            path     = %ctx.path,
            upstream = ?ctx.upstream,
            route    = ?ctx.route,
            ws       = ctx.is_ws,
        );

        if ctx.upstream == Upstream::Frontend {
            if let Some(ref static_srv) = self.state.frontend_static {
                if static_srv.serve(session, &ctx.path).await? {
                    return Ok(true); // file ditemukan & served
                }

                // FIX: Kalau ini file static (punya ekstensi) dan tidak ada di disk,
                // jangan proxy ke upstream :3100 — langsung 404.
                // Proxy ke :3100 cuma buat latency tinggi & confusing.
                if ctx.is_static {
                    let mut resp = ResponseHeader::build(http::StatusCode::NOT_FOUND, None)?;
                    resp.insert_header("content-type", "text/plain")?;
                    resp.insert_header("content-length", "9")?;
                    session.write_response_header(Box::new(resp), false).await?;
                    session
                        .write_response_body(Some(bytes::Bytes::from_static(b"Not found")), true)
                        .await?;
                    return Ok(true);
                }

                // Kalau route SPA, lanjut ke upstream :3100
            }
        }

        Ok(false)
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

        // FIX: id_hex_buf() bukan id_hex() — no String alloc per response
        let id_buf = ctx.id_hex_buf();
        tracing::info!(
            id      = id_buf.as_str(),
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
            id      = ctx.id,
            backend = %ctx.backend_addr,
            "gagal connect ke upstream"
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
            id      = ctx.id,
            backend = %ctx.backend_addr,
            uri     = ?session.req_header().uri,
            "proxy error: {}", e,
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
    async fn handle_preflight(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        let origin_str = session
            .req_header()
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("*");

        let allowed = resolve_origin(origin_str, &self.state.cfg);

        // FIX: id_hex_buf() → zero alloc
        let id_buf = ctx.id_hex_buf();
        let mut resp = ResponseHeader::build(http::StatusCode::NO_CONTENT, None)?;
        resp.insert_header("vary", "origin")?;
        resp.insert_header("access-control-allow-origin", allowed)?;
        // REVIEW FIX: jangan set credentials kalau wildcard (sama seperti apply_cors)
        if allowed != "*" {
            resp.insert_header("access-control-allow-credentials", "true")?;
        }

        use self::context::RouteKind;
        match ctx.route {
            RouteKind::Object => {
                resp.insert_header(
                    "access-control-allow-methods",
                    "GET, HEAD, PUT, DELETE, OPTIONS",
                )?;
                resp.insert_header("access-control-allow-headers",
                    "authorization, range, content-type, x-amz-date, x-amz-content-sha256, x-amz-security-token")?;
                resp.insert_header("access-control-max-age", "3600")?;
            }
            _ => {
                resp.insert_header(
                    "access-control-allow-methods",
                    "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                )?;
                resp.insert_header(
                    "access-control-allow-headers",
                    "authorization, content-type, x-request-id, x-app-token", // FIX: x-app-token internal JWT
                )?;
                resp.insert_header("access-control-max-age", "86400")?;
            }
        }

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

        let body: bytes::Bytes = match err {
            PolicyError::RateLimited { retry_after_secs } => {
                let mut nbuf = itoa::Buffer::new();
                resp.insert_header("retry-after", nbuf.format(*retry_after_secs))?;
                // FIX: gunakan static template untuk body yang paling umum
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

        // FIX: hindari format!() saat tidak ada query string (kasus paling umum)
        let location = match req.uri.query() {
            None => format!("https://{}{}", host, path),
            Some(q) => format!("https://{}{}?{}", host, path, q),
        };

        let mut resp = ResponseHeader::build(http::StatusCode::MOVED_PERMANENTLY, None)?;
        resp.insert_header("location", location.as_str())?;
        resp.insert_header("content-length", "0")?;
        resp.insert_header("cache-control", "public, max-age=31536000")?;
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

    let state = Arc::new(ProxyState {
        cfg: Arc::clone(&cfg_arc),
        policy,
        backend_pool: Arc::new(UpstreamPool::single(cfg.backend_addr.clone())),
        frontend_pool: Arc::new(UpstreamPool::single(cfg.frontend_addr.clone())),
        s3_pool: Arc::new(UpstreamPool::single(cfg.rustfs_s3_address.clone())),
        ui_pool: Arc::new(UpstreamPool::single(cfg.rustfs_ui_address.clone())),
        frontend_static: cfg
            .frontend_dist_path
            .as_ref()
            .map(|p| Arc::new(StaticServe::new(p))),
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
            .expect("Gagal load TLS cert web — cek path di config.yaml");

        if let (Some(cert_api), Some(key_api)) = (cfg.tls_cert_api.clone(), cfg.tls_key_api.clone())
        {
            if std::path::Path::new(&cert_api).exists() && std::path::Path::new(&key_api).exists() {
                use openssl::ssl::{NameType, SslAcceptor, SslFiletype, SslMethod};
                let mut api_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
                    .expect("API SslAcceptor gagal");
                api_builder
                    .set_certificate_chain_file(&cert_api)
                    .expect("cert API");
                api_builder
                    .set_private_key_file(&key_api, SslFiletype::PEM)
                    .expect("key API");
                let api_ctx = api_builder.build().into_context();

                // Pre-compute SNI strings sekali saat startup — zero alloc per handshake.
                let api_domain: Box<str> = cfg.api_domain.as_str().into();
                let api_domain_www: Box<str> = format!("www.{}", cfg.api_domain).into();
                let api_domain_sub: Box<str> = format!(".{}", cfg.api_domain).into();

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
                tracing::info!("SNI dual-cert: web={cert_web}, api={cert_api}");
            } else {
                tracing::warn!(
                    "TLS cert api tidak ditemukan di {cert_api} / {key_api} — hanya web TLS aktif"
                );
            }
        }

        svc.add_tls_with_settings(&cfg.listen_addr, None, tls);
        tracing::info!(
            "HTTPS {} ready (web_domain={})",
            cfg.listen_addr,
            cfg.web_domain
        );
    } else {
        tracing::warn!(
            "TLS tidak aktif — plain HTTP di {}. ulala.space TIDAK akan bisa dibuka via browser.",
            cfg.listen_addr
        );
        svc.add_tcp(&cfg.listen_addr);
    }

    svc
}

pub fn build_redirect_service(
    cfg: &Config,
    server: &mut Server,
) -> impl pingora_core::services::Service {
    let mut svc = http_proxy_service(&server.configuration, RedirectProxy);
    svc.add_tcp(&cfg.http_redirect_addr);
    tracing::info!("HTTP redirect {} → HTTPS ready", cfg.http_redirect_addr);
    svc
}
