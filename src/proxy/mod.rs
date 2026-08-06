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

use tokio_util::sync::CancellationToken;

use async_trait::async_trait;
use pingora_core::prelude::*;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{ErrorSource, ErrorType};
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
    pub ppm_pool: Arc<UpstreamPool>,
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
            Upstream::Ppm => &self.ppm_pool,
        }
    }
}

// ─── KineticProxy ─────────────────────────────────────────────────────────────

pub struct KineticProxy {
    state: Arc<ProxyState>,
    // OnceLock: cleanup task di-spawn tepat sekali saat request pertama.
    cleanup_spawned: Arc<OnceLock<()>>,
    // Token untuk stop cleanup task saat KineticProxy di-drop (graceful shutdown).
    cleanup_token: CancellationToken,
}

impl Drop for KineticProxy {
    fn drop(&mut self) {
        self.cleanup_token.cancel();
    }
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
            let token = self.cleanup_token.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = token.cancelled() => {
                            tracing::info!("rate limiter cleanup task stopped");
                            break;
                        }
                        _ = interval.tick() => {
                            rate_limiter.cleanup();
                            tracing::debug!(
                                active_ips = rate_limiter.active_count(),
                                "rate limiter cleanup"
                            );
                        }
                    }
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
        // Host: HTTP/1.1 mengirim header `Host`, tapi HTTP/2 (semua browser https)
        // menaruh authority di pseudo-header `:authority` → header `host` kerap
        // KOSONG. Ambil header dulu, fallback ke URI authority. Tanpa fallback ini,
        // Host allowlist di bawah menolak SEMUA request H2 (host kosong) → seluruh
        // situs balas 421 "Not found".
        let host_owned = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .filter(|h| !h.is_empty())
            .or_else(|| req.uri.host())
            .unwrap_or("")
            .to_string();

        let client_ip: Option<IpAddr> = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|sa| sa.ip());

        // Host allowlist — tolak Host asing SEBELUM menyentuh backend. Scanner
        // internet menghantam IP:443 kita dengan Host acak (IP mentah,
        // *.serviciodepaginasweb.cl, dll); rule fallback #10 dulu meneruskannya ke
        // Frontend :3100 → koneksi backend terbuang + circuit breaker berputar.
        // 421 Misdirected Request: benar secara semantik & memberitahu client sah
        // (yang salah sambung SNI/Host) untuk membuka koneksi baru.
        // Fail-open bila host tak terdeteksi (kosong): jangan pernah menjatuhkan
        // seluruh situs hanya karena host tak terbaca — cukup tolak host yang
        // JELAS ada dan bukan milik kita.
        if !host_owned.is_empty() && !router::is_known_host(&host_owned, &self.state.cfg) {
            tracing::debug!(host = %host_owned, path = %path_owned, "reject unknown host");
            let mut resp = ResponseHeader::build(http::StatusCode::MISDIRECTED_REQUEST, None)?;
            resp.insert_header("content-type", "text/plain")?;
            resp.insert_header("content-length", "9")?;
            resp.insert_header("x-served-by", "kinetic-proxy")?;
            resp.insert_header("cache-control", "no-store")?;
            resp.insert_header("connection", "close")?;
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(bytes::Bytes::from_static(b"Not found")), true)
                .await?;
            return Ok(true);
        }

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
        // Hanya error UPSTREAM (backend benar-benar gagal) yang menghukum circuit
        // breaker. Error DOWNSTREAM (client mutus koneksi: "ConnectionClosed",
        // "H2 stream no longer needed", "Connection reset by peer") BUKAN salah
        // backend — scanner/bot yang connect lalu putus tak boleh membuka breaker
        // & merusak routing untuk user asli.
        if e.esource == ErrorSource::Upstream {
            if let Some(backend) = self.state.pool_for(ctx.upstream).find(&ctx.backend_addr) {
                backend.breaker.record_failure();
            }
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

        // FIX: gunakan path_and_query() — sudah percent-encoded dari URI asli.
        // format!("?{}", q) dari req.uri.query() bisa produce invalid URL
        // jika query string mengandung spasi atau karakter khusus lain.
        let pq = req.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(path);
        let location = format!("https://{}{}", host, pq);

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

/// Satu cert non-default beserta nama SNI yang boleh memakainya.
///
/// Nama dihitung sekali saat startup (bukan `format!` per handshake) karena
/// callback SNI berjalan di jalur terpanas yang ada: tiap koneksi TLS baru.
struct SniCert {
    /// Nama persis (domain + www-nya).
    exact: Vec<Box<str>>,
    /// Akhiran ".domain" untuk mencakup seluruh subdomain — hanya diisi bila
    /// certnya memang mencakup mereka.
    suffix: Option<Box<str>>,
    ctx: openssl::ssl::SslContext,
}

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
        // Bisa lebih dari satu instans app PPM: UpstreamPool sudah round-robin
        // + circuit breaker per-alamat, jadi load balancing di sini cukup soal
        // memberinya daftar, bukan kode penyeimbang baru.
        ppm_pool: Arc::new(UpstreamPool::new(cfg.ppm_upstreams())),
        frontend_static: cfg
            .frontend_dist_path
            .as_ref()
            .map(|p| Arc::new(StaticServe::new(p))),
    });

    let proxy = KineticProxy {
        state,
        cleanup_spawned: Arc::new(OnceLock::new()),
        cleanup_token: CancellationToken::new(),
    };
    let mut svc = http_proxy_service(&server.configuration, proxy);

    if cfg.tls_enabled() {
        let cert_web = cfg.tls_cert_web.as_deref().unwrap();
        let key_web = cfg.tls_key_web.as_deref().unwrap();

        let mut tls = pingora_core::listeners::tls::TlsSettings::intermediate(cert_web, key_web)
            .expect("Gagal load TLS cert web — cek path di config.yaml");

        // ── HTTP/2 untuk domain web (ulala.space) ──────────────────────────────
        // Set ALPN "h2,http/1.1" di listener web. Ini yang bikin lazy WASM chunk
        // kamu ter-multiplex dalam 1 koneksi (tidak kena limit 6-koneksi & HOL h1).
        // SELURUH keuntungan WASM ada di domain ini.
        //
        // CATATAN WEBSOCKET (wajib test):
        //   FE kamu pakai wss://ulala.space/api/ws → lewat listener ini.
        //   WS adalah HTTP/1.1 Upgrade. Browser modern membuka koneksi h1 terpisah
        //   untuk WS walau ALPN menawarkan h2 (Pingora tidak meng-advertise
        //   SETTINGS_ENABLE_CONNECT_PROTOCOL), jadi normalnya chat tetap jalan.
        //   ROLLBACK 1 baris kalau chat putus: comment baris enable_h2() di bawah.
        tls.enable_h2();

        // ── Cert tambahan per-SNI ─────────────────────────────────────────────
        // Cert web adalah default (fallthrough). Domain lain yang punya cert
        // sendiri didaftarkan di sini; SNI yang tak cocok satu pun tetap
        // dilayani cert web — itu yang membuat subdomain seperti
        // ppm.ulala.space cukup menumpang SAN cert web.
        let mut sni_certs: Vec<SniCert> = Vec::new();

        if let (Some(cert_api), Some(key_api)) = (cfg.tls_cert_api.clone(), cfg.tls_key_api.clone())
        {
            if std::path::Path::new(&cert_api).exists() && std::path::Path::new(&key_api).exists() {
                use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
                let mut api_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
                    .expect("API SslAcceptor gagal");
                api_builder
                    .set_certificate_chain_file(&cert_api)
                    .expect("cert API");
                api_builder
                    .set_private_key_file(&key_api, SslFiletype::PEM)
                    .expect("key API");

                // ── (OPSIONAL) HTTP/2 untuk domain API (ulalaapi.store) ─────────
                // Default: DIMATIKAN. API domain tetap h1.
                // Alasan: keuntungan h2 di REST kecil, tapi nambah risiko untuk
                //   WS yang juga lewat ulalaapi.store/api/ws. Image/REST/WS kamu
                //   sudah terbukti jalan di h1 → jangan diutak-atik tanpa alasan.
                //
                // Aktifkan HANYA kalau kamu benar-benar butuh multiplexing di API
                // domain DAN sudah test WS chat lewat domain ini. Caranya:
                // uncomment blok di bawah (imports-nya self-contained di sini).
                //
                // use openssl::ssl::{select_next_proto, AlpnError};
                // api_builder.set_alpn_select_callback(|_ssl, client| {
                //     // Prioritas h2, fallback http/1.1. Wire format: len-prefixed.
                //     select_next_proto(b"\x02h2\x08http/1.1", client)
                //         .ok_or(AlpnError::NOACK)
                // });

                // Pre-compute SNI strings sekali saat startup — zero alloc per handshake.
                sni_certs.push(SniCert {
                    exact: vec![
                        cfg.api_domain.as_str().into(),
                        format!("www.{}", cfg.api_domain).into(),
                    ],
                    // Semua subdomain api (image., ui.) ada di cert yang sama.
                    suffix: Some(format!(".{}", cfg.api_domain).into()),
                    ctx: api_builder.build().into_context(),
                });
                tracing::info!("SNI cert api={cert_api}");
            } else {
                tracing::warn!(
                    "TLS cert api tidak ditemukan di {cert_api} / {key_api} — hanya web TLS aktif"
                );
            }
        }

        // ── Cert PPM (ppm-afm.com) ────────────────────────────────────────────
        // Domain berdiri sendiri, jadi TIDAK bisa menumpang cert web seperti
        // ppm.ulala.space dulu. Hanya domain UTAMA + www yang didaftarkan di
        // sini: alias di `ppm_domains` sengaja jatuh ke cert web, karena
        // cert ppm-afm.com tak mencakupnya dan menyajikannya ke sana justru
        // membuat browser menolak koneksi.
        if let (Some(cert_ppm), Some(key_ppm)) = (cfg.tls_cert_ppm.clone(), cfg.tls_key_ppm.clone())
        {
            if cfg.ppm_domain.is_empty() {
                tracing::warn!("tls_cert_ppm diisi tapi ppm_domain kosong — cert PPM diabaikan");
            } else if std::path::Path::new(&cert_ppm).exists()
                && std::path::Path::new(&key_ppm).exists()
            {
                use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
                let mut b =
                    SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("PPM SslAcceptor");
                b.set_certificate_chain_file(&cert_ppm).expect("cert PPM");
                b.set_private_key_file(&key_ppm, SslFiletype::PEM)
                    .expect("key PPM");
                sni_certs.push(SniCert {
                    exact: vec![
                        cfg.ppm_domain.as_str().into(),
                        format!("www.{}", cfg.ppm_domain).into(),
                    ],
                    suffix: None,
                    ctx: b.build().into_context(),
                });
                tracing::info!("SNI cert ppm={cert_ppm} (domain={})", cfg.ppm_domain);
            } else {
                tracing::warn!(
                    "TLS cert ppm tidak ditemukan di {cert_ppm} / {key_ppm} — {} akan disajikan cert web (browser menolak)",
                    cfg.ppm_domain
                );
            }
        }

        if !sni_certs.is_empty() {
            use openssl::ssl::NameType;
            tls.set_servername_callback(move |ssl, _| {
                if let Some(sni) = ssl.servername(NameType::HOST_NAME) {
                    for c in &sni_certs {
                        let cocok = c.exact.iter().any(|d| &**d == sni)
                            || c.suffix.as_deref().is_some_and(|s| sni.ends_with(s));
                        if cocok {
                            ssl.set_ssl_context(&c.ctx)
                                .map_err(|_| openssl::ssl::SniError::NOACK)?;
                            break;
                        }
                    }
                }
                // Tak ada yang cocok → biarkan cert web (default listener).
                Ok(())
            });
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
