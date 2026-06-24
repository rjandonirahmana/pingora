//! kinetic-proxy — Cloudflare-style lightweight reverse proxy.
//!
//! Architecture:
//!
//!   Client
//!     ↓
//!   [TLS SNI dual-cert]        ulala.space / ulalaapi.store
//!     ↓
//!   [Router — pure fn]         zero allocation, deterministic
//!     ↓
//!   [Context Builder]          satu struct, dipakai semua layer
//!     ↓
//!   [Policy Layer]             rate limit (token bucket) + WAF
//!     ↓
//!   [Upstream Layer]           timeout per RouteKind
//!     ↓
//!   [Transform Layer]          CORS / Cache / Content-Type / Security headers
//!     ↓
//!   Client
//!
//! FIX:
//!   - Opt::parse_args() bukan Opt::default() → baca CLI args Pingora
//!     (config file, worker threads, upgrade socket, dll)
//!   - Panic hook via tracing → log panic alih-alih stderr raw
//!   - tracing_subscriber with_ansi(false) → container / systemd friendly
//!   - main() return Result → graceful error handling tanpa raw panic
//!   - Server::new error mapping → log fatal sebelum exit
//!   - Komentar SPA fallback → static web server HARUS serve index.html

mod config;
mod proxy;
mod upstream;

use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use tracing_subscriber::{fmt, EnvFilter};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ── Panic hook ─────────────────────────────────────────────────────────────
    // Log panic via tracing alih-alih raw stderr — critical untuk production debugging.
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(target: "panic", "PANIC: {}", info);
        default_panic(info);
    }));

    // ── Logging ───────────────────────────────────────────────────────────────
    // with_ansi(false): log container / systemd tidak perlu ANSI color codes.
    // with_target(true): tunjukkan module path untuk filtering yang presisi.
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,kinetic_proxy=debug")),
        )
        .with_ansi(false)
        .with_target(true)
        .init();

    // ── Config ────────────────────────────────────────────────────────────────
    let cfg = config::Config::load().map_err(|e| {
        tracing::error!("FATAL: gagal load config: {e}");
        e
    })?;

    tracing::info!(
        web    = %cfg.web_domain,
        api    = %cfg.api_domain,
        tls    = cfg.tls_enabled(),
        rps    = cfg.rate_limit_rps,
        "kinetic-proxy starting"
    );
    tracing::info!(
        frontend = %cfg.frontend_addr,
        backend  = %cfg.backend_addr,
        s3       = %cfg.rustfs_s3_address,
        console  = %cfg.rustfs_ui_address,
        "upstreams"
    );

    // ── Pingora server ────────────────────────────────────────────────────────
    // FIX: parse_args() membaca CLI args Pingora (--conf, -t, dll).
    //      Opt::default() ignore semua CLI args → tidak production-ready.
    let opt = Opt::parse_args();
    let mut server = Server::new(Some(opt)).map_err(|e| {
        tracing::error!("FATAL: Server::new gagal: {e}");
        e
    })?;
    server.bootstrap();

    let proxy_svc = proxy::build_proxy_service(&cfg, &mut server);
    let redirect_svc = proxy::build_redirect_service(&cfg, &mut server);

    server.add_service(proxy_svc);
    server.add_service(redirect_svc);

    tracing::info!(
        listen = %cfg.listen_addr,
        redirect = %cfg.http_redirect_addr,
        "kinetic-proxy ready — waiting for connections"
    );

    // ── Run ───────────────────────────────────────────────────────────────────
    // run_forever() blocking sampai SIGTERM/SIGINT.
    // Pingora handle signal & graceful shutdown internal.
    server.run_forever();
}
