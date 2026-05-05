//! kinetic-proxy — Cloudflare-style lightweight reverse proxy.
//!
//! Architecture:
//!
//!  Client
//!    ↓
//!  [TLS SNI dual-cert]        ulala.space / ulalaapi.store
//!    ↓
//!  [Router — pure fn]         zero allocation, deterministic
//!    ↓
//!  [Context Builder]          satu struct, dipakai semua layer
//!    ↓
//!  [Policy Layer]             rate limit (token bucket) + WAF
//!    ↓
//!  [Upstream Layer]           timeout per RouteKind
//!    ↓
//!  [Transform Layer]          CORS / Cache / Content-Type / Security headers
//!    ↓
//!  Client

mod config;
mod proxy;
mod upstream;

use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use tracing_subscriber::{fmt, EnvFilter};

fn main() {
    // ── Logging ───────────────────────────────────────────────────────────────
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,kinetic_proxy=debug")),
        )
        .compact()
        .init();

    // ── Config ────────────────────────────────────────────────────────────────
    let cfg = config::Config::load();

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
    let opt = Opt::default();
    let mut server = Server::new(Some(opt)).expect("Server::new gagal");
    server.bootstrap();

    let proxy_svc = proxy::build_proxy_service(&cfg, &mut server);
    let redirect_svc = proxy::build_redirect_service(&cfg, &mut server);

    server.add_service(proxy_svc);
    server.add_service(redirect_svc);

    tracing::info!("kinetic-proxy ready");
    server.run_forever();
}
