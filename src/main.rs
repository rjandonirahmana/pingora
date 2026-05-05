//! kinetic-proxy — entry point
//!
//! Menjalankan dua service Pingora:
//!   1. proxy_service   — HTTPS :443  (SNI dual-cert, routing dua domain)
//!   2. redirect_service — HTTP  :80  (301 → HTTPS untuk semua domain)
//!
//! Arsitektur akhir:
//!
//!  ┌─────────────┐
//!  │   Internet  │
//!  └──────┬──────┘
//!         │ :80 / :443
//!         ▼
//!  ┌──────────────────────────────────────────────┐
//!  │           KineticProxy (Pingora)             │
//!  │                                              │
//!  │  :80  → 301 https://$host$request_uri        │
//!  │                                              │
//!  │  :443 ulala.space       /*       → :3100     │
//!  │  :443 ulalaapi.store    /api/ws/ → :8080 WS  │
//!  │  :443 ulalaapi.store    /api/    → :8080 REST │
//!  │  :443 ulalaapi.store    /image/  → :3902      │
//!  │                                              │
//!  │  TLS: SNI → pilih cert per domain            │
//!  └──────────────────────────────────────────────┘

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
        .init();

    // ── Konfigurasi ───────────────────────────────────────────────────────────
    let cfg = config::Config::load();
    tracing::info!(
        "Config: web={} api={} tls={}",
        cfg.web_domain,
        cfg.api_domain,
        cfg.tls_enabled()
    );
    tracing::info!(
        "Upstreams: frontend={} backend={} image={}",
        cfg.frontend_addr,
        cfg.backend_addr,
        cfg.image_addr
    );

    // ── Pingora server ────────────────────────────────────────────────────────
    let opt = Opt::default();
    let mut server = Server::new(Some(opt)).expect("Server::new gagal");
    server.bootstrap();

    // ── Service 1: HTTPS reverse proxy (:443) ─────────────────────────────────
    let proxy_svc = proxy::build_proxy_service(&cfg, &mut server);
    server.add_service(proxy_svc);

    // ── Service 2: HTTP → HTTPS redirect (:80) ────────────────────────────────
    let redirect_svc = proxy::build_redirect_service(&cfg, &mut server);
    server.add_service(redirect_svc);

    tracing::info!("kinetic-proxy siap.");
    server.run_forever();
}
