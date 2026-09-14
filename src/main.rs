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
    // Default `info`: di produksi level DEBUG membanjiri log (satu baris per
    // request `id=… method=…` + `rate limiter cleanup` tiap menit). Untuk
    // debugging, override via env: `RUST_LOG=info,kinetic_proxy=debug`.
    fmt()
        .with_env_filter(filter_log())
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

/// Filter log: level dari `RUST_LOG` (bawaan `info`), ditambah peredam untuk
/// tiga target pingora yang HANYA melaporkan ulah klien.
///
/// ── KENAPA INI ADA ──────────────────────────────────────────────────────────
/// Port 443 yang terbuka di internet diketuk terus-menerus oleh pemindai. Tiap
/// ketukan menghasilkan satu baris ERROR, dan tak satu pun di antaranya berarti
/// ada yang salah di server ini:
///
///   pingora_core::services::listening  "TLSHandshakeFailure ... unsupported
///     protocol / no shared cipher / version too low / unexpected EOF /
///     Connection reset" — pemindai mencoba SSLv3/TLS1.0 atau memutus di tengah
///     handshake. Server menolak dengan benar; penolakan itulah yang dicatat.
///
///   pingora_core::apps  "H2 handshake error ... connection closed before
///     reading preface" — klien menutup koneksi sebelum bicara. Termasuk browser
///     asli yang pindah halaman.
///
///   pingora_proxy  "Fail to proxy: ..." dan "Downstream InvalidHTTPHeader
///     buf: \x16\x03\x01..." — yang terakhir itu ClientHello TLS yang dikirim ke
///     port 80, probe RDP (`Cookie: mstshash=`), preface h2c, atau URI eksploit
///     PHP. Semuanya sampah sebelum HTTP terbentuk. Barisnya juga menempelkan
///     RIBUAN byte hex ke log untuk satu paket sampah.
///
/// Yang HILANG dari `pingora_proxy` hanyalah duplikat: setiap kegagalan yang
/// benar-benar milik kita sudah dicatat oleh `kinetic_proxy` sendiri —
/// `error_while_proxy` (dengan id, backend, uri) dan `fail_to_connect`. Kalau
/// keduanya diam, memang tak ada permintaan yang gagal.
///
/// Bahayanya kalau tidak dilakukan: `Upstream ReadTimedout` — SATU-SATUNYA baris
/// yang berarti app di belakang benar-benar tak menjawab — tenggelam di antara
/// ratusan baris pemindai, dan insiden 8 Sep 2026 memakan waktu berjam-jam untuk
/// dilihat.
///
/// Kembalikan semuanya saat perlu memeriksa TLS/handshake: `PROXY_LOG_NOISE=1`.
/// Target pingora yang diredam. Dipisah jadi konstanta supaya ada satu tempat
/// untuk diubah, dan supaya sebuah test bisa membuktikan ketiganya masih terurai
/// — salah ketik di sini tidak akan menggagalkan build, hanya diam-diam gagal
/// meredam.
const PEREDAM: [&str; 3] = [
    "pingora_core::services::listening=off",
    "pingora_core::apps=off",
    "pingora_proxy=off",
];

fn filter_log() -> EnvFilter {
    let dasar = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if std::env::var("PROXY_LOG_NOISE").is_ok_and(|v| v == "1") {
        return dasar;
    }

    // Ditambahkan SESUDAH `RUST_LOG` dibaca, dan itu disengaja: env produksi
    // menyetel `RUST_LOG=info` secara eksplisit, jadi mengubah nilai bawaan saja
    // tak akan mengubah apa pun di server.
    PEREDAM
        .iter()
        .copied()
        .fold(dasar, |f, d| match d.parse() {
            Ok(d) => f.add_directive(d),
            // Direktif ini konstanta; kalau suatu saat salah ketik, lebih baik
            // log tetap jalan apa adanya daripada proxy menolak start.
            Err(e) => {
                eprintln!("filter log '{d}' tak valid, dilewati: {e}");
                f
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direktif_peredam_terurai() {
        for d in PEREDAM {
            assert!(
                d.parse::<tracing_subscriber::filter::Directive>().is_ok(),
                "direktif log '{d}' tak terurai — peredam gagal diam-diam"
            );
        }
    }
}
