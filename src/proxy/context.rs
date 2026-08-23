//! RequestCtx — central state untuk satu request.
//! Diisi sekali, dibaca di semua layer. Zero recompute.
//!
//! Optimasi dari original:
//!   - host, path: tetap String (dibaca dari Session header, harus owned untuk lifetime)
//!   - client_ip_str: SmolStr — stack-allocated untuk IPv4/IPv6 str (max 45 chars)
//!   - backend_addr: SmolStr — addr upstream biasanya pendek (e.g. "127.0.0.1:8080")
//!   - id_hex(): tidak return String baru — tulis ke stack buffer caller via id_hex_buf()
//!   - Tambahan id_hex_bytes() untuk insert_header tanpa intermediate String

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use http::Method;
use smol_str::SmolStr;

use crate::proxy::router::RouteDecision;
use crate::upstream::Upstream;

static REQ_COUNTER: AtomicU64 = AtomicU64::new(1);

#[inline]
pub fn next_id() -> u64 {
    REQ_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ─── RouteKind ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Api,
    Websocket,
    Static,
    Object,
    Dashboard,
    /// PPM AFM (app Leptos SSR terpisah). BUKAN Static → CSP/COOP/MIME/cache
    /// khusus-frontend ulala TIDAK diterapkan (ppm kelola sendiri + pakai
    /// leptos/nonce). Timeout longgar utk SSE + siaran audio chunked.
    Ppm,
    /// Panel admin WhatsApp — diperlakukan sama dengan [`RouteKind::Ppm`]:
    /// jangan disentuh header frontend-nya, dan beri timeout longgar.
    WaAdmin,
    /// Gitea — sama seperti dua di atas: aplikasi pihak lain yang mengurus
    /// MIME/cache/CSP-nya sendiri.
    ///
    /// Timeout longgar di sini BUKAN kemewahan: `git push` mengirim satu badan
    /// permintaan yang bisa berukuran ratusan MB dan `git clone` repo besar
    /// membuat server menghitung pack cukup lama sebelum satu byte pun terkirim.
    /// Dengan timeout ketat, keduanya putus di tengah dan terbaca sebagai
    /// "push gagal" tanpa sebab yang jelas.
    Gitea,
}

impl RouteKind {
    pub fn from_decision(decision: &RouteDecision) -> Self {
        match decision.upstream {
            Upstream::Backend if decision.is_ws => RouteKind::Websocket,
            Upstream::Backend => RouteKind::Api,
            Upstream::Frontend => RouteKind::Static,
            Upstream::RustFS3 => RouteKind::Object,
            Upstream::RustFSUI => RouteKind::Dashboard,
            Upstream::Ppm => RouteKind::Ppm,
            // Panel admin WA disamakan dengan PPM: sama-sama aplikasi pihak
            // lain yang mengurus MIME/cache/CSP-nya sendiri, dan dasbornya
            // lazim memakai koneksi panjang (polling status sesi WhatsApp).
            Upstream::WaAdmin => RouteKind::WaAdmin,
            Upstream::Gitea => RouteKind::Gitea,
        }
    }
}

// ─── TimeoutConfig ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct TimeoutConfig {
    pub connect_secs: u64,
    pub read_secs: u64,
    pub write_secs: u64,
}

impl TimeoutConfig {
    pub fn for_route(kind: RouteKind) -> Self {
        match kind {
            RouteKind::Websocket => Self {
                connect_secs: 10,
                read_secs: 3600,
                write_secs: 3600,
            },
            RouteKind::Api => Self {
                connect_secs: 5,
                read_secs: 60,
                write_secs: 30,
            },
            RouteKind::Object => Self {
                connect_secs: 5,
                read_secs: 120,
                write_secs: 120,
            },
            RouteKind::Static => Self {
                connect_secs: 3,
                read_secs: 30,
                write_secs: 10,
            },
            RouteKind::Dashboard => Self {
                connect_secs: 5,
                read_secs: 60,
                write_secs: 30,
            },
            // PPM: SSE (/api/live-events) + siaran audio chunked (poll/download)
            // bersifat long-lived → read/write longgar seperti Websocket.
            RouteKind::Ppm | RouteKind::WaAdmin => Self {
                connect_secs: 10,
                read_secs: 3600,
                write_secs: 3600,
            },
            // Gitea: `git push` mengirim satu badan permintaan yang bisa
            // ratusan MB, dan `git clone` repo besar membuat server menghitung
            // pack cukup lama SEBELUM satu byte pun terkirim balik. Keduanya
            // tampak seperti koneksi menganggur bagi proxy — dengan timeout
            // ketat mereka diputus di tengah dan terbaca sebagai "push gagal"
            // tanpa sebab yang jelas. Samakan dengan long-lived di atas.
            RouteKind::Gitea => Self {
                connect_secs: 10,
                read_secs: 3600,
                write_secs: 3600,
            },
        }
    }
}

// ─── HexBuf — stack-allocated 16-char hex string ─────────────────────────────

/// Buffer stack untuk format "{:016x}" — 16 bytes, no heap allocation.
pub struct HexBuf([u8; 16]);

impl HexBuf {
    pub fn as_str(&self) -> &str {
        // Safety: kita tulis ASCII hex digits saja
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

// ─── RequestCtx ──────────────────────────────────────────────────────────────

pub struct RequestCtx {
    // Identity
    pub id: u64,
    pub started_at: Instant,

    // Routing
    pub upstream: Upstream,
    pub route: RouteKind,
    pub timeout: TimeoutConfig,

    // Request info — host & path harus String (owned untuk lifetime independence)
    pub host: String,
    pub path: String,
    pub method: Method,

    // Flags
    pub is_ws: bool,
    pub is_static: bool,
    pub is_api: bool,
    pub is_object: bool,

    // Transform
    pub strip_prefix: Option<&'static str>,

    // Client info
    pub client_ip: Option<IpAddr>,
    // SmolStr: stack-allocated jika ≤ 22 bytes (cukup untuk semua IPv4 "255.255.255.255:65535"
    // dan IPv6 "::1" dll). Tidak ada heap alloc untuk kasus umum.
    pub client_ip_str: SmolStr,

    // Backend addr yang terpilih — SmolStr: "127.0.0.1:8080" = 14 bytes, fits on stack.
    pub backend_addr: SmolStr,

    // Retry counter
    pub attempts: u8,
}

impl RequestCtx {
    pub fn new(
        decision: RouteDecision,
        host: String,
        path: String,
        method: Method,
        client_ip: Option<IpAddr>,
    ) -> Self {
        let route = RouteKind::from_decision(&decision);
        let timeout = TimeoutConfig::for_route(route);

        // SmolStr::new() — stack jika ≤ 22 chars (true untuk semua IP string)
        let client_ip_str = client_ip
            .map(|ip| SmolStr::new(ip.to_string()))
            .unwrap_or_default();

        Self {
            id: next_id(),
            started_at: Instant::now(),
            upstream: decision.upstream,
            route,
            timeout,
            host,
            path,
            method,
            is_ws: decision.is_ws,
            // FIX: is_static harus path-based (punya ekstensi file) bukan route-based.
            // Sebelumnya: matches!(route, RouteKind::Static) → true untuk SEMUA frontend
            // termasuk SPA routes (/explore, /pulse, /events) yang harusnya no-cache.
            // Akibatnya: HTML page di-cache "immutable" → browser tidak fetch bundle baru
            // saat redeploy, dan WASM/JS hashes lama → app gagal load.
            is_static: decision.is_static, // dari is_static_path() di router.rs
            is_api: matches!(route, RouteKind::Api | RouteKind::Websocket),
            is_object: matches!(route, RouteKind::Object),
            strip_prefix: decision.strip_prefix,
            client_ip,
            client_ip_str,
            backend_addr: SmolStr::default(), // diisi di upstream_peer
            attempts: 0,
        }
    }

    #[inline]
    pub fn elapsed_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }

    /// Zero-alloc hex ID: tulis ke stack buffer, return reference.
    /// Gunakan ini di insert_header() daripada id_hex() yang return String.
    #[inline]
    pub fn id_hex_buf(&self) -> HexBuf {
        let mut buf = [0u8; 16];
        // Manual hex encoding ke stack buffer — no format!, no alloc
        let id = self.id;
        const HEX: &[u8] = b"0123456789abcdef";
        for i in 0..8 {
            let byte = ((id >> ((7 - i) * 8)) & 0xff) as u8;
            buf[i * 2] = HEX[(byte >> 4) as usize];
            buf[i * 2 + 1] = HEX[(byte & 0xf) as usize];
        }
        HexBuf(buf)
    }

    /// Backward compat — dipakai di logging. Untuk insert_header pakai id_hex_buf().
    #[inline]
    pub fn id_hex(&self) -> String {
        format!("{:016x}", self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_buf_matches_format_macro() {
        for id in [0u64, 1, 0x1234, 0xdeadbeef, u64::MAX] {
            let ctx = RequestCtx { id, ..RequestCtx::default() };
            assert_eq!(
                ctx.id_hex_buf().as_str(),
                ctx.id_hex().as_str(),
                "id_hex_buf mismatch untuk id={id:#x}"
            );
        }
    }

    #[test]
    fn hex_buf_known_values() {
        let ctx = RequestCtx { id: 0, ..RequestCtx::default() };
        assert_eq!(ctx.id_hex_buf().as_str(), "0000000000000000");

        let ctx = RequestCtx { id: 0x1234, ..RequestCtx::default() };
        assert_eq!(ctx.id_hex_buf().as_str(), "0000000000001234");

        let ctx = RequestCtx { id: u64::MAX, ..RequestCtx::default() };
        assert_eq!(ctx.id_hex_buf().as_str(), "ffffffffffffffff");
    }
}

impl Default for RequestCtx {
    fn default() -> Self {
        Self {
            id: 0,
            started_at: Instant::now(),
            upstream: Upstream::Frontend,
            route: RouteKind::Static,
            timeout: TimeoutConfig::for_route(RouteKind::Static),
            host: String::new(),
            path: String::new(),
            method: Method::GET,
            is_ws: false,
            is_static: false, // FIX: default false, bukan true
            is_api: false,
            is_object: false,
            strip_prefix: None,
            client_ip: None,
            client_ip_str: SmolStr::default(),
            backend_addr: SmolStr::default(),
            attempts: 0,
        }
    }
}
