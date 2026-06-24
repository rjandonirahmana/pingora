//! Policy layer — rate limiting, WAF dasar, header validation.
//!
//! Fix dari original:
//!   - Bucket::try_consume(): load+check+sub → CAS loop (fix underflow race condition)
//!   - Bucket refill: fetch_add+cap → fetch_update dengan .min(capacity) (fix overflow race)
//!   - Bucket refill: gunakan compare_exchange pada last_refill (fix double-refill race)
//!   - PolicyLayer::apply(): panggil waf_check untuk semua request, bukan hanya is_api
//!   - waf_check(): hapus /.well-known/security.txt dari blocklist (false positive)

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use crate::config::Config;
use crate::proxy::context::RequestCtx;

// Hard cap jumlah IP di rate limiter — cegah OOM saat DDoS IP spoofing.
// 100k entry × ~64 bytes/entry ≈ 6.4MB max.
const MAX_BUCKETS: usize = 100_000;

// Saat tabel penuh, bucket yang idle melebihi ambang ini di-evict inline agar
// IP baru yang sah tidak ke-lockout sampai cleanup periodik (1 jam) berjalan.
const EVICT_IDLE_SECS: u64 = 300; // 5 menit

// ─── PolicyError ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum PolicyError {
    RateLimited {
        retry_after_secs: u64,
    },
    BlockedIp,
    /// &'static str: zero alloc — semua reason adalah string literal
    SuspiciousRequest(&'static str),
}

// ─── Rate Limiter (Token Bucket) ──────────────────────────────────────────────

struct Bucket {
    tokens: AtomicU32,
    last_refill: AtomicU64, // unix seconds — kapan token terakhir di-refill
    last_seen: AtomicU64,   // unix seconds — kapan request terakhir diterima
}

impl Bucket {
    fn new(capacity: u32) -> Self {
        let now = now_secs();
        Self {
            tokens: AtomicU32::new(capacity),
            last_refill: AtomicU64::new(now),
            last_seen: AtomicU64::new(now),
        }
    }

    fn try_consume(&self, capacity: u32, refill_per_sec: u32) -> bool {
        // Catat waktu request ini — dipakai eviction (bukan last_refill yang
        // hanya update saat ada token yang ditambahkan).
        self.last_seen.store(now_secs(), Ordering::Relaxed);

        let now = now_secs();
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(last);

        // Refill tokens jika ada waktu berlalu.
        // FIX: gunakan compare_exchange pada last_refill agar hanya 1 thread yang refill.
        // Tanpa ini: thread A dan B sama-sama baca last=T, keduanya hitung refill, keduanya
        // store → double refill (token bisa melebihi capacity secara efektif).
        if elapsed > 0 {
            let refill = (elapsed as u32)
                .saturating_mul(refill_per_sec)
                .min(capacity);
            if refill > 0 {
                // Hanya thread yang menang CAS yang boleh refill.
                if self
                    .last_refill
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    self.tokens
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                            Some(cur.saturating_add(refill).min(capacity))
                        })
                        .ok();
                }
                // Thread yang kalah CAS: last_refill sudah diupdate thread lain, skip refill.
            }
        }

        // FIX: CAS loop — atomic compare-and-swap, tidak ada race condition underflow
        loop {
            let cur = self.tokens.load(Ordering::Relaxed);
            if cur == 0 {
                return false;
            }
            match self.tokens.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue, // retry jika ada thread lain yang modify lebih cepat
            }
        }
    }
}

pub struct RateLimiter {
    // DashMap: sharded RwLock internal — concurrent reads & writes tanpa global lock.
    // Jauh lebih cepat dari Arc<RwLock<HashMap>> di high-concurrency.
    buckets: Arc<DashMap<IpAddr, Arc<Bucket>>>,
    capacity: u32,
    refill_per_sec: u32,
}

impl RateLimiter {
    pub fn new(rps: u64) -> Self {
        let rps = rps as u32;
        Self {
            buckets: Arc::new(DashMap::with_capacity(1024)),
            capacity: rps * 3,
            refill_per_sec: rps,
        }
    }

    /// Sync check — tidak blocking, DashMap pakai sharded lock internal.
    pub fn check(&self, ip: IpAddr) -> Result<(), PolicyError> {
        // Fast path: IP sudah ada di map — read lock per shard saja
        if let Some(bucket) = self.buckets.get(&ip) {
            return if bucket.try_consume(self.capacity, self.refill_per_sec) {
                Ok(())
            } else {
                Err(PolicyError::RateLimited {
                    retry_after_secs: 1,
                })
            };
        }

        // Slow path: IP baru — cek cap dulu sebelum insert.
        if self.buckets.len() >= MAX_BUCKETS {
            // Tabel penuh. Sebelum menolak, coba evict bucket yang sudah idle
            // beberapa menit (bukan menunggu cleanup periodik yang ambangnya 1 jam).
            // Ini menahan kasus umum: tabel terisi burst sesaat lalu IP-nya pergi —
            // tanpa eviction, slot mereka mengunci IP baru yang sah selama 1 jam.
            //
            // CATATAN JUJUR soal batas efektivitas:
            //   - Ini BUKAN obat DDoS. Kalau 100k bucket semuanya AKTIF (tiap IP
            //     terus mengirim), tidak ada yang idle → tidak ada yang ter-evict →
            //     IP baru tetap ditolak. Itu memang perilaku yang benar saat flood.
            //   - Source IP TCP tidak bisa di-spoof (handshake harus selesai), jadi
            //     mengisi 100k bucket butuh 100k IP nyata (botnet), bukan spoofing.
            self.evict_stale(EVICT_IDLE_SECS);

            if self.buckets.len() >= MAX_BUCKETS {
                // Masih penuh setelah eviction → flood IP aktif. Tolak (lindungi memory).
                return Err(PolicyError::RateLimited {
                    retry_after_secs: 60,
                });
            }
        }

        // entry().or_insert_with() is atomic per shard:
        //   - Only one thread inserts a new bucket for a given IP.
        //   - Concurrent threads for the same IP get the existing bucket.
        //   - try_consume() result is correctly propagated (fixes silent discard bug).
        let allowed = self
            .buckets
            .entry(ip)
            .or_insert_with(|| Arc::new(Bucket::new(self.capacity)))
            .try_consume(self.capacity, self.refill_per_sec);

        if allowed {
            Ok(())
        } else {
            Err(PolicyError::RateLimited { retry_after_secs: 1 })
        }
    }

    /// Hapus bucket yang idle lebih lama dari `idle_secs`. Return jumlah yang dihapus.
    /// Dipakai oleh cleanup periodik (idle 1 jam) dan eviction inline saat tabel
    /// penuh (idle 5 menit).
    ///
    /// FIX: pakai `last_seen` bukan `last_refill` untuk eviction.
    /// `last_refill` hanya update saat ada token baru (tergantung refill_per_sec).
    /// IP yang membuat 1 req/jam bisa memiliki last_refill yang tidak pernah update
    /// kalau refill threshold > waktu antar request. `last_seen` update setiap request.
    fn evict_stale(&self, idle_secs: u64) -> usize {
        let cutoff = now_secs().saturating_sub(idle_secs);
        let before = self.buckets.len();
        self.buckets
            .retain(|_, bucket| bucket.last_seen.load(Ordering::Relaxed) > cutoff);
        before - self.buckets.len()
    }

    /// Hapus bucket yang tidak aktif > 1 jam.
    /// Dipanggil periodik oleh scheduler di build_proxy_service().
    pub fn cleanup(&self) {
        let removed = self.evict_stale(3600);
        if removed > 0 {
            tracing::info!(
                "Rate limiter cleanup: removed {} idle IPs, {} active",
                removed,
                self.buckets.len()
            );
        }
    }

    pub fn active_count(&self) -> usize {
        self.buckets.len()
    }
}

// ─── WAF (Basic) ─────────────────────────────────────────────────────────────

/// WAF check — zero allocation: semua error reason adalah &'static str literal.
pub fn waf_check(path: &str, _method: &http::Method) -> Result<(), PolicyError> {
    // Path traversal
    if path.contains("../") || path.contains("..\\") || path.contains("%2e%2e") {
        return Err(PolicyError::SuspiciousRequest("path traversal"));
    }

    // Null byte injection
    if path.contains('\0') || path.contains("%00") {
        return Err(PolicyError::SuspiciousRequest("null byte"));
    }

    // Oversized path
    if path.len() > 4096 {
        return Err(PolicyError::SuspiciousRequest("oversized path"));
    }

    // Scanner paths — linear scan over &[&str], no alloc.
    // NOTE: /.well-known/security.txt dihapus dari blocklist — ini path standar
    // untuk security disclosure dan dipakai oleh tool legitimate (shodan, google).
    // Hanya block /.well-known/acme-challenge bypass jika ada attack vector.
    const BLOCKED: &[&str] = &[
        "/wp-admin",
        "/wp-login",
        "/.env",
        "/.git/",
        "/phpinfo",
        "/phpmyadmin",
        "/admin/config",
        "/actuator/",
        "/console/",
    ];
    for &blocked in BLOCKED {
        if path.starts_with(blocked) {
            return Err(PolicyError::SuspiciousRequest("blocked scanner path"));
        }
    }

    Ok(())
}

// ─── Policy pipeline ─────────────────────────────────────────────────────────

pub struct PolicyLayer {
    pub rate_limiter: Arc<RateLimiter>,
    // HashSet: O(1) lookup vs Vec O(n)
    blocked_ips: HashSet<IpAddr>,
}

impl PolicyLayer {
    pub fn new(rate_limit_rps: u64) -> Self {
        Self {
            rate_limiter: Arc::new(RateLimiter::new(rate_limit_rps)),
            blocked_ips: HashSet::new(),
        }
    }

    pub fn with_blocked_ips(rate_limit_rps: u64, blocked: Vec<IpAddr>) -> Self {
        Self {
            rate_limiter: Arc::new(RateLimiter::new(rate_limit_rps)),
            blocked_ips: blocked.into_iter().collect(),
        }
    }

    /// Sync apply — tidak perlu async karena DashMap tidak memerlukan .await.
    pub fn apply(&self, ctx: &RequestCtx) -> Result<(), PolicyError> {
        // WAF check untuk semua path non-static (bukan hanya API)
        if !ctx.is_static {
            waf_check(&ctx.path, &ctx.method)?;
        }

        if let Some(ip) = ctx.client_ip {
            // O(1) HashSet lookup
            if self.blocked_ips.contains(&ip) {
                return Err(PolicyError::BlockedIp);
            }
            if !ctx.is_static {
                self.rate_limiter.check(ip)?;
            }
        }

        Ok(())
    }

    /// Zero alloc: return static slice reference, tidak alokasi Vec baru per request.
    pub fn error_response(
        err: &PolicyError,
    ) -> (http::StatusCode, &'static [(&'static str, &'static str)]) {
        match err {
            PolicyError::RateLimited { .. } => (
                http::StatusCode::TOO_MANY_REQUESTS,
                &[("content-type", "application/json")],
            ),
            PolicyError::BlockedIp => (
                http::StatusCode::FORBIDDEN,
                &[("content-type", "application/json")],
            ),
            PolicyError::SuspiciousRequest(_) => (
                http::StatusCode::BAD_REQUEST,
                &[("content-type", "application/json")],
            ),
        }
    }
}

// ─── Hotlink protection (Referer allowlist) ──────────────────────────────────
//
// Tujuan: image RustFS hanya boleh di-embed/diakses dari domain kita sendiri.
// Mekanisme: cek header `Referer` request. Karena Referrer-Policy kita
// "strict-origin-when-cross-origin", embed sah dari ulala.space ke
// image.ulalaapi.store TETAP mengirim Referer "https://ulala.space/", jadi
// embed sah lolos, sedangkan embed dari domain lain ketahuan & ditolak.
//
// CATATAN PENTING (jujur soal batasannya):
//   - Ini hotlink protection, BUKAN keamanan sungguhan. Referer bisa dipalsukan
//     (attacker set "Referer: https://ulala.space" manual) atau di-strip
//     (<img referrerpolicy="no-referrer">). Cukup untuk cegah hotlink kasual &
//     pencurian bandwidth, TIDAK cukup untuk melindungi konten rahasia.
//   - Untuk proteksi nyata: pakai presigned/signed URL yang expire.

// Toggle: kalau true, request TANPA Referer diizinkan (mis. akses URL langsung
// di address bar, webview tertentu, sebagian browser privacy). Kalau false,
// request tanpa Referer ikut DITOLAK (mode strict — "benar-benar cuma dari
// halaman kita"), tapi akses URL langsung jadi 403.
const ALLOW_EMPTY_REFERER: bool = true;

/// Ekstrak host dari sebuah URL/Referer tanpa alokasi.
/// "https://ulala.space/foo?x=1" → Some("ulala.space")
/// "[::1]:3100" → Some("[::1]")  (IPv6-safe via strip_port dari transform.rs)
fn url_host(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host_port = after_scheme.split(['/', '?', '#']).next()?;
    // buang userinfo "user:pass@host" → ambil setelah '@' terakhir
    let host_port = host_port.rsplit('@').next()?;
    // FIX: gunakan strip_port() yang sudah IPv6-aware ([::1]:port → [::1])
    // Sebelumnya: split(':').next() → pecah di ':' pertama dalam "[::1]:3100" → "[" (salah).
    let host = crate::proxy::transform::strip_port(host_port);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// True kalau `host` adalah subdomain dari `parent` (zero-alloc).
/// is_subdomain_of("image.ulalaapi.store", "ulalaapi.store") == true
fn is_subdomain_of(host: &str, parent: &str) -> bool {
    host.len() > parent.len() + 1
        && host.ends_with(parent)
        && host.as_bytes()[host.len() - parent.len() - 1] == b'.'
}

/// True kalau Referer berasal dari domain kita (boleh akses image).
/// `referer` = nilai header Referer (None jika tidak ada).
pub fn referer_allowed(referer: Option<&str>, cfg: &Config) -> bool {
    let referer = match referer {
        Some(r) => r,
        None => return ALLOW_EMPTY_REFERER,
    };

    let host = match url_host(referer) {
        Some(h) => h,
        None => return false, // Referer ada tapi malformed → tolak
    };

    let web = cfg.web_domain.as_str(); // mis. "ulala.space"
    let api = cfg.api_domain.as_str(); // mis. "ulalaapi.store"

    // Apex domain kita
    if host == web || host == api {
        return true;
    }
    // Subdomain domain kita (www.ulala.space, image.ulalaapi.store, ui.ulalaapi.store)
    if is_subdomain_of(host, web) || is_subdomain_of(host, api) {
        return true;
    }
    // Origin dev / cors yang sudah di-whitelist (mis. http://localhost:3100,
    // http://77.237.242.1:3100) — supaya dev environment tidak ke-blok.
    for origin in cfg.dev_origins.iter().chain(cfg.cors_origins.iter()) {
        if url_host(origin) == Some(host) {
            return true;
        }
    }

    false
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── Tests: hotlink referer parsing ───────────────────────────────────────────
#[cfg(test)]
mod hotlink_tests {
    use super::{is_subdomain_of, url_host};

    #[test]
    fn url_host_extraction() {
        assert_eq!(
            url_host("https://ulala.space/explore?x=1"),
            Some("ulala.space")
        );
        assert_eq!(
            url_host("https://image.ulalaapi.store/a/b.jpg"),
            Some("image.ulalaapi.store")
        );
        assert_eq!(url_host("http://localhost:3100/"), Some("localhost"));
        assert_eq!(url_host("https://user:pass@evil.com/x"), Some("evil.com"));
        assert_eq!(url_host("https://host:8443"), Some("host"));
        assert_eq!(url_host("garbage"), Some("garbage"));
        assert_eq!(url_host("https://"), None);
        // IPv6 — sebelumnya split(':').next() pecah di ':' pertama → "[" (salah)
        assert_eq!(url_host("http://[::1]:3100/"), Some("[::1]"));
        assert_eq!(url_host("https://[::1]/path"), Some("[::1]"));
    }

    #[test]
    fn subdomain_matching_rejects_spoof() {
        // sah
        assert!(is_subdomain_of("image.ulalaapi.store", "ulalaapi.store"));
        assert!(is_subdomain_of("www.ulala.space", "ulala.space"));
        // spoof: HARUS ditolak
        assert!(!is_subdomain_of("ulala.space.evil.com", "ulala.space"));
        assert!(!is_subdomain_of("notulalaapi.store", "ulalaapi.store"));
        assert!(!is_subdomain_of("ulalaapi.store", "ulalaapi.store")); // apex, bukan subdomain
        assert!(!is_subdomain_of("xulalaapi.store", "ulalaapi.store"));
    }
}
