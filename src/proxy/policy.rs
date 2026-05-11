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

use crate::proxy::context::RequestCtx;

// Hard cap jumlah IP di rate limiter — cegah OOM saat DDoS IP spoofing.
// 100k entry × ~64 bytes/entry ≈ 6.4MB max.
const MAX_BUCKETS: usize = 100_000;

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
    last_refill: AtomicU64, // unix seconds
}

impl Bucket {
    fn new(capacity: u32) -> Self {
        Self {
            tokens: AtomicU32::new(capacity),
            last_refill: AtomicU64::new(now_secs()),
        }
    }

    fn try_consume(&self, capacity: u32, refill_per_sec: u32) -> bool {
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

        // Slow path: IP baru — cek cap dulu sebelum insert
        if self.buckets.len() >= MAX_BUCKETS {
            // Bucket penuh → tolak request daripada leak memory.
            // Ini correct behavior saat DDoS: semua IP baru di-rate-limit.
            return Err(PolicyError::RateLimited {
                retry_after_secs: 60,
            });
        }

        let bucket = Arc::new(Bucket::new(self.capacity));
        bucket.try_consume(self.capacity, self.refill_per_sec);
        self.buckets.insert(ip, bucket);
        Ok(())
    }

    /// Hapus bucket yang tidak aktif > 1 jam.
    /// Dipanggil periodik oleh scheduler di build_proxy_service().
    pub fn cleanup(&self) {
        let cutoff = now_secs().saturating_sub(3600);
        let before = self.buckets.len();
        self.buckets
            .retain(|_, bucket| bucket.last_refill.load(Ordering::Relaxed) > cutoff);
        let after = self.buckets.len();
        if before != after {
            tracing::info!(
                "Rate limiter cleanup: {} → {} active IPs (removed {})",
                before,
                after,
                before - after
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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
