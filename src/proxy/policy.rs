//! Policy layer — rate limiting, WAF dasar, header validation.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use crate::proxy::context::{RequestCtx, RouteKind};

// ─── PolicyError ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum PolicyError {
    RateLimited { retry_after_secs: u64 },
    BlockedIp,
    SuspiciousRequest(String),
}

// ─── Rate Limiter (Token Bucket) ──────────────────────────────────────────────

struct Bucket {
    tokens:      AtomicU32,
    last_refill: AtomicU64, // unix seconds
}

impl Bucket {
    fn new(capacity: u32) -> Self {
        Self {
            tokens:      AtomicU32::new(capacity),
            last_refill: AtomicU64::new(now_secs()),
        }
    }

    fn try_consume(&self, capacity: u32, refill_per_sec: u32) -> bool {
        let now     = now_secs();
        let last    = self.last_refill.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(last);

        if elapsed > 0 {
            let refill = (elapsed as u32).saturating_mul(refill_per_sec).min(capacity);
            if refill > 0 {
                self.tokens.fetch_add(refill, Ordering::Relaxed);
                let cur = self.tokens.load(Ordering::Relaxed);
                if cur > capacity {
                    self.tokens.store(capacity, Ordering::Relaxed);
                }
                self.last_refill.store(now, Ordering::Relaxed);
            }
        }

        let cur = self.tokens.load(Ordering::Relaxed);
        if cur == 0 { return false; }
        self.tokens.fetch_sub(1, Ordering::Relaxed);
        true
    }
}

pub struct RateLimiter {
    buckets:        Arc<RwLock<HashMap<IpAddr, Arc<Bucket>>>>,
    capacity:       u32,
    refill_per_sec: u32,
}

impl RateLimiter {
    pub fn new(rps: u64) -> Self {
        let rps = rps as u32;
        Self {
            buckets:        Arc::new(RwLock::new(HashMap::new())),
            capacity:       rps * 3,
            refill_per_sec: rps,
        }
    }

    pub async fn check(&self, ip: IpAddr) -> Result<(), PolicyError> {
        {
            let guard = self.buckets.read().await;
            if let Some(bucket) = guard.get(&ip) {
                if !bucket.try_consume(self.capacity, self.refill_per_sec) {
                    return Err(PolicyError::RateLimited { retry_after_secs: 1 });
                }
                return Ok(());
            }
        }
        let bucket = Arc::new(Bucket::new(self.capacity));
        bucket.try_consume(self.capacity, self.refill_per_sec);
        self.buckets.write().await.insert(ip, bucket);
        Ok(())
    }

    pub async fn cleanup(&self) {
        let cutoff = now_secs().saturating_sub(3600);
        let mut guard = self.buckets.write().await;
        guard.retain(|_, bucket| bucket.last_refill.load(Ordering::Relaxed) > cutoff);
        tracing::debug!("Rate limiter cleanup: {} active IPs", guard.len());
    }
}

// ─── WAF (Basic) ─────────────────────────────────────────────────────────────

/// FIX: `_method` prefix — parameter wajib ada untuk konsistensi API tapi belum dipakai.
pub fn waf_check(path: &str, _method: &http::Method) -> Result<(), PolicyError> {
    // Path traversal
    if path.contains("../") || path.contains("..\\") || path.contains("%2e%2e") {
        return Err(PolicyError::SuspiciousRequest("path traversal".into()));
    }

    // Null byte injection
    if path.contains('\0') || path.contains("%00") {
        return Err(PolicyError::SuspiciousRequest("null byte".into()));
    }

    // Oversized path
    if path.len() > 4096 {
        return Err(PolicyError::SuspiciousRequest("oversized path".into()));
    }

    // Scanner paths
    const BLOCKED: &[&str] = &[
        "/wp-admin", "/wp-login", "/.env", "/.git/",
        "/phpinfo", "/phpmyadmin", "/admin/config",
        "/actuator/", "/console/", "/.well-known/security.txt",
    ];
    for blocked in BLOCKED {
        if path.starts_with(blocked) {
            return Err(PolicyError::SuspiciousRequest(format!("blocked path: {}", blocked)));
        }
    }

    Ok(())
}

// ─── Policy pipeline ─────────────────────────────────────────────────────────

pub struct PolicyLayer {
    pub rate_limiter: Arc<RateLimiter>,
    blocked_ips:      Vec<IpAddr>,
}

impl PolicyLayer {
    pub fn new(rate_limit_rps: u64) -> Self {
        Self {
            rate_limiter: Arc::new(RateLimiter::new(rate_limit_rps)),
            blocked_ips:  Vec::new(),
        }
    }

    pub async fn apply(&self, ctx: &RequestCtx) -> Result<(), PolicyError> {
        if ctx.is_api {
            waf_check(&ctx.path, &ctx.method)?;
        }

        if let Some(ip) = ctx.client_ip {
            if self.blocked_ips.contains(&ip) {
                return Err(PolicyError::BlockedIp);
            }
            if !ctx.is_static {
                self.rate_limiter.check(ip).await?;
            }
        }

        Ok(())
    }

    pub fn error_response(err: &PolicyError) -> (http::StatusCode, Vec<(&'static str, String)>) {
        match err {
            PolicyError::RateLimited { retry_after_secs } => (
                http::StatusCode::TOO_MANY_REQUESTS,
                vec![
                    ("retry-after",  retry_after_secs.to_string()),
                    ("content-type", "application/json".into()),
                ],
            ),
            PolicyError::BlockedIp => (
                http::StatusCode::FORBIDDEN,
                vec![("content-type", "application/json".into())],
            ),
            PolicyError::SuspiciousRequest(_) => (
                http::StatusCode::BAD_REQUEST,
                vec![("content-type", "application/json".into())],
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
