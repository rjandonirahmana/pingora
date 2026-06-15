//! Upstream pool — load balancing + circuit breaker.
//!
//! Optimasi dari original:
//!   - Backend.addr: String → SmolStr (stack-allocated untuk addr pendek)
//!   - find(): pakai &str parameter untuk zero-copy comparison
//!   - UpstreamPool::single(): konstruktor khusus tetap ada, internal optimized

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use smol_str::SmolStr;

const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
// PROBING: exactly one thread won OPEN→PROBING CAS and is the live probe.
// All other requests are blocked until record_success() or record_failure().
const STATE_PROBING: u8 = 2;

pub struct CircuitBreaker {
    state: AtomicU8,
    failures: AtomicU32,
    last_failure: AtomicU64,
    threshold: u32,
    cooldown_secs: u64,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            state: AtomicU8::new(STATE_CLOSED),
            failures: AtomicU32::new(0),
            last_failure: AtomicU64::new(0),
            threshold,
            cooldown_secs,
        }
    }

    pub fn allow(&self) -> bool {
        match self.state.load(Ordering::Acquire) {
            STATE_CLOSED => true,
            STATE_OPEN => {
                let elapsed = now_secs().saturating_sub(self.last_failure.load(Ordering::Relaxed));
                if elapsed >= self.cooldown_secs {
                    // Only the thread that wins OPEN→PROBING CAS sends the probe.
                    // All concurrent losers get false — no concurrent probes allowed.
                    self.state
                        .compare_exchange(
                            STATE_OPEN,
                            STATE_PROBING,
                            Ordering::Release,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                } else {
                    false
                }
            }
            // STATE_PROBING: probe already in flight — block all other requests.
            _ => false,
        }
    }

    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.state.store(STATE_CLOSED, Ordering::Release);
    }

    pub fn record_failure(&self) {
        let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.last_failure.store(now_secs(), Ordering::Relaxed);
        if failures >= self.threshold {
            self.state.store(STATE_OPEN, Ordering::Release);
            tracing::warn!("Circuit breaker OPEN setelah {} failures", failures);
        } else {
            // Probe failed but still below threshold — go back to OPEN so a new
            // probe can be attempted after the next cooldown window.
            // CAS guards against overwriting a concurrent state change.
            let _ = self.state.compare_exchange(
                STATE_PROBING,
                STATE_OPEN,
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }

    pub fn state_name(&self) -> &'static str {
        match self.state.load(Ordering::Relaxed) {
            STATE_CLOSED => "closed",
            STATE_OPEN => "open",
            STATE_PROBING => "half-open",
            _ => "unknown",
        }
    }
}

pub struct Backend {
    // SmolStr: stack-allocated jika addr ≤ 22 chars ("127.0.0.1:8080" = 14).
    // Tidak ada heap alloc untuk semua kasus localhost/private addr.
    pub addr: SmolStr,
    pub breaker: CircuitBreaker,
}

impl Backend {
    pub fn new(addr: String) -> Self {
        Self {
            addr: SmolStr::new(&addr),
            breaker: CircuitBreaker::new(5, 30),
        }
    }
}

pub struct UpstreamPool {
    backends: Vec<Arc<Backend>>,
    counter: AtomicU32,
}

impl UpstreamPool {
    pub fn new(addrs: Vec<String>) -> Self {
        Self {
            backends: addrs
                .into_iter()
                .map(|a| Arc::new(Backend::new(a)))
                .collect(),
            counter: AtomicU32::new(0),
        }
    }

    pub fn single(addr: String) -> Self {
        Self::new(vec![addr])
    }

    pub fn next(&self) -> Option<Arc<Backend>> {
        let len = self.backends.len();
        if len == 0 {
            return None;
        }

        let start = self.counter.fetch_add(1, Ordering::Relaxed) as usize;
        for i in 0..len {
            let b = &self.backends[(start + i) % len];
            if b.breaker.allow() {
                return Some(b.clone());
            }
        }

        tracing::error!("Semua backend OPEN — fallback ke backend[0]");
        Some(self.backends[0].clone())
    }

    /// Cari backend berdasarkan addr — &str parameter untuk zero-copy comparison.
    pub fn find(&self, addr: &str) -> Option<Arc<Backend>> {
        self.backends
            .iter()
            .find(|b| b.addr.as_str() == addr)
            .cloned()
    }

    pub fn status(&self) -> Vec<(&str, &str)> {
        self.backends
            .iter()
            .map(|b| (b.addr.as_str(), b.breaker.state_name()))
            .collect()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
