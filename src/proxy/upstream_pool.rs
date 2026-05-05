//! Upstream pool — load balancing + circuit breaker.
//!
//! Round-robin dengan circuit breaker per backend.
//! State: Closed → Open (setelah N failure) → Half-Open (setelah cooldown) → Closed

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const STATE_CLOSED:    u8 = 0;
const STATE_OPEN:      u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

pub struct CircuitBreaker {
    state:         AtomicU8,
    failures:      AtomicU32,
    last_failure:  AtomicU64,
    threshold:     u32,
    cooldown_secs: u64,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            state:         AtomicU8::new(STATE_CLOSED),
            failures:      AtomicU32::new(0),
            last_failure:  AtomicU64::new(0),
            threshold,
            cooldown_secs,
        }
    }

    pub fn allow(&self) -> bool {
        match self.state.load(Ordering::Acquire) {
            STATE_CLOSED => true,
            STATE_OPEN   => {
                let elapsed = now_secs().saturating_sub(self.last_failure.load(Ordering::Relaxed));
                if elapsed >= self.cooldown_secs {
                    self.state.compare_exchange(
                        STATE_OPEN, STATE_HALF_OPEN,
                        Ordering::Release, Ordering::Relaxed,
                    ).ok();
                    true
                } else {
                    false
                }
            }
            _ => true, // HALF_OPEN: izinkan 1 probe
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
        }
    }

    pub fn state_name(&self) -> &'static str {
        match self.state.load(Ordering::Relaxed) {
            STATE_CLOSED    => "closed",
            STATE_OPEN      => "open",
            STATE_HALF_OPEN => "half-open",
            _               => "unknown",
        }
    }
}

pub struct Backend {
    pub addr:    String,
    pub breaker: CircuitBreaker,
}

impl Backend {
    pub fn new(addr: String) -> Self {
        Self {
            addr,
            breaker: CircuitBreaker::new(5, 30),
        }
    }
}

pub struct UpstreamPool {
    backends: Vec<Arc<Backend>>,
    counter:  AtomicU32,
}

impl UpstreamPool {
    pub fn new(addrs: Vec<String>) -> Self {
        Self {
            backends: addrs.into_iter().map(|a| Arc::new(Backend::new(a))).collect(),
            counter:  AtomicU32::new(0),
        }
    }

    pub fn single(addr: String) -> Self {
        Self::new(vec![addr])
    }

    /// Pilih backend (round-robin, skip yang OPEN).
    pub fn next(&self) -> Option<Arc<Backend>> {
        let len = self.backends.len();
        if len == 0 { return None; }

        let start = self.counter.fetch_add(1, Ordering::Relaxed) as usize;
        for i in 0..len {
            let b = &self.backends[(start + i) % len];
            if b.breaker.allow() {
                return Some(b.clone());
            }
        }

        // Semua OPEN → fallback ke [0]
        tracing::error!("Semua backend OPEN — fallback ke backend[0]");
        Some(self.backends[0].clone())
    }

    /// Cari backend berdasarkan addr — untuk update circuit breaker di error handler.
    pub fn find(&self, addr: &str) -> Option<Arc<Backend>> {
        self.backends.iter().find(|b| b.addr == addr).cloned()
    }

    pub fn status(&self) -> Vec<(&str, &str)> {
        self.backends.iter().map(|b| (b.addr.as_str(), b.breaker.state_name())).collect()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
