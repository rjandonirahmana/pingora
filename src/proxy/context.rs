//! RequestCtx — central state untuk satu request.
//! Diisi sekali, dibaca di semua layer. Zero recompute.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use http::Method;

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
}

impl RouteKind {
    pub fn from_decision(decision: &RouteDecision) -> Self {
        match decision.upstream {
            Upstream::Backend  if decision.is_ws => RouteKind::Websocket,
            Upstream::Backend                    => RouteKind::Api,
            Upstream::Frontend                   => RouteKind::Static,
            Upstream::RustFS3                    => RouteKind::Object,
            Upstream::RustFSUI                   => RouteKind::Dashboard,
        }
    }
}

// ─── TimeoutConfig ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct TimeoutConfig {
    pub connect_secs: u64,
    pub read_secs:    u64,
    pub write_secs:   u64,
}

impl TimeoutConfig {
    pub fn for_route(kind: RouteKind) -> Self {
        match kind {
            RouteKind::Websocket => Self { connect_secs: 10, read_secs: 3600, write_secs: 3600 },
            RouteKind::Api       => Self { connect_secs: 5,  read_secs: 60,   write_secs: 30   },
            RouteKind::Object    => Self { connect_secs: 5,  read_secs: 120,  write_secs: 120  },
            RouteKind::Static    => Self { connect_secs: 3,  read_secs: 30,   write_secs: 10   },
            RouteKind::Dashboard => Self { connect_secs: 5,  read_secs: 60,   write_secs: 30   },
        }
    }
}

// ─── RequestCtx ──────────────────────────────────────────────────────────────

pub struct RequestCtx {
    // Identity
    pub id:           u64,
    pub started_at:   Instant,

    // Routing
    pub upstream:     Upstream,
    pub route:        RouteKind,
    pub timeout:      TimeoutConfig,

    // Request info
    pub host:         String,
    pub path:         String,
    pub method:       Method,

    // Flags
    pub is_ws:        bool,
    pub is_static:    bool,
    pub is_api:       bool,
    pub is_object:    bool,

    // Transform
    pub strip_prefix: Option<&'static str>,

    // Client info
    pub client_ip:     Option<IpAddr>,
    pub client_ip_str: String,

    // Backend addr yang terpilih — untuk circuit breaker lookup di error handler
    pub backend_addr:  String,

    // Retry counter
    pub attempts:      u8,
}

impl RequestCtx {
    pub fn new(
        decision:  RouteDecision,
        host:      String,
        path:      String,
        method:    Method,
        client_ip: Option<IpAddr>,
    ) -> Self {
        let route   = RouteKind::from_decision(&decision);
        let timeout = TimeoutConfig::for_route(route);

        let client_ip_str = client_ip.map(|ip| ip.to_string()).unwrap_or_default();

        Self {
            id:           next_id(),
            started_at:   Instant::now(),
            upstream:     decision.upstream,
            route,
            timeout,
            host,
            path,
            method,
            is_ws:        decision.is_ws,
            is_static:    matches!(route, RouteKind::Static),
            is_api:       matches!(route, RouteKind::Api | RouteKind::Websocket),
            is_object:    matches!(route, RouteKind::Object),
            strip_prefix: decision.strip_prefix,
            client_ip,
            client_ip_str,
            backend_addr: String::new(), // diisi di upstream_peer
            attempts:     0,
        }
    }

    #[inline]
    pub fn elapsed_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }

    #[inline]
    pub fn id_hex(&self) -> String {
        format!("{:016x}", self.id)
    }
}

impl Default for RequestCtx {
    fn default() -> Self {
        Self {
            id:           0,
            started_at:   Instant::now(),
            upstream:     Upstream::Frontend,
            route:        RouteKind::Static,
            timeout:      TimeoutConfig::for_route(RouteKind::Static),
            host:         String::new(),
            path:         String::new(),
            method:       Method::GET,
            is_ws:        false,
            is_static:    true,
            is_api:       false,
            is_object:    false,
            strip_prefix: None,
            client_ip:    None,
            client_ip_str: String::new(),
            backend_addr: String::new(),
            attempts:     0,
        }
    }
}
