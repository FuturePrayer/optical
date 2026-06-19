//! Metrics collection for tunnel observability.
//!
//! Uses a global `MetricsRegistry` (via `OnceLock`) so any code path can
//! record metrics without threading `Arc` references through every function
//! signature. The registry is initialized once in `app.rs` at startup.
//!
//! Key design:
//! - `TunnelMetrics` are keyed by tunnel peer address (e.g. "peer:9000").
//!   Pre-registered by `run_forwarders` (Client/outbound role) before the
//!   `TunnelClient` starts, and by the tunnel server (Server/inbound role)
//!   after a successful handshake.
//! - `ForwarderMetrics` are keyed by local listen address.
//! - `HistoryBuffer` stores periodic snapshots for trend analysis.

pub mod history;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::Instant;

use serde::Serialize;

use crate::config::Protocol;

/// Tunnel connection state.
pub const STATE_DISCONNECTED: u8 = 0;
pub const STATE_CONNECTED: u8 = 1;

/// Tunnel role: Client (Node1, outbound dialer) or Server (Node2, inbound
/// listener). Distinguishes tunnel directions in status output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRole {
    Client,
    Server,
}

impl TunnelRole {
    /// Display label: "outbound" (Client) or "inbound" (Server).
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelRole::Client => "outbound",
            TunnelRole::Server => "inbound",
        }
    }
}

/// Per-tunnel metrics. Shared across reconnections (the registry entry
/// persists; each new `Tunnel` grabs the same `Arc`).
pub struct TunnelMetrics {
    pub role: TunnelRole,
    pub state: AtomicU8,
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    /// Most recent RTT in microseconds (0 = unknown).
    pub rtt_us: AtomicU64,
    pub reconnect_count: AtomicU32,
    pub last_connected: Mutex<Option<Instant>>,
    pub last_disconnected: Mutex<Option<Instant>>,
}

impl TunnelMetrics {
    fn new(role: TunnelRole) -> Self {
        Self {
            role,
            state: AtomicU8::new(STATE_DISCONNECTED),
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            rtt_us: AtomicU64::new(0),
            reconnect_count: AtomicU32::new(0),
            last_connected: Mutex::new(None),
            last_disconnected: Mutex::new(None),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.state.load(Ordering::Relaxed) == STATE_CONNECTED
    }

    /// Seconds since the last successful connection (0 if never connected).
    pub fn uptime_secs(&self) -> u64 {
        let guard = self.last_connected.lock().unwrap();
        match *guard {
            Some(t) if self.is_connected() => t.elapsed().as_secs(),
            _ => 0,
        }
    }
}

/// Per-forwarder metrics, keyed by the local listen address.
pub struct ForwarderMetrics {
    pub proto: Protocol,
    pub target: String,
    pub active_streams: AtomicU32,
    pub total_streams: AtomicU32,
    /// local → tunnel direction.
    pub bytes_sent: AtomicU64,
    /// tunnel → local direction.
    pub bytes_recv: AtomicU64,
}

impl ForwarderMetrics {
    fn new(proto: Protocol, target: &str) -> Self {
        Self {
            proto,
            target: target.to_string(),
            active_streams: AtomicU32::new(0),
            total_streams: AtomicU32::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
        }
    }
}

/// Global metrics registry.
pub struct MetricsRegistry {
    tunnels: RwLock<HashMap<String, std::sync::Arc<TunnelMetrics>>>,
    forwarders: RwLock<HashMap<SocketAddr, std::sync::Arc<ForwarderMetrics>>>,
    pub history: Mutex<history::HistoryBuffer>,
    pub started_at: Instant,
}

static REGISTRY: OnceLock<MetricsRegistry> = OnceLock::new();

/// Initialize the global registry. Called once at startup from `app.rs`.
/// After this, `try_get()` returns `Some`.
pub fn init() -> &'static MetricsRegistry {
    REGISTRY.get_or_init(|| MetricsRegistry {
        tunnels: RwLock::new(HashMap::new()),
        forwarders: RwLock::new(HashMap::new()),
        history: Mutex::new(history::HistoryBuffer::new()),
        started_at: Instant::now(),
    })
}

/// Get the global registry if initialized.
pub fn try_get() -> Option<&'static MetricsRegistry> {
    REGISTRY.get()
}

impl MetricsRegistry {
    /// Register a tunnel metrics entry. Called before `TunnelClient::start`
    /// (Client role) or after a server-side handshake (Server role).
    pub fn register_tunnel(
        &self,
        addr: &str,
        role: TunnelRole,
    ) -> std::sync::Arc<TunnelMetrics> {
        let metrics = std::sync::Arc::new(TunnelMetrics::new(role));
        self.tunnels
            .write()
            .unwrap()
            .insert(addr.to_string(), metrics.clone());
        metrics
    }

    /// Remove a tunnel metrics entry. The `expected` Arc is compared by
    /// pointer to avoid removing a newer entry that replaced the original
    /// under the same key (e.g. a server-side peer reconnected before the
    /// old monitor task ran).
    pub fn unregister_tunnel(&self, addr: &str, expected: &std::sync::Arc<TunnelMetrics>) {
        let mut tunnels = self.tunnels.write().unwrap();
        if let Some(existing) = tunnels.get(addr) {
            if std::sync::Arc::ptr_eq(existing, expected) {
                tunnels.remove(addr);
            }
        }
    }

    /// Look up tunnel metrics by address.
    pub fn get_tunnel(&self, addr: &str) -> Option<std::sync::Arc<TunnelMetrics>> {
        self.tunnels.read().unwrap().get(addr).cloned()
    }

    /// Register a forwarder metrics entry.
    pub fn register_forwarder(
        &self,
        listen: SocketAddr,
        proto: Protocol,
        target: &str,
    ) -> std::sync::Arc<ForwarderMetrics> {
        let metrics = std::sync::Arc::new(ForwarderMetrics::new(proto, target));
        self.forwarders
            .write()
            .unwrap()
            .insert(listen, metrics.clone());
        metrics
    }

    /// Look up forwarder metrics by listen address.
    pub fn get_forwarder(&self, listen: SocketAddr) -> Option<std::sync::Arc<ForwarderMetrics>> {
        self.forwarders.read().unwrap().get(&listen).cloned()
    }

    /// Take a point-in-time snapshot of all metrics.
    pub fn snapshot(&self) -> Snapshot {
        let tunnels = self
            .tunnels
            .read()
            .unwrap()
            .iter()
            .map(|(addr, m)| TunnelSnapshot {
                addr: addr.clone(),
                role: m.role.as_str().to_string(),
                state: if m.is_connected() {
                    "connected"
                } else {
                    "disconnected"
                }
                .to_string(),
                rtt_us: m.rtt_us.load(Ordering::Relaxed),
                bytes_sent: m.bytes_sent.load(Ordering::Relaxed),
                bytes_recv: m.bytes_recv.load(Ordering::Relaxed),
                reconnect_count: m.reconnect_count.load(Ordering::Relaxed),
                uptime_secs: m.uptime_secs(),
            })
            .collect();

        let forwarders = self
            .forwarders
            .read()
            .unwrap()
            .iter()
            .map(|(listen, m)| ForwarderSnapshot {
                listen: listen.to_string(),
                proto: m.proto.to_string(),
                target: m.target.clone(),
                active_streams: m.active_streams.load(Ordering::Relaxed),
                total_streams: m.total_streams.load(Ordering::Relaxed),
                bytes_sent: m.bytes_sent.load(Ordering::Relaxed),
                bytes_recv: m.bytes_recv.load(Ordering::Relaxed),
            })
            .collect();

        Snapshot {
            uptime_secs: self.started_at.elapsed().as_secs(),
            tunnels,
            forwarders,
        }
    }

}

// ── Snapshot types (for JSON serialization) ─────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub uptime_secs: u64,
    pub tunnels: Vec<TunnelSnapshot>,
    pub forwarders: Vec<ForwarderSnapshot>,
}

#[derive(Debug, Serialize)]
pub struct TunnelSnapshot {
    pub addr: String,
    pub role: String,
    pub state: String,
    pub rtt_us: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub reconnect_count: u32,
    pub uptime_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct ForwarderSnapshot {
    pub listen: String,
    pub proto: String,
    pub target: String,
    pub active_streams: u32,
    pub total_streams: u32,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}
