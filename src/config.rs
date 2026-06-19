use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::error::{OpticalError, Result};

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

/// Underlying transport protocol carrying the encrypted tunnel.
///
/// The client (Node1) side selects the transport via the `tunnel` address URL
/// scheme (`tcp://`, `kcp://`, `ws://`); a bare `host:port` defaults to TCP for
/// backwards compatibility. The server (Node2) side is selected by this config
/// field since `tunnel_listen: SocketAddr` carries no scheme.
///
/// - `Tcp`: plain TCP (default)
/// - `Kcp`: reliable low-latency UDP over KCP (tokio-kcp)
/// - `Ws`:  WebSocket, traverses HTTP proxies/firewalls (tokio-tungstenite)
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    #[default]
    Tcp,
    Kcp,
    Ws,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportKind::Tcp => write!(f, "tcp"),
            TransportKind::Kcp => write!(f, "kcp"),
            TransportKind::Ws => write!(f, "ws"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Pre-shared key in hex format: "hex:<64 hex chars>"
    pub psk: String,
    /// Path to ML-DSA-65 private key file
    pub mldsa_private_key: PathBuf,
    /// Path to ML-DSA-65 public key file
    pub mldsa_public_key: PathBuf,
    /// Tunnel server listen address (None = don't act as Node2)
    pub tunnel_listen: Option<SocketAddr>,
    /// Transport protocol for the tunnel *listener* (Node2 side). The client
    /// (Node1) side instead selects transport per-forwarder via the `tunnel`
    /// address URL scheme. Default: `tcp` (backwards compatible).
    #[serde(default)]
    pub tunnel_transport: TransportKind,
    /// Local port forwarders (empty = don't act as Node1)
    #[serde(default)]
    pub forwarders: Vec<ForwarderConfig>,
    /// Tunnel connection parameters
    #[serde(default)]
    pub tunnel: TunnelConfig,
    /// Admin API listen address for observability (None = disabled).
    /// Example: "127.0.0.1:9100"
    #[serde(default)]
    pub admin_listen: Option<SocketAddr>,
    /// Whether to accept reverse tunnel registrations from peers (Node2 role).
    /// When `false`, incoming RegisterReverse frames are rejected with status=disabled.
    /// Default: true.
    #[serde(default = "default_true")]
    pub allow_reverse: bool,
    /// Directory for daily-rotating log files. When set, logs are written to
    /// rolling files in this directory (one file per day) in addition to
    /// stdout. When omitted, logs go to stdout only.
    #[serde(default)]
    pub log_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForwarderConfig {
    /// Local listen address
    pub listen: SocketAddr,
    /// Protocol to forward
    pub proto: Protocol,
    /// Tunnel peer address "host:port"
    pub tunnel: String,
    /// Final target address "host:port"
    pub target: String,
    /// Reverse mode: if true, the peer (Node2) listens on `listen` and forwards
    /// connections back through the tunnel to this node (Node1), which dials `target`.
    /// Default: false (normal mode — this node listens and the peer dials).
    #[serde(default)]
    pub reverse: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TunnelConfig {
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout_secs: u64,
    #[serde(default = "default_reconnect_initial")]
    pub reconnect_initial_secs: u64,
    #[serde(default = "default_reconnect_max")]
    pub reconnect_max_secs: u64,
    #[serde(default = "default_udp_idle")]
    pub udp_idle_secs: u64,
    /// Timeout (seconds) for dialing a target after receiving an OPEN request
    /// (Node2 → final target, or Node1 → target in reverse mode). Prevents
    /// unreachable targets from holding stream IDs and tasks indefinitely.
    /// Default: 10.
    #[serde(default = "default_dial_timeout")]
    pub dial_timeout_secs: u64,
    /// Timeout (seconds) for waiting on an OPEN_ACK after sending an OPEN
    /// frame (Node1 → Node2, or Node2 → Node1 in reverse mode). Prevents a
    /// stalled peer dial from hanging the local connection indefinitely.
    /// Default: 15.
    #[serde(default = "default_open_ack_timeout")]
    pub open_ack_timeout_secs: u64,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 15,
            heartbeat_timeout_secs: 45,
            reconnect_initial_secs: 1,
            reconnect_max_secs: 30,
            udp_idle_secs: 60,
            dial_timeout_secs: 10,
            open_ack_timeout_secs: 15,
        }
    }
}

fn default_heartbeat_interval() -> u64 {
    15
}
fn default_heartbeat_timeout() -> u64 {
    45
}
fn default_reconnect_initial() -> u64 {
    1
}
fn default_reconnect_max() -> u64 {
    30
}
fn default_udp_idle() -> u64 {
    60
}
fn default_dial_timeout() -> u64 {
    10
}
fn default_open_ack_timeout() -> u64 {
    15
}
fn default_true() -> bool {
    true
}

impl Config {
    /// Load and validate config from a YAML file.
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| OpticalError::Config(format!("failed to read config file '{path}': {e}")))?;
        let config: Config = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Parse the PSK hex string into 32 raw bytes.
    pub fn psk_bytes(&self) -> Result<[u8; 32]> {
        let s = self
            .psk
            .strip_prefix("hex:")
            .ok_or_else(|| OpticalError::Config("PSK must be in 'hex:<hex>' format".into()))?;
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(OpticalError::Config(format!(
                "PSK must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    fn validate(&self) -> Result<()> {
        if self.forwarders.is_empty() && self.tunnel_listen.is_none() {
            return Err(OpticalError::Config(
                "at least one of 'forwarders' or 'tunnel_listen' must be configured".into(),
            ));
        }
        // Validate PSK format early
        self.psk_bytes()?;
        Ok(())
    }

    /// Whether this node acts as Node1 (forwarder).
    pub fn is_node1(&self) -> bool {
        !self.forwarders.is_empty()
    }

    /// Whether this node acts as Node2 (tunnel server).
    pub fn is_node2(&self) -> bool {
        self.tunnel_listen.is_some()
    }
}
