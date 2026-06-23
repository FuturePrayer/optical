//! Wire protocol for the config-center session layer.
//!
//! The center session reuses the tunnel's wire frame format (15-byte header
//! as AEAD AAD + encrypted JSON payload) but is a **separate connection** from
//! the multiplexed tunnel. It runs over its own PQ handshake and uses
//! `stream_id = 0` control frames exclusively with the center-specific frame
//! types (`NodeRegister`, `ConfigPush`, `StatusReport`, `ConfigAck`).
//!
//! This module defines:
//! - The JSON message structs (de)serialized as frame payloads.
//! - [`read_frame`] / [`write_frame`]: encrypt/decrypt + frame I/O over any
//!   `AsyncRead + AsyncWrite` stream, sharing the tunnel codec helpers.
//!
//! Both the node-side [`CenterClient`](crate::center_client) and the
//! center-server session (under the `center` feature) use this module.

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::aead::AeadCipher;
use crate::error::{OpticalError, Result};
use crate::proto::frame::{build_header, parse_header, FrameType, HEADER_SIZE, MAX_PAYLOAD};

// ── JSON message types ─────────────────────────────────────────────────────

/// `NodeRegister` payload: node → center. Sent right after the handshake.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct NodeRegisterMsg {
    /// The node's permanent ID (SHA-256 of its ML-DSA-65 verifying key, hex).
    /// Redundant with the handshake's dsa_pubkey, but included explicitly so
    /// the center can route by ID without re-hashing.
    pub node_id: String,
    /// optical version string (e.g. "0.1.4").
    pub version: String,
    /// Free-form capability tags (e.g. `["tcp", "kcp", "ws", "reverse"]`).
    pub capabilities: Vec<String>,
}

/// Node2 (tunnel server) configuration that the center can push to a node.
/// When present in a ConfigPushMsg, the node applies these as its tunnel
/// server settings (overriding the local config.yml).
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct NodeServerConfig {
    /// Tunnel server listen address. None = don't run a tunnel server.
    #[serde(default)]
    pub tunnel_listen: Option<std::net::SocketAddr>,
    /// Transport protocol for the tunnel server.
    #[serde(default = "default_tcp")]
    pub tunnel_transport: crate::config::TransportKind,
    /// Whether to accept reverse tunnel registrations from peers.
    #[serde(default = "default_true")]
    pub allow_reverse: bool,
}

fn default_tcp() -> crate::config::TransportKind {
    crate::config::TransportKind::Tcp
}

fn default_true() -> bool {
    true
}

/// `ConfigPush` payload: center → node. Carries the forwarders this node
/// should run, optionally Node2 (tunnel server) settings, plus an
/// incrementing version number.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ConfigPushMsg {
    /// Monotonically increasing config version assigned by the center.
    pub config_version: u64,
    /// The forwarders this node should run. Replaces the node's entire
    /// forwarder set on each push (full-state, not patch).
    pub forwarders: Vec<crate::config::ForwarderConfig>,
    /// Node2 (tunnel server) configuration. None = leave the node's current
    /// tunnel server settings unchanged (backwards-compatible with pushes
    /// that only manage forwarders).
    #[serde(default)]
    pub server_config: Option<NodeServerConfig>,
}

/// `StatusReport` payload: node → center. Periodic liveness + metrics.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct StatusReportMsg {
    /// The config version the node currently has applied (so the center can
    /// detect drift and re-push).
    pub config_version_applied: u64,
    /// Node uptime in seconds.
    pub uptime_secs: u64,
    /// Real-time metrics snapshot.
    pub snapshot: crate::metrics::Snapshot,
}

/// `ConfigAck` payload: node → center. Confirms a config push was applied.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ConfigAckMsg {
    pub config_version: u64,
    /// Whether the config was applied successfully.
    pub ok: bool,
    /// Error message when `ok == false`.
    #[serde(default)]
    pub error: String,
}

// ── Frame I/O (encrypt/decrypt + read/write over a duplex stream) ──────────

/// Write a single encrypted frame carrying a JSON-serialized payload of the
/// given frame type. Uses `stream_id = 0` (control frame) and a per-direction
/// monotonic counter supplied by the caller.
pub async fn write_frame<T: Serialize, W: AsyncWrite + Unpin>(
    writer: &mut W,
    cipher: &AeadCipher,
    counter: u64,
    frame_type: FrameType,
    msg: &T,
) -> Result<()> {
    let json = serde_json::to_vec(msg)
        .map_err(|e| OpticalError::Config(format!("center msg serialize: {e}")))?;
    if json.len() > MAX_PAYLOAD {
        return Err(OpticalError::Config(format!(
            "center msg too large: {} > {MAX_PAYLOAD}",
            json.len()
        )));
    }
    let header = build_header(0, counter, frame_type, (json.len() + 16) as u16);
    let ciphertext = cipher.encrypt(0, counter, &header, &json)?;
    writer.write_all(&header).await.map_err(OpticalError::Io)?;
    writer.write_all(&ciphertext).await.map_err(OpticalError::Io)?;
    writer.flush().await.map_err(OpticalError::Io)?;
    Ok(())
}

/// Read a single encrypted frame, decrypt it, and deserialize the JSON payload
/// as `T`. Returns the raw frame type byte alongside (so the caller can
/// dispatch on type before deserializing). Unknown frame types are returned
/// as `Ok(None)` after draining their payload — forward compatibility.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    cipher: &AeadCipher,
) -> Result<Option<(FrameType, Vec<u8>)>> {
    let mut header = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header).await.map_err(OpticalError::Io)?;
    let (_stream_id, counter, frame_type_raw, payload_len) = parse_header(&header);
    let mut ct = vec![0u8; payload_len];
    reader.read_exact(&mut ct).await.map_err(OpticalError::Io)?;
    let plaintext = cipher.decrypt(0, counter, &header, &ct)?;
    match FrameType::from_u8(frame_type_raw) {
        Ok(ft) => Ok(Some((ft, plaintext))),
        Err(_) => {
            tracing::trace!(frame_type = frame_type_raw, "skipping unknown center frame");
            Ok(None)
        }
    }
}

/// Helper: read a frame and deserialize its payload as `T`, ignoring frames
/// whose type does not match `expected` (returns `Ok(None)` for those so the
/// caller can keep the loop going).
pub async fn read_frame_as<T: DeserializeOwned, R: AsyncRead + Unpin>(
    reader: &mut R,
    cipher: &AeadCipher,
    expected: FrameType,
) -> Result<Option<T>> {
    match read_frame(reader, cipher).await? {
        Some((ft, plaintext)) if ft == expected => {
            let msg = serde_json::from_slice(&plaintext)
                .map_err(|e| OpticalError::Config(format!("center msg deserialize: {e}")))?;
            Ok(Some(msg))
        }
        Some((ft, _)) => {
            tracing::debug!(?ft, expected = ?expected, "center frame type mismatch, ignoring");
            Ok(None)
        }
        None => Ok(None),
    }
}
