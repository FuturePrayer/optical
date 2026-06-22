//! Tunnel frame types and wire encoding.
//!
//! Frame wire format (all fields big-endian):
//! ```text
//! [4B stream_id][8B counter][1B frame_type][2B payload_len][payload (AEAD ciphertext + 16B tag)]
//!  └──── AAD (15 bytes) ────────────────────┘    └── encrypted ──┘
//! ```
//! The 15-byte header is used as Additional Authenticated Data (AAD) for AEAD.
//! `payload_len` is the length of the encrypted payload (plaintext_len + 16 for tag).

use bytes::Bytes;

use crate::error::{OpticalError, Result};

/// Header size in bytes (4 + 8 + 1 + 2).
pub const HEADER_SIZE: usize = 15;

/// AEAD tag size.
pub const TAG_SIZE: usize = 16;

/// Maximum payload size (plaintext). The encrypted payload will be this + 16 bytes.
pub const MAX_PAYLOAD: usize = 65535 - TAG_SIZE;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Open a new stream. Payload (plaintext): [1B proto][2B target_len BE][target bytes]
    Open = 0x01,
    /// Acknowledge stream open. Payload (plaintext): [1B status (0=ok, 1=refused)]
    OpenAck = 0x02,
    /// Data frame. Payload (plaintext): raw data bytes.
    Data = 0x03,
    /// Close a stream. Payload: empty.
    Close = 0x04,
    /// Heartbeat ping. Payload: empty.
    Ping = 0x05,
    /// Heartbeat pong. Payload: empty.
    Pong = 0x06,
    /// Diagnostic echo request. Payload: arbitrary bytes (echoed back).
    Echo = 0x07,
    /// Diagnostic echo reply. Payload: identical bytes from corresponding Echo.
    EchoReply = 0x08,
    /// Register a reverse tunnel listener (stream_id=0 control frame).
    /// Payload (plaintext): [1B proto][2B listen_len BE][listen][2B target_len BE][target]
    RegisterReverse = 0x09,
    /// Acknowledge a reverse tunnel registration (stream_id=0 control frame).
    /// Payload (plaintext): [1B status (0=ok, 1=conflict, 2=disabled)][2B msg_len BE][msg]
    RegisterReverseAck = 0x0A,
    // ── Config-center frames (stream_id=0 control frames). Only used by the
    //    center session layer; the tunnel multiplexer ignores these. ──
    /// Node → center: register this node (carries node identity + capabilities).
    /// Payload (plaintext JSON): { node_id, version, capabilities }
    NodeRegister = 0x0B,
    /// Center → node: push a config update.
    /// Payload (plaintext JSON): { config_version, forwarders, tunnel_params }
    ConfigPush = 0x0C,
    /// Node → center: periodic status report.
    /// Payload (plaintext JSON): { snapshot, config_version_applied, uptime_secs }
    StatusReport = 0x0D,
    /// Node → center: acknowledge a config push.
    /// Payload (plaintext JSON): { config_version, ok, error }
    ConfigAck = 0x0E,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Open),
            0x02 => Ok(Self::OpenAck),
            0x03 => Ok(Self::Data),
            0x04 => Ok(Self::Close),
            0x05 => Ok(Self::Ping),
            0x06 => Ok(Self::Pong),
            0x07 => Ok(Self::Echo),
            0x08 => Ok(Self::EchoReply),
            0x09 => Ok(Self::RegisterReverse),
            0x0A => Ok(Self::RegisterReverseAck),
            0x0B => Ok(Self::NodeRegister),
            0x0C => Ok(Self::ConfigPush),
            0x0D => Ok(Self::StatusReport),
            0x0E => Ok(Self::ConfigAck),
            _ => Err(OpticalError::FrameDecode(format!("unknown frame type: {v}"))),
        }
    }
}

/// A decoded tunnel frame (before encryption/after decryption).
#[allow(dead_code)]
#[derive(Debug)]
pub struct Frame {
    pub stream_id: u32,
    pub counter: u64,
    pub frame_type: FrameType,
    pub payload: Bytes,
}

/// Build the 15-byte header bytes from components.
pub fn build_header(stream_id: u32, counter: u64, frame_type: FrameType, payload_len: u16) -> [u8; HEADER_SIZE] {
    let mut header = [0u8; HEADER_SIZE];
    header[0..4].copy_from_slice(&stream_id.to_be_bytes());
    header[4..12].copy_from_slice(&counter.to_be_bytes());
    header[12] = frame_type as u8;
    header[13..15].copy_from_slice(&payload_len.to_be_bytes());
    header
}

/// Parse a 15-byte header into (stream_id, counter, frame_type_raw, payload_len).
///
/// Returns the raw frame-type byte rather than a [`FrameType`] so that
/// callers can decide how to handle unknown types: a known type can be
/// converted via [`FrameType::from_u8`], while an unknown type (forward
/// compatibility) can be skipped without breaking the connection. This is
/// critical for protocol evolution — see "protocol compatibility" in
/// AGENTS.md.
pub fn parse_header(header: &[u8; HEADER_SIZE]) -> (u32, u64, u8, usize) {
    let stream_id = u32::from_be_bytes(header[0..4].try_into().unwrap());
    let counter = u64::from_be_bytes(header[4..12].try_into().unwrap());
    let frame_type_raw = header[12];
    let payload_len = u16::from_be_bytes(header[13..15].try_into().unwrap()) as usize;
    (stream_id, counter, frame_type_raw, payload_len)
}

// ── OPEN payload helpers ───────────────────────────────────────────────────

/// Encode an OPEN frame payload: [1B proto][2B target_len BE][target bytes]
pub fn encode_open_payload(proto_byte: u8, target: &str) -> Vec<u8> {
    let target_bytes = target.as_bytes();
    let mut payload = Vec::with_capacity(1 + 2 + target_bytes.len());
    payload.push(proto_byte);
    payload.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(target_bytes);
    payload
}

/// Decode an OPEN frame payload.
pub fn decode_open_payload(payload: &[u8]) -> Result<(u8, String)> {
    if payload.len() < 3 {
        return Err(OpticalError::FrameDecode("OPEN payload too short".into()));
    }
    let proto_byte = payload[0];
    let target_len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
    if payload.len() < 3 + target_len {
        return Err(OpticalError::FrameDecode("OPEN payload target truncated".into()));
    }
    let target = String::from_utf8(payload[3..3 + target_len].to_vec())
        .map_err(|e| OpticalError::FrameDecode(format!("invalid target string: {e}")))?;
    Ok((proto_byte, target))
}

/// Encode an OPEN_ACK payload: [1B status]
pub fn encode_open_ack_payload(success: bool) -> [u8; 1] {
    [if success { 0 } else { 1 }]
}

/// Decode an OPEN_ACK payload.
pub fn decode_open_ack_payload(payload: &[u8]) -> Result<bool> {
    if payload.is_empty() {
        return Err(OpticalError::FrameDecode("OPEN_ACK payload empty".into()));
    }
    Ok(payload[0] == 0)
}

// ── RegisterReverse payload helpers ─────────────────────────────────────────

/// Status of a reverse tunnel registration request.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReverseAckStatus {
    /// Registration succeeded.
    Ok = 0,
    /// Listen address already in use by another tunnel.
    Conflict = 1,
    /// Reverse tunneling is disabled on the server.
    Disabled = 2,
}

impl ReverseAckStatus {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Ok,
            2 => Self::Disabled,
            _ => Self::Conflict,
        }
    }
}

/// Encode a RegisterReverse payload:
/// `[1B proto][2B listen_len BE][listen][2B target_len BE][target]`
pub fn encode_register_reverse_payload(proto_byte: u8, listen: &str, target: &str) -> Vec<u8> {
    let listen_bytes = listen.as_bytes();
    let target_bytes = target.as_bytes();
    let mut payload = Vec::with_capacity(1 + 2 + listen_bytes.len() + 2 + target_bytes.len());
    payload.push(proto_byte);
    payload.extend_from_slice(&(listen_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(listen_bytes);
    payload.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(target_bytes);
    payload
}

/// Decode a RegisterReverse payload into `(proto_byte, listen, target)`.
pub fn decode_register_reverse_payload(payload: &[u8]) -> Result<(u8, String, String)> {
    if payload.len() < 5 {
        return Err(OpticalError::FrameDecode(
            "RegisterReverse payload too short".into(),
        ));
    }
    let proto_byte = payload[0];
    let listen_len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
    if payload.len() < 3 + listen_len + 2 {
        return Err(OpticalError::FrameDecode(
            "RegisterReverse listen truncated".into(),
        ));
    }
    let listen = String::from_utf8(payload[3..3 + listen_len].to_vec())
        .map_err(|e| OpticalError::FrameDecode(format!("invalid listen string: {e}")))?;
    let target_len = u16::from_be_bytes([
        payload[3 + listen_len],
        payload[4 + listen_len],
    ]) as usize;
    let target_start = 5 + listen_len;
    if payload.len() < target_start + target_len {
        return Err(OpticalError::FrameDecode(
            "RegisterReverse target truncated".into(),
        ));
    }
    let target = String::from_utf8(payload[target_start..target_start + target_len].to_vec())
        .map_err(|e| OpticalError::FrameDecode(format!("invalid target string: {e}")))?;
    Ok((proto_byte, listen, target))
}

/// Encode a RegisterReverseAck payload: `[1B status][2B msg_len BE][msg]`
pub fn encode_register_reverse_ack_payload(status: ReverseAckStatus, msg: &str) -> Vec<u8> {
    let msg_bytes = msg.as_bytes();
    let mut payload = Vec::with_capacity(1 + 2 + msg_bytes.len());
    payload.push(status as u8);
    payload.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(msg_bytes);
    payload
}

/// Decode a RegisterReverseAck payload into `(status, msg)`.
pub fn decode_register_reverse_ack_payload(
    payload: &[u8],
) -> Result<(ReverseAckStatus, String)> {
    if payload.is_empty() {
        return Err(OpticalError::FrameDecode(
            "RegisterReverseAck payload empty".into(),
        ));
    }
    let status = ReverseAckStatus::from_u8(payload[0]);
    if payload.len() < 3 {
        return Ok((status, String::new()));
    }
    let msg_len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
    if payload.len() < 3 + msg_len {
        return Ok((status, String::new()));
    }
    let msg = String::from_utf8(payload[3..3 + msg_len].to_vec())
        .map_err(|e| OpticalError::FrameDecode(format!("invalid ack message string: {e}")))?;
    Ok((status, msg))
}
