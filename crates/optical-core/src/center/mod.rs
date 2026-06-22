//! Config-center session layer.
//!
//! This module groups everything related to the config-center feature:
//!
//! - [`proto`]: the wire protocol (JSON messages over encrypted frames, shared
//!   by client and server). **Always compiled** — it has no feature gate.
//! - [`client`]: the node-side [`CenterClient`] that connects to a center,
//!   registers, receives config pushes, and reports status. **Always
//!   compiled** (a plain `optical` node can connect to a center when its
//!   config has a `center:` block).
//! - `server` (only under the `center` feature): the center server that
//!   accepts node connections, manages the node registry, and pushes configs.
//!
//! The center session is a **separate connection** from the multiplexed
//! tunnel: it runs its own PQ handshake and exchanges `stream_id=0` control
//! frames (`NodeRegister`, `ConfigPush`, `StatusReport`, `ConfigAck`). See
//! [`proto`] for the wire format.

pub mod proto;

/// Node-side center client (always compiled).
pub mod client;

/// Event broadcast hub for SSE (always compiled — small, no deps).
pub mod events;

// ── center-feature-only modules below ──────────────────────────────────────

/// Global center state (registry + sessions + hub), OnceLock-backed.
/// Only under `center` — references NodeRegistry/SessionMap which are gated.
#[cfg(feature = "center")]
pub mod state;

// Center server (only when building optical-center).
#[cfg(feature = "center")]
pub mod server;

#[cfg(feature = "center")]
pub mod registry;

/// Web admin (REST + SSE + embedded webui). Only under the `center` feature.
#[cfg(feature = "center")]
pub mod web_admin;
