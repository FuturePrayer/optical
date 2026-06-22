//! Shared core library for the `optical` node binary and the
//! `optical-center` config center binary.
//!
//! All tunnel, crypto, transport, forwarding, dial, metrics, admin, service,
//! and config logic lives here. The two binaries in the workspace are thin
//! CLI dispatchers over this library.
//!
//! # Features
//!
//! - `node` (default): forwarders, tunnel server/client, dial, node admin API.
//! - `center`: config-center server, REST/SSE admin API, embedded web UI.
//!   The node-side `CenterClient` is always compiled (so a plain `optical`
//!   node can connect to a center); only the *server* side is feature-gated.

pub mod admin;
pub mod app;
pub mod center;
pub mod config;
pub mod config_manager;
pub mod crypto;
pub mod dial;
pub mod error;
pub mod forward;
pub mod metrics;
pub mod paths;
pub mod proto;
pub mod service;
pub mod transport;
pub mod tunnel;
pub mod updater;

/// CLI subcommand implementations shared by both binaries.
pub mod cli;

/// Embedded web UI assets (center feature only).
#[cfg(feature = "center")]
pub mod webui;
