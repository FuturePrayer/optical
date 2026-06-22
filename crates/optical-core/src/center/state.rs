//! Global center state: a process-wide handle to the [`NodeRegistry`] and
//! [`SessionMap`], stored in a [`OnceLock`] so the admin API (and any other
//! code path) can reach them without threading `Arc`s through every function
//! signature — mirroring the `metrics::try_get()` pattern.

use std::sync::{Arc, OnceLock};

use crate::center::registry::NodeRegistry;
use crate::center::server::SessionMap;

/// Process-wide center state (registry + live sessions + SSE broadcast hub).
#[derive(Clone)]
pub struct CenterState {
    pub registry: Arc<NodeRegistry>,
    pub sessions: SessionMap,
    pub hub: crate::center::events::EventHub,
}

static STATE: OnceLock<CenterState> = OnceLock::new();

/// Install the global center state. Called once from `app.rs` when the center
/// server starts. Subsequent calls are no-ops (the first wins).
pub fn init(state: CenterState) {
    let _ = STATE.set(state);
}

/// Get the global center state, if the center server is running.
pub fn try_get() -> Option<&'static CenterState> {
    STATE.get()
}
