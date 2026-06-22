//! Event hub: broadcast center events (node online/offline/status/config) to
//! SSE subscribers. Subscribers are the `/api/events` connections held open by
//! the browser's `EventSource`.

use std::sync::Arc;

use serde::Serialize;
use tokio::sync::{broadcast, Mutex};

/// Maximum buffered events per subscriber before older ones are dropped.
const CHANNEL_CAPACITY: usize = 256;

/// A center event, serialized as an SSE `data:` line.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum CenterEvent {
    NodeOnline { node_id: String },
    NodeOffline { node_id: String },
    NodeStatus { node_id: String },
    NodeRegistered { node_id: String, version: String },
    ConfigPushed { node_id: String, config_version: u64 },
    PendingRequest { node_id: String },
}

/// Broadcast hub: holds a set of subscriber channels. Cloning is cheap (Arc).
#[derive(Clone)]
pub struct EventHub {
    subs: Arc<Mutex<Vec<broadcast::Sender<CenterEvent>>>>,
}

impl EventHub {
    pub fn new() -> Self {
        Self {
            subs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Subscribe to events. Returns a receiver that yields events until the
    /// hub is dropped or the subscriber lags (lagging yields a
    /// `broadcast::error::RecvError::Lagged`, which the caller should skip).
    pub async fn subscribe(&self) -> broadcast::Receiver<CenterEvent> {
        let (tx, rx) = broadcast::channel(CHANNEL_CAPACITY);
        self.subs.lock().await.push(tx);
        rx
    }

    /// Broadcast an event to all subscribers. Stale subscribers (whose
    /// receiver was dropped) are pruned.
    pub async fn broadcast(&self, event: CenterEvent) {
        let mut subs = self.subs.lock().await;
        let mut keep = Vec::with_capacity(subs.len());
        for tx in subs.drain(..) {
            // send: broadcast channels use `send` (not `try_send`); a full
            // channel lags the receiver (it gets a Lagged error on next recv,
            // which the SSE handler skips). receiver_count()==0 means dropped.
            if tx.receiver_count() > 0 {
                let _ = tx.send(event.clone());
                keep.push(tx);
            }
        }
        *subs = keep;
    }
}
