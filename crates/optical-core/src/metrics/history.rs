//! Ring-buffer time-series storage for metrics history.
//!
//! Samples are taken every 10 seconds and retained for 60 minutes (360 samples).

use std::collections::VecDeque;

use serde::Serialize;

use super::{ForwarderSnapshot, TunnelSnapshot};

const SAMPLE_INTERVAL_SECS: u64 = 10;
const MAX_SAMPLES: usize = 360; // 60 minutes at 10s interval

#[derive(Debug, Serialize)]
pub struct Sample {
    /// Unix epoch seconds.
    pub timestamp: u64,
    pub tunnels: Vec<TunnelSnapshot>,
    pub forwarders: Vec<ForwarderSnapshot>,
}

pub struct HistoryBuffer {
    samples: VecDeque<Sample>,
}

impl HistoryBuffer {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_SAMPLES),
        }
    }

    /// Push a new sample. Old samples are evicted beyond `MAX_SAMPLES`.
    pub fn push(&mut self, tunnels: Vec<TunnelSnapshot>, forwarders: Vec<ForwarderSnapshot>) {
        if self.samples.len() >= MAX_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(Sample {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            tunnels,
            forwarders,
        });
    }

    /// Return all stored samples.
    pub fn samples(&self) -> &VecDeque<Sample> {
        &self.samples
    }
}

/// Spawn a background task that samples metrics every 10 seconds.
pub fn spawn_sampler(cancel: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(SAMPLE_INTERVAL_SECS);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(interval) => {
                    if let Some(reg) = super::try_get() {
                        let snap = reg.snapshot();
                        reg.history.lock().unwrap().push(snap.tunnels, snap.forwarders);
                    }
                }
            }
        }
    });
}
