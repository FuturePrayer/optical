//! Configuration hot-reload manager for the node role (Node1).
//!
//! When a node is managed by a config center, its forwarder set is delivered
//! via `ConfigPush` and may change at runtime. The [`ConfigManager`] owns the
//! currently-running forwarder tasks and applies new configs by cancelling
//! the old task set and starting a fresh one.
//!
//! Design: full-restart on each apply (not fine-grained diff). This is simple,
//! correct, and reuses [`crate::forward::run_forwarders`] unchanged. Existing
//! in-flight connections are dropped on apply — acceptable for an MVP; a
//! fine-grained diff (only restart forwarders whose listen/proto/target
//! changed) can be layered on later.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::admin::TunnelRegistry;
use crate::center::proto::ConfigPushMsg;
use crate::config::TunnelConfig;
use crate::crypto::pqdsa::DsaKeyPair;
use crate::forward;
use crate::metrics;
use crate::transport::AnyTransport;

/// Manages the node's forwarder tasks, applying config pushes from the center.
pub struct ConfigManager {
    /// Shared dependencies needed to spawn forwarders.
    deps: ForwarderDeps,
    /// The currently-running forwarder supervisor task (if any) + its cancel.
    current: Mutex<CurrentForwarders>,
    /// Latest applied config version (for status reports / drift detection).
    applied_version: Mutex<u64>,
}

struct ForwarderDeps {
    transport: AnyTransport,
    psk: [u8; 32],
    dsa_keypair: DsaKeyPair,
    tunnel_config: TunnelConfig,
    tunnel_registry: Arc<TunnelRegistry>,
    /// Parent cancel — when the whole node shuts down, this fires.
    parent_cancel: CancellationToken,
}

struct CurrentForwarders {
    /// Cancel token for the current forwarder set. Dropping/replacing this
    /// cancels the old tasks.
    cancel: Option<CancellationToken>,
    /// The supervisor task returned by `run_forwarders`.
    task: Option<JoinHandle<Result<()>>>,
}

impl ConfigManager {
    /// Create a new manager. Forwarders are not started until [`apply`] is
    /// called with a config push.
    pub fn new(
        transport: AnyTransport,
        psk: [u8; 32],
        dsa_keypair: DsaKeyPair,
        tunnel_config: TunnelConfig,
        tunnel_registry: Arc<TunnelRegistry>,
        parent_cancel: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            deps: ForwarderDeps {
                transport,
                psk,
                dsa_keypair,
                tunnel_config,
                tunnel_registry,
                parent_cancel,
            },
            current: Mutex::new(CurrentForwarders {
                cancel: None,
                task: None,
            }),
            applied_version: Mutex::new(0),
        })
    }

    /// The config version currently applied (0 = none yet). Used by the center
    /// client when building StatusReport messages.
    pub async fn applied_version(&self) -> u64 {
        *self.applied_version.lock().await
    }

    /// Run a loop that consumes `ConfigPushMsg`s from the channel and applies
    /// them. Intended to be spawned as a task. Exits when the channel closes
    /// or the parent cancel fires.
    pub async fn run_loop(self: Arc<Self>, mut rx: mpsc::Receiver<ConfigPushMsg>) {
        loop {
            tokio::select! {
                biased;
                _ = self.deps.parent_cancel.cancelled() => break,
                msg = rx.recv() => {
                    match msg {
                        Some(push) => {
                            if let Err(e) = self.apply(push).await {
                                tracing::error!("config apply failed: {e:#}");
                            }
                        }
                        None => break, // channel closed (center client stopped)
                    }
                }
            }
        }
        tracing::info!("config manager loop stopped");
    }

    /// Apply a config push: cancel the old forwarder set, wait for it to
    /// drain, then start the new one. Updates `applied_version`.
    pub async fn apply(&self, push: ConfigPushMsg) -> Result<()> {
        let version = push.config_version;
        let forwarders = push.forwarders;
        tracing::info!(
            config_version = version,
            forwarders = forwarders.len(),
            "applying config push"
        );

        // 1. Cancel + drain the old forwarder set.
        {
            let mut cur = self.current.lock().await;
            if let Some(cancel) = cur.cancel.take() {
                cancel.cancel();
            }
            if let Some(task) = cur.task.take() {
                // Bound the drain so a stuck forwarder can't block apply forever.
                match tokio::time::timeout(std::time::Duration::from_secs(30), task).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::warn!("old forwarder task errored on drain: {e:#}"),
                    Err(_) => tracing::warn!("old forwarder task did not drain in 30s, abandoning"),
                }
            }
        }

        // 2. Start the new forwarder set (if non-empty).
        let child_cancel = self.deps.parent_cancel.child_token();
        let mut new_cur = CurrentForwarders {
            cancel: Some(child_cancel.clone()),
            task: None,
        };

        if !forwarders.is_empty() {
            // Pre-register forwarder + tunnel metrics so Tunnel::new can find them.
            for fwd in &forwarders {
                if let Some(reg) = metrics::try_get() {
                    reg.register_forwarder(fwd.listen, fwd.proto, &fwd.target);
                    reg.register_tunnel(&fwd.tunnel, metrics::TunnelRole::Client);
                }
            }
            let transport = self.deps.transport.clone();
            let psk = self.deps.psk;
            let dsa_keypair = self.deps.dsa_keypair.clone();
            let tunnel_cfg = self.deps.tunnel_config.clone();
            let registry = self.deps.tunnel_registry.clone();
            new_cur.task = Some(tokio::spawn(async move {
                forward::run_forwarders(
                    transport,
                    forwarders,
                    psk,
                    dsa_keypair,
                    tunnel_cfg,
                    child_cancel,
                    registry,
                )
                .await
            }));
        }

        // 3. Swap in the new state + version.
        *self.current.lock().await = new_cur;
        *self.applied_version.lock().await = version;
        tracing::info!(config_version = version, "config applied");
        Ok(())
    }

    /// Drain the current forwarder set on shutdown.
    pub async fn shutdown(&self) {
        let mut cur = self.current.lock().await;
        if let Some(cancel) = cur.cancel.take() {
            cancel.cancel();
        }
        if let Some(task) = cur.task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(30), task).await;
        }
    }
}
