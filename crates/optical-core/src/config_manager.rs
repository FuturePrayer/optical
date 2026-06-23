//! Configuration hot-reload manager for center-managed nodes.
//!
//! When a node is managed by a config center, its forwarder set AND tunnel
//! server (Node2) settings are delivered via `ConfigPush` and may change at
//! runtime. The [`ConfigManager`] owns the currently-running forwarder and
//! tunnel-server tasks, applying new configs by cancelling the old task set
//! and starting a fresh one.
//!
//! Design: full-restart on each apply (not fine-grained diff). This is simple,
//! correct, and reuses [`crate::forward::run_forwarders`] and
//! [`crate::tunnel::server::run`] unchanged. Existing in-flight connections
//! are dropped on apply — acceptable for an MVP; a fine-grained diff can be
//! layered on later.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::admin::TunnelRegistry;
use crate::center::proto::{ConfigPushMsg, NodeServerConfig};
use crate::config::TunnelConfig;
use crate::crypto::pqdsa::DsaKeyPair;
use crate::forward;
use crate::metrics;
use crate::transport::AnyTransport;
use crate::tunnel;

/// Manages the node's forwarder + tunnel-server tasks, applying config pushes
/// from the center.
pub struct ConfigManager {
    /// Shared dependencies needed to spawn forwarders + tunnel server.
    deps: Arc<NodeDeps>,
    /// The currently-running forwarder supervisor task (if any) + its cancel.
    current_forwarders: Mutex<CurrentTask>,
    /// The currently-running tunnel-server task (if any) + its cancel.
    current_server: Mutex<CurrentTask>,
    /// Latest applied config version (for status reports / drift detection).
    applied_version: Mutex<u64>,
}

/// Shared dependencies for spawning both forwarder and tunnel-server tasks.
struct NodeDeps {
    /// Client-side transport (for forwarders to dial peers).
    transport: AnyTransport,
    /// TCP socket buffer size (for both client + server transports).
    socket_buffer_bytes: u64,
    /// KCP config (for both client + server transports).
    kcp_config: crate::transport::kcp::KcpConfig,
    psk: [u8; 32],
    dsa_keypair: DsaKeyPair,
    tunnel_config: TunnelConfig,
    tunnel_registry: Arc<TunnelRegistry>,
    /// Reverse-registry shared across tunnel-server instances (prevents port
    /// conflicts across hot-restarts).
    reverse_registry: Arc<crate::forward::reverse::ReverseRegistry>,
    /// Parent cancel — when the whole node shuts down, this fires.
    parent_cancel: CancellationToken,
}

struct CurrentTask {
    /// Cancel token for the current task set. Replacing this cancels the old.
    cancel: Option<CancellationToken>,
    /// The supervisor task (run_forwarders or tunnel::server::run). The task
    /// logs its own errors and returns (), so the JoinHandle type is uniform
    /// regardless of which underlying function spawned it.
    task: Option<JoinHandle<()>>,
}

impl Default for CurrentTask {
    fn default() -> Self {
        Self {
            cancel: None,
            task: None,
        }
    }
}

impl ConfigManager {
    /// Create a new manager. Forwarders and tunnel server are not started
    /// until [`apply`] is called with a config push.
    pub fn new(
        transport: AnyTransport,
        psk: [u8; 32],
        dsa_keypair: DsaKeyPair,
        tunnel_config: TunnelConfig,
        tunnel_registry: Arc<TunnelRegistry>,
        reverse_registry: Arc<crate::forward::reverse::ReverseRegistry>,
        socket_buffer_bytes: u64,
        kcp_config: crate::transport::kcp::KcpConfig,
        parent_cancel: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            deps: Arc::new(NodeDeps {
                transport,
                socket_buffer_bytes,
                kcp_config,
                psk,
                dsa_keypair,
                tunnel_config,
                tunnel_registry,
                reverse_registry,
                parent_cancel,
            }),
            current_forwarders: Mutex::new(CurrentTask::default()),
            current_server: Mutex::new(CurrentTask::default()),
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

    /// Apply a config push: restart forwarders (always) and tunnel server (if
    /// server_config changed). Updates `applied_version`.
    pub async fn apply(&self, push: ConfigPushMsg) -> Result<()> {
        let version = push.config_version;
        let forwarders = push.forwarders;
        let server_config = push.server_config;
        tracing::info!(
            config_version = version,
            forwarders = forwarders.len(),
            has_server_config = server_config.is_some(),
            "applying config push"
        );

        // 1. Restart forwarders (cancel old + start new).
        self.restart_forwarders(forwarders).await;

        // 2. Restart tunnel server if server_config is present.
        if let Some(sc) = server_config {
            self.restart_tunnel_server(sc).await;
        }

        // 3. Update applied version.
        *self.applied_version.lock().await = version;
        tracing::info!(config_version = version, "config applied");
        Ok(())
    }

    /// Cancel + drain old forwarders, then start the new set.
    async fn restart_forwarders(&self, forwarders: Vec<crate::config::ForwarderConfig>) {
        // Cancel + drain old.
        {
            let mut cur = self.current_forwarders.lock().await;
            drain_task(&mut cur, "forwarder").await;
        }

        // Start new (if non-empty).
        let mut new_cur = CurrentTask::default();
        if !forwarders.is_empty() {
            let child_cancel = self.deps.parent_cancel.child_token();
            new_cur.cancel = Some(child_cancel.clone());
            // Pre-register metrics.
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
                if let Err(e) = forward::run_forwarders(
                    transport, forwarders, psk, dsa_keypair, tunnel_cfg, child_cancel, registry,
                )
                .await
                {
                    tracing::error!("forwarder supervisor error: {e:#}");
                }
            }));
        }
        *self.current_forwarders.lock().await = new_cur;
    }

    /// Cancel + drain old tunnel server, then start the new one (or stop if
    /// tunnel_listen is None).
    async fn restart_tunnel_server(&self, sc: NodeServerConfig) {
        // Cancel + drain old.
        {
            let mut cur = self.current_server.lock().await;
            drain_task(&mut cur, "tunnel server").await;
        }

        let mut new_cur = CurrentTask::default();

        // Start new tunnel server if a listen address is configured.
        if let Some(listen_addr) = sc.tunnel_listen {
            let child_cancel = self.deps.parent_cancel.child_token();
            new_cur.cancel = Some(child_cancel.clone());

            // Construct a server transport for the requested transport kind.
            let server_transport = AnyTransport::for_server(
                sc.tunnel_transport,
                self.deps.socket_buffer_bytes,
                self.deps.kcp_config.clone(),
            );
            let psk = self.deps.psk;
            let dsa_keypair = self.deps.dsa_keypair.clone();
            let tunnel_cfg = self.deps.tunnel_config.clone();
            let allow_reverse = sc.allow_reverse;
            let rev_registry = self.deps.reverse_registry.clone();
            new_cur.task = Some(tokio::spawn(async move {
                if let Err(e) = tunnel::server::run(
                    server_transport,
                    listen_addr,
                    psk,
                    dsa_keypair,
                    tunnel_cfg,
                    allow_reverse,
                    rev_registry,
                    child_cancel,
                )
                .await
                {
                    tracing::error!("tunnel server error: {e:#}");
                }
            }));
            tracing::info!(
                listen = %listen_addr,
                transport = ?sc.tunnel_transport,
                allow_reverse,
                "tunnel server (re)started by config manager"
            );
        } else {
            tracing::info!("tunnel server stopped (no tunnel_listen in pushed config)");
        }

        *self.current_server.lock().await = new_cur;
    }

    /// Drain all tasks on shutdown.
    pub async fn shutdown(&self) {
        let mut fwd = self.current_forwarders.lock().await;
        drain_task(&mut fwd, "forwarder").await;
        let mut srv = self.current_server.lock().await;
        drain_task(&mut srv, "tunnel server").await;
    }
}

/// Cancel the task's token (if any) and await its completion with a 30s
/// timeout. Used during hot-reload and shutdown.
async fn drain_task(cur: &mut CurrentTask, label: &str) {
    if let Some(cancel) = cur.cancel.take() {
        cancel.cancel();
    }
    if let Some(task) = cur.task.take() {
        match tokio::time::timeout(std::time::Duration::from_secs(30), task).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!("old {label} task panicked: {e}"),
            Err(_) => tracing::warn!("old {label} task did not drain in 30s, abandoning"),
        }
    }
}
