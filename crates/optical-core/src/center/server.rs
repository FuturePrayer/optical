//! Center server: accepts node connections, runs a per-node session, and
//! coordinates config pushes + status collection via the [`NodeRegistry`].
//!
//! The accept loop mirrors [`crate::tunnel::server::run`] (PQ handshake +
//! spawn-per-connection), but the session is the center protocol
//! (NodeRegister/ConfigPush/StatusReport/ConfigAck) rather than the
//! multiplexed-tunnel OPEN protocol.
//!
//! Config push path: the admin API (or approval flow) calls
//! [`NodeRegistry::approve`], then [`push_config`] delivers the new config to
//! the node's live session via a per-session mpsc channel.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::center::events::CenterEvent;
use crate::center::proto::{self, ConfigPushMsg, NodeRegisterMsg, StatusReportMsg};
use crate::center::registry::NodeRegistry;
use crate::config::ForwarderConfig;
use crate::crypto::pqdsa::DsaKeyPair;
use crate::proto::frame::FrameType;
use crate::transport::{AnyTransport, Listen};
use crate::tunnel::server::server_handshake;

/// A live session for one connected node, keyed by node_id. Held in a shared
/// map so the admin API / approval flow can push configs to it.
struct LiveSession {
    /// Sender for outbound ConfigPush messages. If the receiver is dropped
    /// (session ended), `try_send` fails and the push is silently dropped.
    push_tx: mpsc::Sender<ConfigPushMsg>,
}

/// Shared map of node_id → live session. Wrapped in the registry handle so
/// any caller (admin API, approval) can push a config to a connected node.
#[derive(Clone)]
pub struct SessionMap {
    inner: Arc<Mutex<HashMap<String, LiveSession>>>,
}

impl SessionMap {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Push a config to a connected node. Returns false if the node is not
    /// currently connected (the caller may leave the config in the registry
    /// for delivery on next connect).
    pub async fn push(&self, node_id: &str, push: ConfigPushMsg) -> bool {
        let map = self.inner.lock().await;
        if let Some(s) = map.get(node_id) {
            s.push_tx.try_send(push).is_ok()
        } else {
            false
        }
    }

    async fn insert(&self, node_id: String, session: LiveSession) {
        self.inner.lock().await.insert(node_id, session);
    }

    async fn remove(&self, node_id: &str) {
        self.inner.lock().await.remove(node_id);
    }
}

/// Run the center server: accept connections, handshake, spawn a session per
/// node. Runs until `cancel` is triggered.
pub async fn run(
    transport: AnyTransport,
    listen_addr: SocketAddr,
    psk: [u8; 32],
    dsa_keypair: DsaKeyPair,
    registry: Arc<NodeRegistry>,
    sessions: SessionMap,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let mut listener = transport.listen(listen_addr).await?;
    tracing::info!("config center listening on {}", listen_addr);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            accept = listener.accept() => {
                let (mut stream, peer_addr) = match accept {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("center accept error: {e}");
                        continue;
                    }
                };
                tracing::info!("center connection from {}", peer_addr);

                let psk = psk;
                let dsa_keypair = dsa_keypair.clone();
                let registry = registry.clone();
                let sessions = sessions.clone();
                let cancel = cancel.clone();

                tokio::spawn(async move {
                    match server_handshake(&mut stream, psk, dsa_keypair).await {
                        Ok(handshake) => {
                            let peer_node_id = handshake.peer_node_id.clone().unwrap_or_default();
                            tracing::info!("center handshake ok, peer node_id={peer_node_id}");
                            let (read_half, write_half) = tokio::io::split(stream);
                            if let Err(e) = run_session(
                                read_half, write_half,
                                handshake, peer_node_id, peer_addr,
                                registry, sessions, cancel,
                            ).await {
                                tracing::debug!("center session ended: {e}");
                            }
                        }
                        Err(e) => {
                            tracing::warn!("center handshake failed from {peer_addr}: {e}");
                        }
                    }
                });
            }
        }
    }

    tracing::info!("config center server stopped");
    Ok(())
}

/// Run one node's session: register, then loop reading frames and pushing
/// configs as they arrive on the per-session channel.
async fn run_session(
    read_half: tokio::io::ReadHalf<Box<dyn crate::transport::Duplex>>,
    write_half: tokio::io::WriteHalf<Box<dyn crate::transport::Duplex>>,
    handshake: crate::crypto::handshake::HandshakeResult,
    peer_node_id: String,
    peer_addr: std::net::SocketAddr,
    registry: Arc<NodeRegistry>,
    sessions: SessionMap,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let send_cipher = handshake.send_cipher;
    let recv_cipher = handshake.recv_cipher;

    // write_half is shared between the reader (which replies to Ping/acks)
    // and the push channel. Protect it with a mutex.
    let write = Arc::new(Mutex::new(write_half));
    let mut send_counter: u64 = 0u64;

    // Per-session channel for outbound config pushes.
    let (push_tx, mut push_rx) = mpsc::channel::<ConfigPushMsg>(16);
    sessions.insert(peer_node_id.clone(), LiveSession { push_tx }).await;

    // On drop, mark the node offline and remove the session.
    let node_id_for_cleanup = peer_node_id.clone();
    let sessions_for_cleanup = sessions.clone();
    let registry_for_cleanup = registry.clone();
    let cleanup = async move {
        registry_for_cleanup.on_disconnect(&node_id_for_cleanup);
        sessions_for_cleanup.remove(&node_id_for_cleanup).await;
        if let Some(state) = crate::center::state::try_get() {
            let _ = state
                .hub
                .broadcast(CenterEvent::NodeOffline {
                    node_id: node_id_for_cleanup.clone(),
                })
                .await;
        }
    };

    let mut read_half = read_half;
    let mut last_heartbeat = tokio::time::Instant::now();
    // Drop a session if no frame (ping/pong/status/any) arrives within this
    // window. Tuned to 90s = 6× the default 15s status interval, so a node
    // missing a few reports (network jitter) is tolerated.
    let heartbeat_check = Duration::from_secs(90);
    let mut heartbeat_timer = tokio::time::interval(heartbeat_check);
    heartbeat_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let pending_push = push_rx.recv();
        tokio::pin!(pending_push);

        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            // Active heartbeat timer: even if the node goes fully silent (no
            // frames at all), this fires and lets us detect the timeout.
            _ = heartbeat_timer.tick() => {
                if last_heartbeat.elapsed() > heartbeat_check {
                    tracing::warn!("center session {} heartbeat timeout ({}s), dropping",
                        peer_node_id, last_heartbeat.elapsed().as_secs());
                    break;
                }
            }
            res = proto::read_frame(&mut read_half, &recv_cipher) => {
                match res {
                    Ok(Some((ft, plaintext))) => {
                        // Any valid frame is proof of liveness — update the
                        // heartbeat timestamp for ALL frame types (not just
                        // Ping/Pong), since nodes send StatusReport every ~15s
                        // as their keepalive.
                        last_heartbeat = tokio::time::Instant::now();
                        match ft {
                            FrameType::NodeRegister => {
                                let msg: NodeRegisterMsg = match serde_json::from_slice(&plaintext) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        tracing::warn!("invalid NodeRegister: {e}");
                                        continue;
                                    }
                                };
                                tracing::info!(
                                    node_id = %msg.node_id,
                                    version = %msg.version,
                                    "node registered"
                                );
                                let (record, approved) =
                                    registry.on_connect(&msg.node_id, &msg.version, peer_addr);
                                // Emit events for the admin UI.
                                if let Some(state) = crate::center::state::try_get() {
                                    let _ = state.hub.broadcast(CenterEvent::NodeRegistered {
                                        node_id: msg.node_id.clone(),
                                        version: msg.version.clone(),
                                    }).await;
                                    let _ = state.hub.broadcast(CenterEvent::NodeOnline {
                                        node_id: msg.node_id.clone(),
                                    }).await;
                                    if !approved {
                                        let _ = state.hub.broadcast(CenterEvent::PendingRequest {
                                            node_id: msg.node_id.clone(),
                                        }).await;
                                    }
                                }
                                if approved && (!record.forwarders.is_empty() || record.server_config.is_some()) {
                                    // Immediately push the assigned config.
                                    let push = ConfigPushMsg {
                                        config_version: record.config_version,
                                        forwarders: record.forwarders.clone(),
                                        server_config: record.server_config.clone(),
                                    };
                                    let mut w = write.lock().await;
                                    let _ = proto::write_frame(
                                        &mut *w, &send_cipher, send_counter,
                                        FrameType::ConfigPush, &push,
                                    ).await;
                                    send_counter += 1;
                                } else if !approved {
                                    tracing::info!(
                                        node_id = %msg.node_id,
                                        "node pending approval (not in whitelist)"
                                    );
                                    // Keep the session alive so the admin API
                                    // can approve + push without a reconnect.
                                }
                            }
                            FrameType::StatusReport => {
                                if let Ok(report) = serde_json::from_slice::<StatusReportMsg>(&plaintext) {
                                    registry.on_status(&peer_node_id, report);
                                    if let Some(state) = crate::center::state::try_get() {
                                        let _ = state.hub.broadcast(CenterEvent::NodeStatus {
                                            node_id: peer_node_id.clone(),
                                        }).await;
                                    }
                                }
                            }
                            FrameType::ConfigAck => {
                                tracing::debug!("node {} acked config", peer_node_id);
                            }
                            FrameType::Ping => {
                                let mut w = write.lock().await;
                                let _ = proto::write_frame(
                                    &mut *w, &send_cipher, send_counter,
                                    FrameType::Pong, &serde_json::json!({}),
                                ).await;
                                send_counter += 1;
                            }
                            FrameType::Pong => {
                                // Pong is a heartbeat reply; liveness already
                                // updated at the top of this branch.
                            }
                            _ => {
                                tracing::trace!(?ft, "ignoring center frame on server");
                            }
                        }
                    }
                    Ok(None) => { /* unknown frame skipped */ }
                    Err(e) => {
                        tracing::debug!("center session read error: {e}");
                        break;
                    }
                }
            }
            Some(push) = &mut pending_push => {
                let mut w = write.lock().await;
                if proto::write_frame(
                    &mut *w, &send_cipher, send_counter,
                    FrameType::ConfigPush, &push,
                ).await.is_err() {
                    break;
                }
                send_counter += 1;
                tracing::info!(
                    node_id = %peer_node_id,
                    config_version = push.config_version,
                    "pushed config to node"
                );
            }
        }
    }

    cleanup.await;
    Ok(())
}

/// Push a config to a node (used by the admin API / approval flow). Updates
/// the registry and, if the node is connected, delivers it immediately.
pub async fn push_config(
    registry: &NodeRegistry,
    sessions: &SessionMap,
    node_id: &str,
    forwarders: Vec<ForwarderConfig>,
    server_config: Option<crate::center::proto::NodeServerConfig>,
) -> bool {
    // approve() bumps config_version and stores the forwarders + server_config.
    registry.approve(node_id, forwarders.clone(), server_config);
    let rec = match registry.get(node_id) {
        Some(r) => r,
        None => return false,
    };
    let push = ConfigPushMsg {
        config_version: rec.config_version,
        forwarders: rec.forwarders,
        server_config: rec.server_config,
    };
    sessions.push(node_id, push).await
}
