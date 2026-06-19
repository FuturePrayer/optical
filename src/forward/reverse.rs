//! Reverse tunnel support.
//!
//! In reverse mode, Node2 (the tunnel server) listens on a local port and
//! forwards incoming connections *back* through the tunnel to Node1 (the
//! tunnel client), which dials the final target. This is useful when Node1
//! sits behind NAT without a public IP.
//!
//! ## Protocol
//!
//! 1. Node1 sends `RegisterReverse(proto, listen, target)` to Node2 after the
//!    tunnel is established.
//! 2. Node2 checks its global [`ReverseRegistry`] for port conflicts, binds
//!    the listener, and replies with `RegisterReverseAck(status, msg)`.
//! 3. For each accepted connection, Node2 opens a stream (sends `OPEN`) back
//!    to Node1, which dials `target` using the existing `dial` module.
//! 4. When the tunnel disconnects, Node2's reverse listeners are cancelled
//!    and their listen addresses are released. Node1 re-registers on reconnect.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::config::ForwarderConfig;
use crate::proto::frame::ReverseAckStatus;
use crate::proto::stream::IncomingReverse;
use crate::tunnel::client::TunnelClient;
use crate::tunnel::Tunnel;

// ── ReverseRegistry ─────────────────────────────────────────────────────────

/// Global registry of reverse listen addresses, shared across all tunnel
/// connections on the server side.
///
/// Ensures that only the first Node1 to request a given `listen` address
/// succeeds; subsequent requests for the same address are rejected with
/// `Conflict`. When a tunnel disconnects, its listener is cancelled and the
/// address is released for re-registration (by the same Node1 after reconnect
/// or by a different Node1).
pub struct ReverseRegistry {
    /// Map: listen address → the listener task's cancel token.
    inner: std::sync::Mutex<HashMap<SocketAddr, CancellationToken>>,
}

impl ReverseRegistry {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Try to register a listen address.
    ///
    /// Returns the listener's `CancellationToken` if successful, or `None` if
    /// the address is already registered and still alive. Stale entries
    /// (cancelled token from a dead tunnel) are evicted automatically.
    pub fn register(&self, addr: SocketAddr) -> Option<CancellationToken> {
        let mut entries = self.inner.lock().unwrap();
        if entries.get(&addr).is_some_and(|t| !t.is_cancelled()) {
            return None; // conflict — still alive
        }
        // Stale entry (if any) is evicted by the insert below.
        let token = CancellationToken::new();
        entries.insert(addr, token.clone());
        Some(token)
    }

    /// Release a listen address (called when the listener task exits).
    pub fn unregister(&self, addr: SocketAddr) {
        self.inner.lock().unwrap().remove(&addr);
    }
}

impl Default for ReverseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Node2 side: handle incoming RegisterReverse requests ────────────────────

/// Process incoming RegisterReverse requests on the server side.
///
/// For each request:
/// - If reverse is disabled, replies with `Disabled`.
/// - If the listen address is already in use, replies with `Conflict`.
/// - Otherwise, binds the listener, replies with `Ok`, and spawns a listener
///   task that accepts connections and opens streams back to the client.
///
/// The listener tasks are tied to `tunnel_cancel` (the tunnel's lifetime) and
/// `listener_cancel` (from the registry). When either fires, the listener
/// stops and releases its address.
pub async fn handle_reverse_requests(
    tunnel: Tunnel,
    mut reverse_rx: mpsc::Receiver<IncomingReverse>,
    allow_reverse: bool,
    registry: Arc<ReverseRegistry>,
    udp_idle_secs: u64,
    cancel: CancellationToken,
) {
    tracing::info!("processing incoming RegisterReverse requests");

    while let Some(req) = reverse_rx.recv().await {
        if cancel.is_cancelled() || !tunnel.is_alive() {
            break;
        }

        let listen_addr: SocketAddr = match req.listen.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("invalid reverse listen address '{}': {e}", req.listen);
                let _ = tunnel
                    .send_register_reverse_ack(
                        ReverseAckStatus::Conflict,
                        "invalid listen address",
                    )
                    .await;
                continue;
            }
        };

        if !allow_reverse {
            tracing::warn!(
                "reverse tunneling disabled, rejecting request for {}",
                req.listen
            );
            let _ = tunnel
                .send_register_reverse_ack(
                    ReverseAckStatus::Disabled,
                    "reverse tunneling disabled on this server",
                )
                .await;
            continue;
        }

        // Try to register in the global registry (atomic check + insert).
        let listener_cancel = match registry.register(listen_addr) {
            Some(token) => token,
            None => {
                tracing::warn!(
                    "reverse listen {} already in use, rejecting",
                    req.listen
                );
                let _ = tunnel
                    .send_register_reverse_ack(
                        ReverseAckStatus::Conflict,
                        "listen address already registered by another tunnel",
                    )
                    .await;
                continue;
            }
        };

        let tunnel_cancel = tunnel.cancel_token();
        let target = req.target.clone();
        let tunnel_clone = tunnel.clone();
        let registry_clone = registry.clone();

        match req.proto_byte {
            0x01 => {
                // TCP
                let listener = match TcpListener::bind(listen_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(
                            "failed to bind reverse TCP listener on {}: {e}",
                            req.listen
                        );
                        registry_clone.unregister(listen_addr);
                        let _ = tunnel
                            .send_register_reverse_ack(
                                ReverseAckStatus::Conflict,
                                &format!("bind failed: {e}"),
                            )
                            .await;
                        continue;
                    }
                };

                // Send ack: ok
                let _ = tunnel.send_register_reverse_ack(ReverseAckStatus::Ok, "").await;
                tracing::info!(
                    "reverse TCP listener: {} → via tunnel → {}",
                    req.listen,
                    req.target
                );

                tokio::spawn(run_reverse_tcp_listener(
                    listener,
                    listen_addr,
                    target,
                    tunnel_clone,
                    registry_clone,
                    tunnel_cancel,
                    listener_cancel,
                ));
            }
            0x02 => {
                // UDP
                let socket = match UdpSocket::bind(listen_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(
                            "failed to bind reverse UDP listener on {}: {e}",
                            req.listen
                        );
                        registry_clone.unregister(listen_addr);
                        let _ = tunnel
                            .send_register_reverse_ack(
                                ReverseAckStatus::Conflict,
                                &format!("bind failed: {e}"),
                            )
                            .await;
                        continue;
                    }
                };

                // Send ack: ok
                let _ = tunnel.send_register_reverse_ack(ReverseAckStatus::Ok, "").await;
                tracing::info!(
                    "reverse UDP listener: {} → via tunnel → {}",
                    req.listen,
                    req.target
                );

                let udp_idle = Duration::from_secs(udp_idle_secs);
                tokio::spawn(run_reverse_udp_listener(
                    socket,
                    listen_addr,
                    target,
                    tunnel_clone,
                    registry_clone,
                    tunnel_cancel,
                    listener_cancel,
                    udp_idle,
                ));
            }
            _ => {
                tracing::warn!(
                    "unknown protocol byte for reverse: {}",
                    req.proto_byte
                );
                registry_clone.unregister(listen_addr);
                let _ = tunnel
                    .send_register_reverse_ack(
                        ReverseAckStatus::Conflict,
                        "unknown protocol",
                    )
                    .await;
            }
        }
    }

    tracing::info!("RegisterReverse handler stopped");
}

/// Reverse TCP listener: accepts local connections and forwards them back
/// through the tunnel via `OPEN` frames.
async fn run_reverse_tcp_listener(
    listener: TcpListener,
    listen: SocketAddr,
    target: String,
    tunnel: Tunnel,
    registry: Arc<ReverseRegistry>,
    tunnel_cancel: CancellationToken,
    listener_cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = tunnel_cancel.cancelled() => break,
            _ = listener_cancel.cancelled() => break,
            accept = listener.accept() => {
                let (local_stream, peer) = match accept {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("reverse TCP accept error on {}: {e}", listen);
                        continue;
                    }
                };
                let tunnel = tunnel.clone();
                let target = target.clone();
                tokio::spawn(async move {
                    tracing::debug!("reverse TCP: new connection from {}", peer);
                    if let Err(e) = crate::forward::tcp::forward_via_tunnel(
                        local_stream, target, tunnel, None,
                    )
                    .await
                    {
                        tracing::debug!("reverse TCP forward from {} error: {e}", peer);
                    }
                });
            }
        }
    }

    registry.unregister(listen);
    tracing::info!("reverse TCP listener on {} stopped", listen);
}

/// Reverse UDP listener: accepts local datagrams and forwards them back
/// through the tunnel via `OPEN` frames.
///
/// Each unique source address is mapped to a single tunnel stream, mirroring
/// the normal UDP forwarder's session management.
#[allow(clippy::too_many_arguments)]
async fn run_reverse_udp_listener(
    socket: UdpSocket,
    listen: SocketAddr,
    target: String,
    tunnel: Tunnel,
    registry: Arc<ReverseRegistry>,
    tunnel_cancel: CancellationToken,
    listener_cancel: CancellationToken,
    udp_idle: Duration,
) {
    let socket = Arc::new(socket);
    let sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Bytes>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut buf = [0u8; 65535];

    loop {
        tokio::select! {
            biased;
            _ = tunnel_cancel.cancelled() => break,
            _ = listener_cancel.cancelled() => break,
            result = socket.recv_from(&mut buf) => {
                let (n, src) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("reverse UDP recv error on {}: {e}", listen);
                        continue;
                    }
                };
                let data = Bytes::copy_from_slice(&buf[..n]);

                let existing = {
                    let sessions = sessions.lock().await;
                    sessions.get(&src).cloned()
                };

                match existing {
                    Some(tx) => {
                        let _ = tx.send(data).await;
                    }
                    None => {
                        // New session
                        let (data_tx, data_rx) = mpsc::channel(64);
                        {
                            let mut sessions = sessions.lock().await;
                            sessions.insert(src, data_tx.clone());
                        }
                        let _ = data_tx.send(data).await;

                        let socket = socket.clone();
                        let sessions = sessions.clone();
                        let tunnel = tunnel.clone();
                        let target = target.clone();
                        let cancel = tunnel_cancel.clone();

                        tokio::spawn(async move {
                            if let Err(e) = crate::forward::udp::udp_session_with_tunnel(
                                socket, src, target, tunnel, sessions, data_rx, udp_idle, cancel, None,
                            )
                            .await
                            {
                                tracing::debug!("reverse UDP session {} error: {e}", src);
                            }
                        });
                    }
                }
            }
        }
    }

    registry.unregister(listen);
    tracing::info!("reverse UDP listener on {} stopped", listen);
}

// ── Node1 side: register reverse forwarders with the peer ───────────────────

/// Register all reverse forwarders with the tunnel server (Node2).
///
/// After the tunnel is established, sends a `RegisterReverse` for each
/// reverse forwarder and waits for the ack. If any registration fails
/// (conflict or disabled), returns an error — the caller should exit the
/// process. On tunnel disconnect, waits for reconnection and re-registers.
pub async fn register_reverse_forwarders(
    tunnel_client: Arc<Mutex<TunnelClient>>,
    reverse_fwds: Vec<ForwarderConfig>,
    cancel: CancellationToken,
) -> Result<()> {
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }

        // Wait for tunnel
        let tunnel = {
            let mut tc = tunnel_client.lock().await;
            match tc.get_tunnel().await {
                Some(t) => t,
                None => return Ok(()), // cancelled
            }
        };

        // Register all reverse items serially
        for fwd in &reverse_fwds {
            let proto_byte = crate::crypto::handshake::proto_to_byte(fwd.proto);
            let listen_str = fwd.listen.to_string();

            tracing::info!(
                "registering reverse: proto={} listen={} target={}",
                fwd.proto,
                fwd.listen,
                fwd.target
            );

            let result = tunnel
                .register_reverse(proto_byte, &listen_str, &fwd.target)
                .await;

            match result {
                Ok((ReverseAckStatus::Ok, _msg)) => {
                    tracing::info!(
                        "reverse registration accepted: {} → {}",
                        fwd.listen,
                        fwd.target
                    );
                }
                Ok((status, msg)) => {
                    let status_str = match status {
                        ReverseAckStatus::Conflict => "conflict",
                        ReverseAckStatus::Disabled => "disabled",
                        ReverseAckStatus::Ok => "ok",
                    };
                    anyhow::bail!(
                        "reverse registration failed for {} ({}): {} — \
                         this is a deployment configuration conflict; \
                         stopping the node",
                        fwd.listen,
                        status_str,
                        msg
                    );
                }
                Err(e) => {
                    anyhow::bail!(
                        "reverse registration error for {}: {e} — stopping the node",
                        fwd.listen
                    );
                }
            }
        }

        tracing::info!("all reverse forwarders registered successfully");

        // Wait for tunnel to die, then re-register.
        let tunnel_cancel = tunnel.cancel_token();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = tunnel_cancel.cancelled() => {
                tracing::info!(
                    "tunnel disconnected, will re-register reverse forwarders after reconnect"
                );
            }
        }
    }
}
