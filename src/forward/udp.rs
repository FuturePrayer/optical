//! UDP forwarder: accepts local UDP datagrams and forwards them through the tunnel.
//!
//! Each unique client source address (ip:port) is mapped to a single tunnel stream.
//! Streams idle for longer than `udp_idle_secs` are automatically closed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::config::TunnelConfig;
use crate::crypto::handshake::proto_to_byte;
use crate::metrics::{self, ForwarderMetrics};
use crate::proto::frame::FrameType;
use crate::proto::stream::{OutboundFrame, StreamIn};
use crate::tunnel::client::TunnelClient;

/// Run a UDP forwarder: listen on `listen`, forward to `target` via tunnel.
pub async fn run(
    listen: SocketAddr,
    target: String,
    tunnel_client: Arc<Mutex<TunnelClient>>,
    config: TunnelConfig,
    cancel: CancellationToken,
) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(listen).await?);
    tracing::info!("UDP forwarder: {} → via tunnel → {}", listen, target);

    // Look up forwarder metrics (if registered)
    let fwd_metrics = metrics::try_get().and_then(|reg| reg.get_forwarder(listen));

    // Map: source address → channel to send data to the session task
    let sessions: Arc<Mutex<HashMap<SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let udp_idle = Duration::from_secs(config.udp_idle_secs);
    let mut buf = [0u8; 65535];

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            result = socket.recv_from(&mut buf) => {
                let (n, src) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("UDP recv error on {}: {e}", listen);
                        continue;
                    }
                };
                let data = Bytes::copy_from_slice(&buf[..n]);

                // Check for existing session
                let existing = {
                    let sessions = sessions.lock().await;
                    sessions.get(&src).cloned()
                };

                match existing {
                    Some(tx) => {
                        // Forward to existing session
                        let _ = tx.send(data).await;
                    }
                    None => {
                        // New session: create channel, register, spawn task
                        let (data_tx, data_rx) = tokio::sync::mpsc::channel(64);
                        {
                            let mut sessions = sessions.lock().await;
                            sessions.insert(src, data_tx.clone());
                        }
                        // Send initial datagram
                        let _ = data_tx.send(data).await;

                        let socket = socket.clone();
                        let sessions = sessions.clone();
                        let tc = tunnel_client.clone();
                        let target = target.clone();
                        let cancel = cancel.clone();
                        let metrics = fwd_metrics.clone();

                        // Count new stream
                        if let Some(ref m) = metrics {
                            m.total_streams.fetch_add(1, Ordering::Relaxed);
                            m.active_streams.fetch_add(1, Ordering::Relaxed);
                        }

                        tokio::spawn(async move {
                            if let Err(e) = udp_session(
                                socket, src, target, tc, sessions, data_rx, udp_idle, cancel, metrics.clone(),
                            ).await {
                                tracing::debug!("UDP session {} error: {e}", src);
                            }
                            // Decrement active streams on exit
                            if let Some(ref m) = metrics {
                                m.active_streams.fetch_sub(1, Ordering::Relaxed);
                            }
                        });
                    }
                }
            }
        }
    }

    tracing::info!("UDP forwarder on {} stopped", listen);
    Ok(())
}

/// Handle a single UDP session (one source address).
async fn udp_session(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    target: String,
    tunnel_client: Arc<Mutex<TunnelClient>>,
    sessions: Arc<Mutex<HashMap<SocketAddr, tokio::sync::mpsc::Sender<Bytes>>>>,
    mut data_rx: tokio::sync::mpsc::Receiver<Bytes>,
    udp_idle: Duration,
    cancel: CancellationToken,
    metrics: Option<Arc<ForwarderMetrics>>,
) -> Result<()> {
    // Get tunnel
    let tunnel = {
        let mut tc = tunnel_client.lock().await;
        match tc.get_tunnel().await {
            Some(t) => t,
            None => {
                // No tunnel, cleanup and exit
                sessions.lock().await.remove(&src);
                return Ok(());
            }
        }
    };

    // Open stream
    let handle = tunnel
        .open_stream(proto_to_byte(crate::config::Protocol::Udp), &target)
        .await?;
    let stream_id = handle.id;
    let tx = handle.tx.clone();
    let mut rx = handle.rx;

    // Wait for OPEN_ACK
    match rx.recv().await {
        Some(StreamIn::OpenAck(true)) => {}
        _ => {
            tunnel.remove_stream(stream_id);
            sessions.lock().await.remove(&src);
            return Ok(());
        }
    }

    tracing::debug!(stream_id, "UDP stream opened for {} → {}", src, target);

    // Task: local datagrams → tunnel
    let to_tunnel = {
        let tx = tx.clone();
        let cancel = cancel.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    msg = data_rx.recv() => {
                        match msg {
                            Some(data) => {
                                if let Some(ref m) = metrics {
                                    m.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
                                }
                                let frame = OutboundFrame {
                                    stream_id,
                                    frame_type: FrameType::Data,
                                    payload: data,
                                };
                                if tx.send(frame).await.is_err() {
                                    break;
                                }
                            }
                            None => break, // channel closed (main loop dropped)
                        }
                    }
                    _ = tokio::time::sleep(udp_idle) => {
                        tracing::debug!(stream_id, "UDP stream idle, closing");
                        break;
                    }
                }
            }
            // Send CLOSE
            let _ = tx
                .send(OutboundFrame {
                    stream_id,
                    frame_type: FrameType::Close,
                    payload: Bytes::new(),
                })
                .await;
        })
    };

    // Task: tunnel → local datagrams
    let from_tunnel = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                StreamIn::Data(data) => {
                    if let Some(ref m) = metrics {
                        m.bytes_recv.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                    if socket.send_to(&data, src).await.is_err() {
                        break;
                    }
                }
                StreamIn::Close | StreamIn::OpenAck(_) => break,
            }
        }
    });

    let _ = to_tunnel.await;
    let _ = from_tunnel.await;

    tunnel.remove_stream(stream_id);
    sessions.lock().await.remove(&src);
    Ok(())
}
