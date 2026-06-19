//! TCP forwarder: accepts local TCP connections and forwards them through the tunnel.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::crypto::handshake::proto_to_byte;
use crate::metrics;
use crate::proto::stream::{copy_tcp_bidirectional, StreamIn};
use crate::tunnel::client::TunnelClient;
use crate::tunnel::Tunnel;

/// Run a TCP forwarder: listen on `listen`, forward to `target` via tunnel.
///
/// `open_ack_timeout` bounds the wait for the peer's OPEN_ACK after sending an
/// OPEN frame, so a stalled peer dial cannot hang the local connection.
pub async fn run(
    listen: SocketAddr,
    target: String,
    tunnel_client: Arc<Mutex<TunnelClient>>,
    cancel: CancellationToken,
    open_ack_timeout: Duration,
) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!("TCP forwarder: {} → via tunnel → {}", listen, target);

    // Look up forwarder metrics (if registered)
    let fwd_metrics = metrics::try_get().and_then(|reg| reg.get_forwarder(listen));

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            accept = listener.accept() => {
                let (local_stream, peer) = match accept {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("TCP accept error on {}: {e}", listen);
                        continue;
                    }
                };
                let target = target.clone();
                let tc = tunnel_client.clone();
                let cancel = cancel.clone();
                let metrics = fwd_metrics.clone();

                // Count new stream
                if let Some(ref m) = metrics {
                    m.total_streams.fetch_add(1, Ordering::Relaxed);
                    m.active_streams.fetch_add(1, Ordering::Relaxed);
                }

                tokio::spawn(async move {
                    tracing::debug!("TCP forward: new connection from {}", peer);
                    if let Err(e) = handle_connection(local_stream, target, tc, cancel, metrics.clone(), open_ack_timeout).await {
                        tracing::debug!("TCP forward from {} error: {e}", peer);
                    }
                    // Decrement active streams on exit
                    if let Some(ref m) = metrics {
                        m.active_streams.fetch_sub(1, Ordering::Relaxed);
                    }
                });
            }
        }
    }

    tracing::info!("TCP forwarder on {} stopped", listen);
    Ok(())
}

async fn handle_connection(
    local: tokio::net::TcpStream,
    target: String,
    tunnel_client: Arc<Mutex<TunnelClient>>,
    _cancel: CancellationToken,
    metrics: Option<Arc<metrics::ForwarderMetrics>>,
    open_ack_timeout: Duration,
) -> Result<()> {
    // Get tunnel (waits for connection if needed)
    let tunnel = {
        let mut tc = tunnel_client.lock().await;
        match tc.get_tunnel().await {
            Some(t) => t,
            None => {
                tracing::warn!("tunnel unavailable, dropping TCP connection");
                return Ok(());
            }
        }
    };

    forward_via_tunnel(local, target, tunnel, metrics, open_ack_timeout).await
}

/// Core TCP forwarding: open a stream to `target` via `tunnel`, wait for
/// OPEN_ACK, then copy bidirectionally.
///
/// Used by both the normal forwarder (via [`TunnelClient`]) and the reverse
/// listener (via [`Tunnel`] directly).
///
/// `open_ack_timeout` bounds the OPEN_ACK wait so a stalled peer dial cannot
/// hang the local connection indefinitely.
pub async fn forward_via_tunnel(
    local: tokio::net::TcpStream,
    target: String,
    tunnel: Tunnel,
    metrics: Option<Arc<metrics::ForwarderMetrics>>,
    open_ack_timeout: Duration,
) -> Result<()> {
    // Open stream
    let handle = tunnel
        .open_stream(proto_to_byte(crate::config::Protocol::Tcp), &target)
        .await?;

    let stream_id = handle.id;
    let tx = handle.tx.clone();
    let mut rx = handle.rx;

    // Wait for OPEN_ACK (bounded by open_ack_timeout)
    match tokio::time::timeout(open_ack_timeout, rx.recv()).await {
        Ok(Some(StreamIn::OpenAck(true))) => {
            tracing::debug!(stream_id, "stream opened to {}", target);
        }
        Ok(Some(StreamIn::OpenAck(false))) => {
            tracing::warn!(stream_id, "stream to {} refused by remote", target);
            tunnel.remove_stream(stream_id);
            return Ok(());
        }
        Ok(None) | Ok(Some(StreamIn::Data(_))) | Ok(Some(StreamIn::Close)) => {
            tracing::warn!(stream_id, "stream to {} closed before ack", target);
            tunnel.remove_stream(stream_id);
            return Ok(());
        }
        Err(_) => {
            tracing::warn!(
                stream_id,
                "stream to {} open_ack timeout after {:?}, closing",
                target,
                open_ack_timeout
            );
            tunnel.remove_stream(stream_id);
            return Ok(());
        }
    }

    // Split local TCP and do bidirectional copy
    let (read_half, write_half) = local.into_split();
    copy_tcp_bidirectional(read_half, write_half, stream_id, tx, rx, metrics).await;
    tunnel.remove_stream(stream_id);

    Ok(())
}
