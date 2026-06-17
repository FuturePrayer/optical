//! TCP dialer: dials a TCP target on receiving an OPEN frame.

use anyhow::Result;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::proto::stream::copy_tcp_bidirectional;
use crate::tunnel::Tunnel;

/// Dial a TCP target and forward traffic bidirectionally through the tunnel stream.
pub async fn dial_and_forward(
    target: &str,
    tunnel: &Tunnel,
    stream_id: u32,
    _cancel: CancellationToken,
) -> Result<()> {
    // Dial target TCP
    let target_stream = TcpStream::connect(target).await?;
    target_stream.set_nodelay(true).ok();
    tracing::debug!(stream_id, "TCP dialed target: {}", target);

    // Accept stream on tunnel
    let handle = tunnel.accept_stream(stream_id);
    let tx = handle.tx.clone();
    let rx = handle.rx;

    // Send OPEN_ACK (success)
    tunnel.send_open_ack(stream_id, true).await?;

    // Bidirectional copy
    let (read_half, write_half) = target_stream.into_split();
    copy_tcp_bidirectional(read_half, write_half, stream_id, tx, rx, None).await;

    tunnel.remove_stream(stream_id);
    tracing::debug!(stream_id, "TCP dial stream closed");
    Ok(())
}
