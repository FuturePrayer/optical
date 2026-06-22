//! TCP dialer: dials a TCP target on receiving an OPEN frame.

use std::time::Duration;

use anyhow::Result;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::proto::stream::copy_tcp_bidirectional;
use crate::tunnel::Tunnel;

/// Dial a TCP target and forward traffic bidirectionally through the tunnel stream.
///
/// `dial_timeout` bounds the connect attempt so an unreachable target cannot
/// hold the stream ID and task indefinitely (OS default connect timeout can
/// reach ~75s–2min on Linux).
pub async fn dial_and_forward(
    target: &str,
    tunnel: &Tunnel,
    stream_id: u32,
    _cancel: CancellationToken,
    dial_timeout: Duration,
) -> Result<()> {
    // Dial target TCP with an explicit timeout
    let target_stream = match tokio::time::timeout(dial_timeout, TcpStream::connect(target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            anyhow::bail!("TCP dial to {} timed out after {:?}", target, dial_timeout);
        }
    };
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
