//! UDP dialer: dials a UDP target on receiving an OPEN frame.

use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::proto::frame::FrameType;
use crate::proto::stream::{OutboundFrame, StreamIn};
use crate::tunnel::Tunnel;

/// Dial a UDP target and forward datagrams bidirectionally through the tunnel stream.
pub async fn dial_and_forward(
    target: &str,
    tunnel: &Tunnel,
    stream_id: u32,
    _cancel: CancellationToken,
) -> Result<()> {
    // Resolve target address
    let target_addr = tokio::net::lookup_host(target)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("failed to resolve UDP target: {}", target))?;

    // Bind a local UDP socket for communicating with the target
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    tracing::debug!(stream_id, "UDP dialed target: {} → {}", target_addr, socket.local_addr()?);

    // Accept stream on tunnel
    let handle = tunnel.accept_stream(stream_id);
    let tx = handle.tx.clone();
    let mut rx = handle.rx;

    // Send OPEN_ACK (success)
    tunnel.send_open_ack(stream_id, true).await?;

    // Task: tunnel → target (datagrams from tunnel sent to target)
    let socket_t = socket.clone();
    let to_target = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                StreamIn::Data(data) => {
                    if socket_t.send_to(&data, target_addr).await.is_err() {
                        break;
                    }
                }
                StreamIn::Close | StreamIn::OpenAck(_) => break,
            }
        }
    });

    // Task: target → tunnel (datagrams from target sent to tunnel)
    let from_target = tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, _)) => {
                    let frame = OutboundFrame {
                        stream_id,
                        frame_type: FrameType::Data,
                        payload: Bytes::copy_from_slice(&buf[..n]),
                    };
                    if tx.send(frame).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // Signal close
        let _ = tx
            .send(OutboundFrame {
                stream_id,
                frame_type: FrameType::Close,
                payload: Bytes::new(),
            })
            .await;
    });

    let _ = to_target.await;
    let _ = from_target.await;

    tunnel.remove_stream(stream_id);
    tracing::debug!(stream_id, "UDP dial stream closed");
    Ok(())
}
