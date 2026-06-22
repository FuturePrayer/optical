//! Dial module (Node2 role): handles incoming OPEN requests by dialing targets.

pub mod tcp;
pub mod udp;

use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::proto::stream::IncomingOpen;
use crate::tunnel::Tunnel;

/// Process incoming OPEN requests from the tunnel.
///
/// For each OPEN, spawns a task that dials the target and forwards traffic.
/// `dial_timeout` bounds each dial attempt so an unreachable target cannot
/// hold the stream ID and task indefinitely.
pub async fn handle_incoming_opens(
    tunnel: Tunnel,
    mut open_rx: mpsc::Receiver<IncomingOpen>,
    cancel: CancellationToken,
    dial_timeout: Duration,
) {
    tracing::info!("processing incoming OPEN requests");

    while let Some(open) = open_rx.recv().await {
        if cancel.is_cancelled() || !tunnel.is_alive() {
            break;
        }

        let tunnel = tunnel.clone();
        let cancel = cancel.clone();
        let stream_id = open.stream_id;
        let proto_byte = open.proto_byte;
        let target = open.target;

        tokio::spawn(async move {
            let result = match proto_byte {
                0x01 => tcp::dial_and_forward(&target, &tunnel, stream_id, cancel, dial_timeout).await,
                0x02 => udp::dial_and_forward(&target, &tunnel, stream_id, cancel, dial_timeout).await,
                _ => {
                    tracing::warn!(stream_id, "unknown protocol byte: {proto_byte}");
                    let _ = tunnel.send_open_ack(stream_id, false).await;
                    return;
                }
            };

            if let Err(e) = result {
                tracing::warn!(stream_id, "dial to {} failed: {e}", target);
                let _ = tunnel.send_open_ack(stream_id, false).await;
            }
        });
    }

    tracing::info!("incoming OPEN handler stopped");
}
