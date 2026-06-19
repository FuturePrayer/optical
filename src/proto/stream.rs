//! Stream handle types for multiplexed tunnel streams.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

use crate::metrics::ForwarderMetrics;
use crate::proto::frame::{FrameType, MAX_PAYLOAD};

/// A frame to be sent over the tunnel (plaintext, before encryption).
#[derive(Debug)]
pub struct OutboundFrame {
    pub stream_id: u32,
    pub frame_type: FrameType,
    pub payload: Bytes,
}

/// Messages a stream handler receives from the tunnel (inbound direction).
#[derive(Debug)]
pub enum StreamIn {
    /// Response to an OPEN request (true = success).
    OpenAck(bool),
    /// Inbound data on the stream.
    Data(Bytes),
    /// Stream was closed by the peer.
    Close,
}

/// Handle to a multiplexed stream.
pub struct StreamHandle {
    pub id: u32,
    /// Send frames to the tunnel writer (shared across all streams).
    pub tx: mpsc::Sender<OutboundFrame>,
    /// Receive data/ack/close from the tunnel reader.
    pub rx: mpsc::Receiver<StreamIn>,
}

impl StreamHandle {
    /// Send data over the stream.
    #[allow(dead_code)]
    pub async fn send_data(&self, data: Bytes) -> Result<(), mpsc::error::SendError<OutboundFrame>> {
        self.tx
            .send(OutboundFrame {
                stream_id: self.id,
                frame_type: FrameType::Data,
                payload: data,
            })
            .await
    }

    /// Close the stream.
    #[allow(dead_code)]
    pub async fn close(&self) -> Result<(), mpsc::error::SendError<OutboundFrame>> {
        self.tx
            .send(OutboundFrame {
                stream_id: self.id,
                frame_type: FrameType::Close,
                payload: Bytes::new(),
            })
            .await
    }
}

/// An incoming OPEN request.
///
/// Both client and server sides may receive OPEN frames in reverse-tunnel
/// mode, so this is delivered to whichever side needs to dial the target.
#[derive(Debug)]
pub struct IncomingOpen {
    pub stream_id: u32,
    pub proto_byte: u8,
    pub target: String,
}

/// An incoming RegisterReverse request (server side only).
///
/// The server is asked to listen on `listen` and, for each accepted
/// connection, open a stream back to the client with `target` as the
/// dial target.
#[derive(Debug)]
pub struct IncomingReverse {
    pub proto_byte: u8,
    pub listen: String,
    pub target: String,
}

/// Bidirectional copy between a TCP read/write half pair and a tunnel stream.
///
/// Used by both forward (Node1) and dial (Node2) for TCP streams.
/// Returns when either direction completes.
pub async fn copy_tcp_bidirectional(
    reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    stream_id: u32,
    tx: mpsc::Sender<OutboundFrame>,
    mut rx: mpsc::Receiver<StreamIn>,
    metrics: Option<Arc<ForwarderMetrics>>,
) {
    // local → tunnel
    let to_tunnel = {
        let tx = tx.clone();
        let metrics = metrics.clone();
        let mut reader = reader;
        tokio::spawn(async move {
            // Read buffer sized to ~MAX_PAYLOAD so a full-size read becomes a
            // single tunnel Data frame (no splitting into 16KB chunks). The
            // buffer is reused across reads; BytesMut::split().freeze() hands
            // off each chunk to the tunnel with a refcount-only slice (no copy).
            let mut buf = BytesMut::with_capacity(MAX_PAYLOAD);
            loop {
                // Ensure MAX_PAYLOAD writable bytes for the next read (split()
                // in the previous iteration left buf empty but with capacity).
                buf.clear();
                buf.resize(MAX_PAYLOAD, 0);
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Some(ref m) = metrics {
                            m.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        // Truncate to the bytes actually read and split off a
                        // cheap refcount Bytes (no copy).
                        buf.truncate(n);
                        let data = buf.split().freeze();
                        let frame = OutboundFrame {
                            stream_id,
                            frame_type: FrameType::Data,
                            payload: data,
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
        })
    };

    // tunnel → local
    let from_tunnel = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                StreamIn::Data(data) => {
                    if let Some(ref m) = metrics {
                        m.bytes_recv.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                    if writer.write_all(&data).await.is_err() {
                        break;
                    }
                }
                StreamIn::Close | StreamIn::OpenAck(_) => break,
            }
        }
    });

    let _ = to_tunnel.await;
    let _ = from_tunnel.await;
}
