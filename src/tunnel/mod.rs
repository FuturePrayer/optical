//! Tunnel connection: encrypted multiplexed transport tunnel.
//!
//! A `Tunnel` wraps a duplex stream (any type implementing `AsyncRead +
//! AsyncWrite + Unpin + Send`) that has completed the PQ handshake.
//! It runs background reader, writer, and heartbeat tasks. Multiple streams
//! are multiplexed over the single connection using stream IDs.

pub mod client;
pub mod server;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::config::TunnelConfig;
use crate::crypto::aead::AeadCipher;
use crate::crypto::handshake::{HandshakeResult, HandshakeRole};
use crate::error::Result;
use crate::metrics::{self, TunnelMetrics, STATE_CONNECTED, STATE_DISCONNECTED};
use crate::proto::frame::{
    self, decode_open_ack_payload, decode_open_payload, decode_register_reverse_ack_payload,
    decode_register_reverse_payload, build_header, parse_header, FrameType, ReverseAckStatus,
    HEADER_SIZE, MAX_PAYLOAD, TAG_SIZE,
};
use crate::proto::stream::{IncomingOpen, IncomingReverse, OutboundFrame, StreamHandle, StreamIn};

/// Per-stream context stored in the tunnel's stream map.
struct StreamCtx {
    send_counter: u64,
    recv_counter: u64,
    /// Channel to deliver inbound frames to the stream handler.
    tx: mpsc::Sender<StreamIn>,
}

struct TunnelInner {
    /// Channel to the writer task (shared by all streams).
    write_tx: mpsc::Sender<OutboundFrame>,
    /// Active streams keyed by stream_id.
    streams: Mutex<HashMap<u32, StreamCtx>>,
    /// Next stream ID (client allocates even IDs: 0, 2, 4, ...;
    /// server allocates odd IDs: 1, 3, 5, ...).
    next_id: AtomicU32,
    /// Role: Client (Node1) or Server (Node2).
    role: HandshakeRole,
    /// Cancellation token — cancelled when the tunnel dies.
    cancel: CancellationToken,
    /// Last PONG received time.
    last_pong: Mutex<Instant>,
    /// Whether the tunnel is still alive.
    alive: AtomicBool,
    /// Metrics for this tunnel (None if observability is disabled or
    /// the tunnel has no registered metrics entry).
    metrics: Option<Arc<TunnelMetrics>>,
    /// Time the last PING was sent (for RTT calculation).
    last_ping_sent: Mutex<Option<Instant>>,
    /// One-shot waiter for `ping_once()` — woken when a PONG arrives.
    ping_waiter: Mutex<Option<oneshot::Sender<Duration>>>,
    /// Channel to deliver EchoReply payloads to the bench client.
    echo_reply_tx: Mutex<Option<mpsc::Sender<Bytes>>>,
    /// One-shot waiter for `register_reverse()` — woken when a RegisterReverseAck arrives.
    register_ack_waiter: Mutex<Option<oneshot::Sender<(ReverseAckStatus, String)>>>,
}

/// An established encrypted tunnel connection.
///
/// Cloneable so it can be shared between the OPEN handler and forwarder tasks.
#[derive(Clone)]
pub struct Tunnel {
    inner: std::sync::Arc<TunnelInner>,
}

impl Tunnel {
    /// Create a new tunnel from an established, handshaked transport stream.
    ///
    /// The `stream` can be any type implementing `AsyncRead + AsyncWrite +
    /// Unpin + Send + 'static` — e.g. `TcpStream`, a KCP stream, or a
    /// `Box<dyn Duplex>` from the transport layer.
    ///
    /// Returns the tunnel handle, a receiver for incoming OPEN requests
    /// (both sides may receive OPENs in reverse-tunnel mode), and a receiver
    /// for incoming RegisterReverse requests (only the server side consumes
    /// these; the client side can drop the receiver).
    pub fn new<S>(
        stream: S,
        handshake: HandshakeResult,
        config: TunnelConfig,
        metrics_key: Option<&str>,
    ) -> (Self, mpsc::Receiver<IncomingOpen>, mpsc::Receiver<IncomingReverse>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (write_tx, write_rx) = mpsc::channel(512);
        let (open_tx, open_rx) = mpsc::channel(64);
        let (reverse_tx, reverse_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();

        // Look up metrics from the global registry (if initialized).
        let metrics = metrics_key.and_then(|key| {
            metrics::try_get().and_then(|reg| reg.get_tunnel(key))
        });

        // Mark tunnel as connected in metrics.
        if let Some(ref m) = metrics {
            m.state.store(STATE_CONNECTED, Ordering::Relaxed);
            *m.last_connected.lock().unwrap() = Some(Instant::now());
        }

        // Stream ID allocation by role: Client uses even IDs (0, 2, 4, ...),
        // Server uses odd IDs (1, 3, 5, ...). This prevents collisions when
        // both sides open streams (required for reverse-tunnel mode).
        let initial_id = match handshake.role {
            HandshakeRole::Client => 0,
            HandshakeRole::Server => 1,
        };

        let inner = Arc::new(TunnelInner {
            write_tx: write_tx.clone(),
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(initial_id),
            role: handshake.role,
            cancel: cancel.clone(),
            last_pong: Mutex::new(Instant::now()),
            alive: AtomicBool::new(true),
            metrics,
            last_ping_sent: Mutex::new(None),
            ping_waiter: Mutex::new(None),
            echo_reply_tx: Mutex::new(None),
            register_ack_waiter: Mutex::new(None),
        });

        let (read_half, write_half) = tokio::io::split(stream);

        // Spawn writer task
        tokio::spawn(writer_task(
            write_rx,
            write_half,
            handshake.send_cipher,
            inner.clone(),
        ));

        // Spawn reader task
        tokio::spawn(reader_task(
            read_half,
            handshake.recv_cipher,
            inner.clone(),
            open_tx,
            reverse_tx,
        ));

        // Spawn heartbeat task
        tokio::spawn(heartbeat_task(inner.clone(), config, cancel));

        (Tunnel { inner }, open_rx, reverse_rx)
    }

    /// Open a new stream to a target (send an OPEN frame to the peer).
    ///
    /// Both sides can open streams — the client allocates even stream IDs
    /// and the server allocates odd stream IDs, so there are no collisions.
    pub async fn open_stream(&self, proto_byte: u8, target: &str) -> Result<StreamHandle> {
        let id = self.inner.next_id.fetch_add(2, Ordering::SeqCst);
        let (in_tx, in_rx) = mpsc::channel(256);

        {
            let mut streams = self.inner.streams.lock().unwrap();
            streams.insert(
                id,
                StreamCtx {
                    send_counter: 0,
                    recv_counter: 0,
                    tx: in_tx,
                },
            );
        }

        // Send OPEN frame
        let payload = frame::encode_open_payload(proto_byte, target);
        self.inner
            .write_tx
            .send(OutboundFrame {
                stream_id: id,
                frame_type: FrameType::Open,
                payload: Bytes::from(payload),
            })
            .await
            .map_err(|_| crate::error::OpticalError::Tunnel("tunnel writer closed".into()))?;

        tracing::debug!(stream_id = id, "OPEN sent for target: {}", target);

        Ok(StreamHandle {
            id,
            tx: self.inner.write_tx.clone(),
            rx: in_rx,
        })
    }

    /// Server side: accept an incoming stream and create a handle.
    pub fn accept_stream(&self, stream_id: u32) -> StreamHandle {
        let (in_tx, in_rx) = mpsc::channel(256);
        {
            let mut streams = self.inner.streams.lock().unwrap();
            streams.insert(
                stream_id,
                StreamCtx {
                    send_counter: 0,
                    recv_counter: 0,
                    tx: in_tx,
                },
            );
        }
        StreamHandle {
            id: stream_id,
            tx: self.inner.write_tx.clone(),
            rx: in_rx,
        }
    }

    /// Send an OPEN_ACK for a stream.
    pub async fn send_open_ack(&self, stream_id: u32, success: bool) -> Result<()> {
        self.inner
            .write_tx
            .send(OutboundFrame {
                stream_id,
                frame_type: FrameType::OpenAck,
                payload: Bytes::from(frame::encode_open_ack_payload(success).to_vec()),
            })
            .await
            .map_err(|_| crate::error::OpticalError::Tunnel("tunnel writer closed".into()))
    }

    /// Send a RegisterReverseAck control frame (stream_id=0).
    pub async fn send_register_reverse_ack(
        &self,
        status: ReverseAckStatus,
        msg: &str,
    ) -> Result<()> {
        self.inner
            .write_tx
            .send(OutboundFrame {
                stream_id: 0,
                frame_type: FrameType::RegisterReverseAck,
                payload: Bytes::from(frame::encode_register_reverse_ack_payload(status, msg)),
            })
            .await
            .map_err(|_| crate::error::OpticalError::Tunnel("tunnel writer closed".into()))
    }

    /// Remove a stream from the tunnel (cleanup).
    pub fn remove_stream(&self, stream_id: u32) {
        let mut streams = self.inner.streams.lock().unwrap();
        streams.remove(&stream_id);
    }

    /// Whether the tunnel is still alive.
    pub fn is_alive(&self) -> bool {
        self.inner.alive.load(Ordering::SeqCst)
    }

    /// Cancel the tunnel (triggers shutdown of all tasks).
    #[allow(dead_code)]
    pub fn cancel(&self) {
        self.inner.alive.store(false, Ordering::SeqCst);
        self.inner.cancel.cancel();
    }

    /// Get a cancellation token that fires when the tunnel dies.
    pub fn cancel_token(&self) -> CancellationToken {
        self.inner.cancel.clone()
    }

    /// Get the tunnel role.
    #[allow(dead_code)]
    pub fn role(&self) -> HandshakeRole {
        self.inner.role
    }

    /// Send a single PING and wait for the PONG, returning the RTT.
    ///
    /// Reuses the existing heartbeat PING/PONG protocol (stream_id=0, empty
    /// payload). Times out after 10 seconds.
    pub async fn ping_once(&self) -> std::result::Result<Duration, &'static str> {
        if !self.is_alive() {
            return Err("tunnel not alive");
        }

        let (tx, rx) = oneshot::channel();
        {
            let mut waiter = self.inner.ping_waiter.lock().unwrap();
            // Clear any stale waiter.
            *waiter = Some(tx);
        }
        {
            let mut last_ping = self.inner.last_ping_sent.lock().unwrap();
            *last_ping = Some(Instant::now());
        }

        // Send PING
        let send_ok = self
            .inner
            .write_tx
            .send(OutboundFrame {
                stream_id: 0,
                frame_type: FrameType::Ping,
                payload: Bytes::new(),
            })
            .await
            .is_ok();

        if !send_ok {
            *self.inner.ping_waiter.lock().unwrap() = None;
            return Err("failed to send PING (tunnel writer closed)");
        }

        // Wait for PONG with timeout
        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(rtt)) => Ok(rtt),
            _ => {
                *self.inner.ping_waiter.lock().unwrap() = None;
                Err("ping timeout (no PONG within 10s)")
            }
        }
    }

    /// Run a throughput benchmark by sending ECHO frames and counting
    /// EchoReply bytes received within `duration`.
    ///
    /// Uses stream_id=0 (same channel as heartbeat). The peer's reader_task
    /// automatically echoes back any Echo frame.
    pub async fn bench(&self, duration: Duration, payload_size: usize) -> BenchResult {
        let (echo_tx, mut echo_rx) = mpsc::channel(256);
        {
            *self.inner.echo_reply_tx.lock().unwrap() = Some(echo_tx);
        }

        let actual_size = payload_size.clamp(1, MAX_PAYLOAD);
        let payload = Bytes::from(vec![0u8; actual_size]);

        let start = Instant::now();
        let deadline = start + duration;
        let mut bytes_sent: u64 = 0;
        let mut bytes_recv: u64 = 0;

        loop {
            if Instant::now() >= deadline {
                break;
            }

            // Fill the write channel with ECHO frames (non-blocking)
            loop {
                match self.inner.write_tx.try_send(OutboundFrame {
                    stream_id: 0,
                    frame_type: FrameType::Echo,
                    payload: payload.clone(),
                }) {
                    Ok(()) => bytes_sent += actual_size as u64,
                    Err(mpsc::error::TrySendError::Full(_)) => break,
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // Tunnel died
                        *self.inner.echo_reply_tx.lock().unwrap() = None;
                        let elapsed = start.elapsed().as_secs_f64();
                        return BenchResult {
                            throughput_mbps: 0.0,
                            bytes_sent,
                            bytes_recv,
                            elapsed_secs: elapsed,
                        };
                    }
                }
            }

            // Drain available replies
            while let Ok(data) = echo_rx.try_recv() {
                bytes_recv += data.len() as u64;
            }

            tokio::task::yield_now().await;
        }

        // Drain remaining replies (2s grace period)
        let drain_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < drain_deadline {
            tokio::select! {
                biased;
                data = echo_rx.recv() => {
                    match data {
                        Some(d) => bytes_recv += d.len() as u64,
                        None => break,
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => break,
            }
        }

        *self.inner.echo_reply_tx.lock().unwrap() = None;

        let elapsed = start.elapsed().as_secs_f64();
        let throughput_mbps = (bytes_recv as f64 * 8.0) / (elapsed * 1_000_000.0);

        BenchResult {
            throughput_mbps,
            bytes_sent,
            bytes_recv,
            elapsed_secs: elapsed,
        }
    }

    /// Send a RegisterReverse control frame and wait for the peer's ack.
    ///
    /// Used by Node1 (client) to ask Node2 (server) to listen on `listen`
    /// and forward incoming connections back through the tunnel to this
    /// node, which dials `target`. Times out after 10 seconds.
    pub async fn register_reverse(
        &self,
        proto_byte: u8,
        listen: &str,
        target: &str,
    ) -> std::result::Result<(ReverseAckStatus, String), &'static str> {
        if !self.is_alive() {
            return Err("tunnel not alive");
        }

        let (tx, rx) = oneshot::channel();
        {
            let mut waiter = self.inner.register_ack_waiter.lock().unwrap();
            *waiter = Some(tx);
        }

        // Send RegisterReverse frame (stream_id=0 control frame)
        let payload = frame::encode_register_reverse_payload(proto_byte, listen, target);
        let send_ok = self
            .inner
            .write_tx
            .send(OutboundFrame {
                stream_id: 0,
                frame_type: FrameType::RegisterReverse,
                payload: Bytes::from(payload),
            })
            .await
            .is_ok();

        if !send_ok {
            *self.inner.register_ack_waiter.lock().unwrap() = None;
            return Err("failed to send RegisterReverse (tunnel writer closed)");
        }

        tracing::debug!("RegisterReverse sent: listen={listen} target={target}");

        // Wait for ack with timeout
        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(result)) => Ok(result),
            _ => {
                *self.inner.register_ack_waiter.lock().unwrap() = None;
                Err("register reverse timeout (no ack within 10s)")
            }
        }
    }
}

/// Result of a throughput benchmark.
#[derive(Debug)]
pub struct BenchResult {
    pub throughput_mbps: f64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub elapsed_secs: f64,
}

/// Writer task: encrypts and writes outbound frames to the transport.
async fn writer_task<W>(
    mut write_rx: mpsc::Receiver<OutboundFrame>,
    mut writer: W,
    send_cipher: AeadCipher,
    inner: std::sync::Arc<TunnelInner>,
) where
    W: AsyncWrite + Unpin + Send,
{
    let cancel = inner.cancel.clone();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            frame = write_rx.recv() => {
                let frame = match frame {
                    Some(f) => f,
                    None => break,
                };

                // Get and increment send counter for this stream
                let counter = {
                    let mut streams = inner.streams.lock().unwrap();
                    match streams.get_mut(&frame.stream_id) {
                        Some(ctx) => {
                            let c = ctx.send_counter;
                            ctx.send_counter += 1;
                            c
                        }
                        None => continue, // stream closed, drop frame
                    }
                };

                // Encrypt
                let ct_len = (frame.payload.len() + TAG_SIZE) as u16;
                let header = build_header(frame.stream_id, counter, frame.frame_type, ct_len);
                let ciphertext = send_cipher.encrypt(frame.stream_id, counter, &header, &frame.payload);

                // Write header + ciphertext
                if writer.write_all(&header).await.is_err() {
                    break;
                }
                if writer.write_all(&ciphertext).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }

                // Record bytes sent for metrics
                if let Some(ref m) = inner.metrics {
                    m.bytes_sent
                        .fetch_add((HEADER_SIZE + ciphertext.len()) as u64, Ordering::Relaxed);
                }
            }
        }
    }
    inner.alive.store(false, Ordering::SeqCst);
    inner.cancel.cancel();
    mark_disconnected(&inner);
    tracing::info!("tunnel writer task exited");
}

/// Reader task: reads, decrypts, and routes inbound frames.
async fn reader_task<R>(
    mut reader: R,
    recv_cipher: AeadCipher,
    inner: std::sync::Arc<TunnelInner>,
    open_tx: mpsc::Sender<IncomingOpen>,
    reverse_tx: mpsc::Sender<IncomingReverse>,
) where
    R: AsyncRead + Unpin + Send,
{
    let cancel = inner.cancel.clone();
    loop {
        let mut header = [0u8; HEADER_SIZE];
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            result = reader.read_exact(&mut header) => {
                if result.is_err() {
                    break;
                }
            }
        }

        let (stream_id, counter, frame_type, payload_len) = parse_header(&header);

        let mut ciphertext = vec![0u8; payload_len];
        if reader.read_exact(&mut ciphertext).await.is_err() {
            break;
        }

        // Record bytes received for metrics (header + ciphertext)
        if let Some(ref m) = inner.metrics {
            m.bytes_recv
                .fetch_add((HEADER_SIZE + ciphertext.len()) as u64, Ordering::Relaxed);
        }

        // Decrypt
        let plaintext = match recv_cipher.decrypt(stream_id, counter, &header, &ciphertext) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(stream_id, "AEAD decrypt failed, dropping frame");
                continue;
            }
        };

        match frame_type {
            FrameType::Open => {
                // Both client and server sides handle OPEN: the receiver dials
                // the target. In normal mode only the server receives OPENs;
                // in reverse-tunnel mode the client also receives OPENs (sent
                // by the server which is listening on the reverse port).
                match decode_open_payload(&plaintext) {
                    Ok((proto_byte, target)) => {
                        let _ = open_tx
                            .send(IncomingOpen {
                                stream_id,
                                proto_byte,
                                target,
                            })
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!(stream_id, "invalid OPEN payload: {e}");
                    }
                }
            }
            FrameType::OpenAck => {
                let success = decode_open_ack_payload(&plaintext).unwrap_or(false);
                let tx = {
                    let streams = inner.streams.lock().unwrap();
                    streams.get(&stream_id).map(|ctx| ctx.tx.clone())
                };
                if let Some(tx) = tx {
                    let _ = tx.send(StreamIn::OpenAck(success)).await;
                }
            }
            FrameType::Data => {
                // Anti-replay: check counter is strictly greater than last seen
                let tx = {
                    let mut streams = inner.streams.lock().unwrap();
                    match streams.get_mut(&stream_id) {
                        Some(ctx) => {
                            if counter <= ctx.recv_counter {
                                tracing::warn!(stream_id, counter, "replay detected, dropping");
                                None
                            } else {
                                ctx.recv_counter = counter;
                                Some(ctx.tx.clone())
                            }
                        }
                        None => None,
                    }
                };
                if let Some(tx) = tx {
                    if tx.send(StreamIn::Data(Bytes::from(plaintext))).await.is_err() {
                        // Stream handler closed; remove stream
                        inner.streams.lock().unwrap().remove(&stream_id);
                    }
                }
            }
            FrameType::Close => {
                let tx = {
                    let mut streams = inner.streams.lock().unwrap();
                    streams.remove(&stream_id).map(|ctx| ctx.tx)
                };
                if let Some(tx) = tx {
                    let _ = tx.send(StreamIn::Close).await;
                }
            }
            FrameType::Ping => {
                // Reply with PONG on stream_id 0
                let _ = inner
                    .write_tx
                    .send(OutboundFrame {
                        stream_id: 0,
                        frame_type: FrameType::Pong,
                        payload: Bytes::new(),
                    })
                    .await;
            }
            FrameType::Pong => {
                let now = Instant::now();
                {
                    let mut last = inner.last_pong.lock().unwrap();
                    *last = now;
                }
                // Compute RTT from last PING send time
                let rtt = {
                    let mut last_ping = inner.last_ping_sent.lock().unwrap();
                    if let Some(t) = *last_ping {
                        *last_ping = None;
                        Some(now.duration_since(t))
                    } else {
                        None
                    }
                };
                if let Some(rtt) = rtt {
                    // Update metrics
                    if let Some(ref m) = inner.metrics {
                        m.rtt_us.store(rtt.as_micros() as u64, Ordering::Relaxed);
                    }
                    // Wake ping waiter
                    let waiter = {
                        let mut w = inner.ping_waiter.lock().unwrap();
                        w.take()
                    };
                    if let Some(tx) = waiter {
                        let _ = tx.send(rtt);
                    }
                }
            }
            FrameType::Echo => {
                // Echo back the payload verbatim as EchoReply
                let _ = inner
                    .write_tx
                    .send(OutboundFrame {
                        stream_id: 0,
                        frame_type: FrameType::EchoReply,
                        payload: Bytes::from(plaintext),
                    })
                    .await;
            }
            FrameType::EchoReply => {
                // Deliver to bench client (if listening)
                let tx = {
                    let guard = inner.echo_reply_tx.lock().unwrap();
                    guard.as_ref().cloned()
                };
                if let Some(tx) = tx {
                    let _ = tx.send(Bytes::from(plaintext)).await;
                }
            }
            FrameType::RegisterReverse => {
                // Only the server side (Node2) is expected to receive these.
                // The server's reverse handler consumes the channel; on the
                // client side the channel is dropped so the send fails silently.
                match decode_register_reverse_payload(&plaintext) {
                    Ok((proto_byte, listen, target)) => {
                        tracing::info!(
                            "received RegisterReverse: proto={proto_byte} listen={listen} target={target}"
                        );
                        let _ = reverse_tx
                            .send(IncomingReverse {
                                proto_byte,
                                listen,
                                target,
                            })
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!("invalid RegisterReverse payload: {e}");
                    }
                }
            }
            FrameType::RegisterReverseAck => {
                // Wake the register_reverse() waiter (client side).
                let (status, msg) = decode_register_reverse_ack_payload(&plaintext)
                    .unwrap_or((ReverseAckStatus::Conflict, "decode error".into()));
                let waiter = {
                    let mut w = inner.register_ack_waiter.lock().unwrap();
                    w.take()
                };
                if let Some(tx) = waiter {
                    let _ = tx.send((status, msg));
                }
            }
        }
    }
    inner.alive.store(false, Ordering::SeqCst);
    inner.cancel.cancel();
    mark_disconnected(&inner);
    tracing::info!("tunnel reader task exited");
}

/// Heartbeat task: sends PING periodically and checks for PONG timeout.
async fn heartbeat_task(
    inner: std::sync::Arc<TunnelInner>,
    config: TunnelConfig,
    cancel: CancellationToken,
) {
    let interval = Duration::from_secs(config.heartbeat_interval_secs);
    let timeout = Duration::from_secs(config.heartbeat_timeout_secs);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(interval) => {
                if !inner.alive.load(Ordering::SeqCst) {
                    break;
                }
                // Send PING
                {
                    let mut last_ping = inner.last_ping_sent.lock().unwrap();
                    *last_ping = Some(Instant::now());
                }
                let _ = inner.write_tx.send(OutboundFrame {
                    stream_id: 0,
                    frame_type: FrameType::Ping,
                    payload: Bytes::new(),
                }).await;

                // Check PONG timeout
                let last_pong = *inner.last_pong.lock().unwrap();
                if last_pong.elapsed() > timeout {
                    tracing::warn!("heartbeat timeout (last pong {:?} ago), closing tunnel", last_pong.elapsed());
                    inner.alive.store(false, Ordering::SeqCst);
                    inner.cancel.cancel();
                    break;
                }
            }
        }
    }
    tracing::info!("tunnel heartbeat task exited");
}

/// Mark the tunnel as disconnected in metrics and increment reconnect count.
/// Called when any tunnel task exits (reader, writer, or heartbeat timeout).
fn mark_disconnected(inner: &TunnelInner) {
    if let Some(ref m) = inner.metrics {
        // Only transition if currently connected (avoid double-counting when
        // both reader and writer exit).
        let prev = m.state.swap(STATE_DISCONNECTED, Ordering::Relaxed);
        if prev == STATE_CONNECTED {
            *m.last_disconnected.lock().unwrap() = Some(Instant::now());
            m.reconnect_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}
