//! Tunnel connection: encrypted multiplexed transport tunnel.
//!
//! A `Tunnel` wraps a duplex stream (any type implementing `AsyncRead +
//! AsyncWrite + Unpin + Send`) that has completed the PQ handshake.
//! It runs background reader, writer, and heartbeat tasks. Multiple streams
//! are multiplexed over the single connection using stream IDs.

pub mod client;
pub mod server;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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
    /// Next stream ID (client allocates even IDs: 2, 4, 6, ...;
    /// server allocates odd IDs: 1, 3, 5, ...).
    /// stream_id=0 is reserved for control frames (PING/PONG/Echo/etc.).
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
    /// Time the last heartbeat PING was sent (for RTT calculation).
    /// Used exclusively by the heartbeat task; `ping_once()` uses
    /// `ping_once_sent` to avoid races.
    last_ping_sent: Mutex<Option<Instant>>,
    /// Dedicated send counter for control frames (stream_id=0).
    /// Control frames (PING/PONG/Echo/RegisterReverse/etc.) are not tied
    /// to any data stream and must always be sendable, independent of
    /// the `streams` map (which only tracks data streams). Without this,
    /// closing the first data stream (which used to get stream_id=0)
    /// would remove `streams[0]`, causing all subsequent control frames
    /// to be silently dropped by `pack_frame`.
    control_send_counter: AtomicU64,
    /// One-shot waiter for `ping_once()` — woken when a PONG arrives.
    ping_waiter: Mutex<Option<oneshot::Sender<Duration>>>,
    /// Send time of the PING issued by `ping_once()`. Separate from
    /// `last_ping_sent` (heartbeat) so the two mechanisms don't
    /// overwrite each other's timestamp.
    ping_once_sent: Mutex<Option<Instant>>,
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

        // Stream ID allocation by role: Client uses even IDs (2, 4, 6, ...),
        // Server uses odd IDs (1, 3, 5, ...). stream_id=0 is reserved for
        // control frames (PING/PONG/Echo/RegisterReverse/etc.) so they are
        // never confused with data streams. This prevents a critical bug
        // where the first data stream (previously stream_id=0) would collide
        // with control frames: once that stream closed, `pack_frame` would
        // silently drop all PINGs/PONGs, causing heartbeat timeouts and
        // 100% ping loss.
        let initial_id = match handshake.role {
            HandshakeRole::Client => 2,
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
            control_send_counter: AtomicU64::new(0),
            ping_waiter: Mutex::new(None),
            ping_once_sent: Mutex::new(None),
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
    /// (2, 4, 6, ...) and the server allocates odd stream IDs (1, 3, 5, ...),
    /// so there are no collisions. stream_id=0 is reserved for control
    /// frames and never assigned to data streams.
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
    ///
    /// stream_id=0 is reserved for control frames and must never be removed
    /// (control frames don't live in the `streams` map, but this guard
    /// prevents a data stream that somehow got id=0 — e.g. from an old
    /// client — from corrupting control-frame send bookkeeping when closed).
    pub fn remove_stream(&self, stream_id: u32) {
        if stream_id == 0 {
            return;
        }
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
    ///
    /// Uses a dedicated `ping_once_sent` timestamp (separate from the
    /// heartbeat's `last_ping_sent`) so that concurrent heartbeat PINGs
    /// don't overwrite this method's send time and steal its PONG.
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
            let mut sent = self.inner.ping_once_sent.lock().unwrap();
            *sent = Some(Instant::now());
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
            *self.inner.ping_once_sent.lock().unwrap() = None;
            return Err("failed to send PING (tunnel writer closed)");
        }

        // Wait for PONG with timeout
        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(rtt)) => Ok(rtt),
            _ => {
                *self.inner.ping_waiter.lock().unwrap() = None;
                *self.inner.ping_once_sent.lock().unwrap() = None;
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
///
/// Uses micro-batching to amortize syscall and framing overhead:
/// 1. Each frame's header + ciphertext are packed into a single buffer and
///    written with one `write_all` (saves a syscall; on WebSocket this also
///    avoids sending the header and ciphertext as two separate WS Binary
///    messages, halving the WS frame overhead and copy count).
/// 2. After sending the first frame, any additional frames already queued in
///    the channel are drained via `try_recv` and appended to the same batch,
///    so a single `flush` pushes them all. This is especially beneficial for
///    small frames (PING, OPEN, OPEN_ACK) and bursty multi-stream traffic.
async fn writer_task<W>(
    mut write_rx: mpsc::Receiver<OutboundFrame>,
    mut writer: W,
    send_cipher: AeadCipher,
    inner: std::sync::Arc<TunnelInner>,
) where
    W: AsyncWrite + Unpin + Send,
{
    let cancel = inner.cancel.clone();
    // Upper bound on how many frames we coalesce into a single flush. Prevents
    // unbounded batching under extreme load (each frame still needs a
    // per-stream counter lock + an encrypt call).
    const MAX_BATCH_FRAMES: usize = 64;
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            frame = write_rx.recv() => {
                let frame = match frame {
                    Some(f) => f,
                    None => break,
                };

                // Pack the first frame into the batch buffer.
                let mut batch: Vec<u8> = match pack_frame(&frame, &send_cipher, &inner) {
                    PackResult::Packed(buf) => buf,
                    PackResult::Dropped => continue, // stream closed, skip this frame
                    PackResult::Fatal => break,      // encrypt failed, tear down
                };
                let mut frame_count = 1usize;

                // Drain any additional queued frames (non-blocking) into the
                // same batch, up to MAX_BATCH_FRAMES. A fatal encrypt error on
                // any frame tears down the tunnel immediately.
                let mut fatal = false;
                while frame_count < MAX_BATCH_FRAMES {
                    match write_rx.try_recv() {
                        Ok(f) => {
                            match pack_frame(&f, &send_cipher, &inner) {
                                PackResult::Packed(buf) => {
                                    batch.extend_from_slice(&buf);
                                    frame_count += 1;
                                }
                                PackResult::Dropped => continue, // stream closed, skip
                                PackResult::Fatal => {
                                    fatal = true;
                                    break;
                                }
                            }
                        }
                        Err(_) => break, // channel empty or closed
                    }
                }
                if fatal {
                    break;
                }

                // Single write + flush for the whole batch.
                if writer.write_all(&batch).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }

                // Bytes-sent metrics are accumulated per-frame inside
                // pack_frame so the count stays accurate even when a later
                // frame in the batch is dropped (stream closed).
            }
        }
    }
    inner.alive.store(false, Ordering::SeqCst);
    inner.cancel.cancel();
    mark_disconnected(&inner);
    tracing::info!("tunnel writer task exited");
}

/// Outcome of packing a single frame for the writer batch.
enum PackResult {
    /// Header + ciphertext packed into a contiguous buffer, ready to write.
    Packed(Vec<u8>),
    /// The frame was dropped (stream already closed). Safe to skip.
    Dropped,
    /// A fatal error occurred (encrypt failed). The tunnel must be torn down.
    Fatal,
}

/// Encrypt a single outbound frame and pack header + ciphertext into a
/// contiguous `Vec<u8>` (so the writer can issue a single `write_all`).
///
/// The returned buffer is `[header (15B)][ciphertext (payload_len + 16B tag)]`
/// ready to write. Bytes-sent metrics are accumulated here so the count stays
/// accurate even when multiple frames are batched.
fn pack_frame(
    frame: &OutboundFrame,
    send_cipher: &AeadCipher,
    inner: &TunnelInner,
) -> PackResult {
    // Control frames (stream_id=0) use a dedicated atomic counter. They are
    // not tied to any data stream and must always be sendable, regardless of
    // the `streams` map state. Data frames look up their per-stream counter
    // in the map; if the stream was closed, the frame is dropped.
    let counter = if frame.stream_id == 0 {
        inner.control_send_counter.fetch_add(1, Ordering::SeqCst)
    } else {
        let mut streams = inner.streams.lock().unwrap();
        match streams.get_mut(&frame.stream_id) {
            Some(ctx) => {
                let c = ctx.send_counter;
                ctx.send_counter += 1;
                c
            }
            None => return PackResult::Dropped, // stream closed, drop frame
        }
    };

    // Encrypt. Failure is fatal: we must NOT write the header (which
    // advertises `payload_len + TAG_SIZE` ciphertext bytes) with an
    // empty/short body, otherwise the peer's frame parser desyncs.
    let ct_len = (frame.payload.len() + TAG_SIZE) as u16;
    let header = build_header(frame.stream_id, counter, frame.frame_type, ct_len);
    let ciphertext = match send_cipher.encrypt(frame.stream_id, counter, &header, &frame.payload) {
        Ok(ct) => ct,
        Err(e) => {
            tracing::error!(stream_id = frame.stream_id, "AEAD encrypt failed: {e}, closing tunnel");
            return PackResult::Fatal;
        }
    };

    // Pack header + ciphertext into a single contiguous buffer.
    let mut buf = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    buf.extend_from_slice(&header);
    buf.extend_from_slice(&ciphertext);

    // Record bytes sent for metrics.
    if let Some(ref m) = inner.metrics {
        m.bytes_sent
            .fetch_add(buf.len() as u64, Ordering::Relaxed);
    }

    PackResult::Packed(buf)
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
    // Reusable ciphertext read buffer — grows to the largest frame seen and
    // is reused across iterations, avoiding a heap allocation per frame.
    let mut ct_buf: Vec<u8> = Vec::new();
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

        // Resize the reusable buffer (no allocation if it's already big
        // enough; Vec only grows, never shrinks, so the capacity sticks).
        ct_buf.resize(payload_len, 0);
        if reader.read_exact(&mut ct_buf[..payload_len]).await.is_err() {
            break;
        }

        // Record bytes received for metrics (header + ciphertext)
        if let Some(ref m) = inner.metrics {
            m.bytes_recv
                .fetch_add((HEADER_SIZE + payload_len) as u64, Ordering::Relaxed);
        }

        // Decrypt. On a reliable transport (TCP/KCP/WS-over-TCP), a decrypt
        // failure almost certainly indicates tampering or a bug. Following
        // the TLS principle ("AEAD-fail ⟹ disconnect"), we tear down the
        // tunnel rather than silently dropping the frame (which would allow
        // unbounded probing).
        let plaintext = match recv_cipher.decrypt(stream_id, counter, &header, &ct_buf[..payload_len]) {
            Ok(p) => p,
            Err(_) => {
                tracing::error!(stream_id, "AEAD decrypt failed, closing tunnel");
                break;
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
                    // Use try_send (non-blocking) so a slow consumer whose
                    // channel is full does not stall the reader and block all
                    // other streams (head-of-line blocking). A full channel
                    // drops the frame and increments the drop counter for
                    // observability; the stream's reliability is already
                    // best-effort (it carries application traffic that has its
                    // own flow control, e.g. TCP over the tunnel).
                    match tx.try_send(StreamIn::Data(Bytes::from(plaintext))) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                stream_id,
                                "stream channel full, dropping inbound Data frame (slow consumer)"
                            );
                            if let Some(ref m) = inner.metrics {
                                m.frames_dropped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            // Stream handler closed; remove stream
                            inner.streams.lock().unwrap().remove(&stream_id);
                        }
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
                // Always update last_pong (used by heartbeat timeout check).
                {
                    let mut last = inner.last_pong.lock().unwrap();
                    *last = now;
                }

                // Priority 1: ping_once() waiter. If an explicit ping is
                // waiting, compute RTT from its dedicated send timestamp
                // (`ping_once_sent`) and deliver the result. This takes
                // precedence over the heartbeat RTT so that a concurrent
                // heartbeat PING doesn't steal the PONG.
                let once_waiter = {
                    let mut w = inner.ping_waiter.lock().unwrap();
                    w.take()
                };
                if let Some(tx) = once_waiter {
                    let rtt = {
                        let mut sent = inner.ping_once_sent.lock().unwrap();
                        sent.take().map(|t| now.duration_since(t))
                    };
                    let rtt = rtt.unwrap_or(Duration::ZERO);
                    if let Some(ref m) = inner.metrics {
                        m.rtt_us.store(rtt.as_micros() as u64, Ordering::Relaxed);
                    }
                    let _ = tx.send(rtt);
                } else {
                    // Priority 2: heartbeat RTT (for metrics only, no waiter).
                    let rtt = {
                        let mut last_ping = inner.last_ping_sent.lock().unwrap();
                        last_ping.take().map(|t| now.duration_since(t))
                    };
                    if let Some(rtt) = rtt {
                        if let Some(ref m) = inner.metrics {
                            m.rtt_us.store(rtt.as_micros() as u64, Ordering::Relaxed);
                        }
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
