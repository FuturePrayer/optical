//! WebSocket transport implementation.
//!
//! Wraps `tokio_tungstenite::WebSocketStream` behind the [`Connect`] and
//! [`Listen`] traits. WebSocket traverses HTTP proxies/firewalls and can sit
//! behind a CDN using "Flexible SSL" (the CDN terminates TLS, plain `ws://`
//! backhauls to this origin). The tunnel's own ChaCha20-Poly1305 AEAD keeps
//! data confidential even when the transport is plaintext.
//!
//! `WebSocketStream<S>` is a `Stream<Item = Message> + Sink<Message>`, **not**
//! `AsyncRead`/`AsyncWrite`, so [`WsDuplex`] adapts the binary-message stream
//! into the byte stream the tunnel multiplexer expects.
//!
//! ## Server-side camouflage
//!
//! Non-WebSocket HTTP requests (e.g. a browser or a CDN HTTP health probe
//! visiting the port) receive a `200 OK` page so the port looks like an
//! ordinary website and passes 200-expecting health checks. Only requests
//! carrying `Upgrade: websocket` are handed to `accept_async`.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_async, client_async, tungstenite::Message, WebSocketStream,
};

use crate::error::Result;

use super::{BoxDuplex, Connect, Listen, Listener};

/// WebSocket transport — carries the optional socket-buffer size for the
/// underlying TCP connection. Connection parameters come from the `ws://`
/// URL (client) or the bound `SocketAddr` (server).
#[derive(Clone, Copy)]
pub struct WsTransport {
    socket_buffer_bytes: u64,
}

impl Default for WsTransport {
    fn default() -> Self {
        Self { socket_buffer_bytes: 0 }
    }
}

impl WsTransport {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a custom TCP socket buffer size applied to the underlying
    /// TCP connection (before the WS upgrade). Pass 0 to keep OS defaults.
    pub fn with_socket_buffer(socket_buffer_bytes: u64) -> Self {
        Self { socket_buffer_bytes }
    }
}

/// Map a `tungstenite::Error` onto `std::io::Error` so it flows through
/// `OpticalError::Io(#[from] std::io::Error)`.
fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::other(e)
}

/// Extract the `host:port` authority from a `ws://host:port[/path]` URL.
fn parse_ws_authority(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("ws://")?;
    match rest.find('/') {
        Some(i) => Some(&rest[..i]),
        None => Some(rest),
    }
}

impl Connect for WsTransport {
    fn connect(&self, addr: &str) -> impl Future<Output = Result<BoxDuplex>> + Send {
        let addr = addr.to_owned();
        let buf_bytes = self.socket_buffer_bytes;
        async move {
            let host_port = parse_ws_authority(&addr).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("expected ws:// URL, got: {addr}"),
                )
            })?;
            // Connect the raw TCP stream first so we can force TCP_NODELAY —
            // Nagle would add up to 40ms to small frames (PING/handshake),
            // which is fatal for the tunnel heartbeat detector. Also apply
            // socket-buffer tuning for high-BDP links.
            let tcp = TcpStream::connect(host_port).await?;
            super::tcp::tune_socket(&tcp, buf_bytes);
            // client_async performs the WS handshake over the already-connected
            // (and nodelay-configured) TCP stream, returning a
            // WebSocketStream<TcpStream> (no TLS wrapper).
            let (ws, _resp) = client_async(addr.as_str(), tcp)
                .await
                .map_err(ws_err)?;
            Ok(Box::new(WsDuplex::new(ws)) as BoxDuplex)
        }
    }
}

impl Listen for WsTransport {
    fn listen(&self, addr: SocketAddr) -> impl Future<Output = Result<Box<dyn Listener>>> + Send {
        let buf_bytes = self.socket_buffer_bytes;
        async move {
            let listener = TcpListener::bind(addr).await?;
            Ok(Box::new(WsTransportListener(listener, buf_bytes)) as Box<dyn Listener>)
        }
    }
}

/// Listener backed by a `TcpListener` that upgrades qualifying connections to
/// WebSocket and serves a camouflage page to plain HTTP clients.
pub struct WsTransportListener(TcpListener, u64);

impl Listener for WsTransportListener {
    fn accept(&mut self) -> Pin<Box<dyn Future<Output = Result<(BoxDuplex, SocketAddr)>> + Send + '_>> {
        let buf_bytes = self.1;
        Box::pin(async move {
            loop {
                let (mut stream, addr) = self.0.accept().await?;
                // Tune the inbound TCP connection (NODELAY + buffer sizes +
                // keepalive) for the same reasons as the client side.
                super::tcp::tune_socket(&stream, buf_bytes);

                // Peek (without consuming) to classify the request. accept_async
                // must re-read the full request line + headers, so we cannot
                // `read` here without replaying the bytes — `peek` leaves the
                // socket buffer intact for tungstenite.
                let mut buf = [0u8; 1024];
                let n = stream.peek(&mut buf).await.unwrap_or(0);
                let head = std::str::from_utf8(&buf[..n]).unwrap_or("");
                let is_ws_upgrade = head.to_ascii_lowercase().contains("upgrade: websocket");
                let headers_complete = head.contains("\r\n\r\n");

                if is_ws_upgrade || !headers_complete {
                    // WebSocket upgrade, or headers not fully received yet
                    // (peek may return a partial fragment) — let tungstenite
                    // complete (or reject) the handshake.
                    match accept_async(stream).await {
                        Ok(ws) => return Ok((Box::new(WsDuplex::new(ws)) as BoxDuplex, addr)),
                        Err(e) => {
                            tracing::warn!("ws handshake failed from {}: {e}", addr);
                            continue; // drop and accept the next connection
                        }
                    }
                } else {
                    // Plain HTTP request (no WS upgrade) — serve the camouflage
                    // page so the port looks like an ordinary website and CDN
                    // HTTP health checks expecting 200 succeed.
                    let resp = camouflage_response();
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.flush().await;
                    // stream dropped here; loop to accept the next connection
                }
            }
        })
    }
}

/// Build the `200 OK` camouflage HTTP response. Content-Length is computed at
/// runtime to stay in sync with the body constant.
fn camouflage_response() -> String {
    const BODY: &str = "<!DOCTYPE html><html><head><title>It works!</title></head>\
<body><h1>It works!</h1><p>The server is running.</p></body></html>";
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Connection: close\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        BODY.len(),
        BODY
    )
}

/// Adapter that presents a `WebSocketStream<S>` as an `AsyncRead + AsyncWrite`
/// byte stream.
///
/// - **Read**: drains an internal `VecDeque<Bytes>` buffer first; when empty,
///   pulls the next `Message`. `Binary` data fills the caller's `ReadBuf` and
///   any remainder is pushed back as a `Bytes` slice (cheap, refcount-only —
///   no copy). `Close`/stream-end signal EOF. `Ping`/`Pong`/`Text` are skipped
///   (tungstenite auto-replies to Pings; the tunnel only ever sends Binary).
/// - **Write**: each `poll_write` sends one `Message::Binary` (one tunnel
///   frame ≈ one WS message).
///
/// `poll_flush` forwards to `Sink::poll_flush` so tunnel PING frames reach the
/// underlying TCP promptly — critical for CDN idle keepalive (a CDN drops a
/// connection after 60-100s with no TCP traffic).
pub struct WsDuplex<S: AsyncRead + AsyncWrite + Unpin + Send> {
    ws: WebSocketStream<S>,
    read_buf: VecDeque<Bytes>,
    closed: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> WsDuplex<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            read_buf: VecDeque::new(),
            closed: false,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for WsDuplex<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 1. Drain the internal buffer first (leftover from a larger message).
        if let Some(front) = self.read_buf.front() {
            let n = std::cmp::min(front.len(), buf.remaining());
            buf.put_slice(&front[..n]);
            if n < front.len() {
                // Keep the rest as a cheap Bytes slice (refcount, no copy).
                *self.read_buf.front_mut().unwrap() = front.slice(n..);
            } else {
                self.read_buf.pop_front();
            }
            return Poll::Ready(Ok(()));
        }
        if self.closed {
            // EOF: return Ok with zero bytes filled.
            return Poll::Ready(Ok(()));
        }
        // 2. Pull the next WebSocket message.
        loop {
            match self.ws.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        let n = std::cmp::min(data.len(), buf.remaining());
                        buf.put_slice(&data[..n]);
                        if n < data.len() {
                            self.read_buf.push_back(data.slice(n..));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Message::Close(_) => {
                        self.closed = true;
                        return Poll::Ready(Ok(())); // EOF
                    }
                    Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Frame(_) => {
                        // tungstenite auto-replies to Ping; the tunnel is
                        // binary-only so Text/Frame should not appear — skip.
                        continue;
                    }
                },
                Poll::Ready(Some(Err(_))) => {
                    // Treat any WS error as EOF; the tunnel will detect the
                    // broken connection via the writer/heartbeat path.
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => {
                    self.closed = true;
                    return Poll::Ready(Ok(())); // stream ended = EOF
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for WsDuplex<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.ws.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(ws_err(e))),
            Poll::Pending => return Poll::Pending,
        }
        let msg = Message::Binary(Bytes::copy_from_slice(buf));
        match self.ws.start_send_unpin(msg) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(ws_err(e))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // MUST forward to Sink::poll_flush so tunnel PING frames reach the
        // underlying TCP promptly (CDN idle keepalive depends on this).
        self.ws.poll_flush_unpin(cx).map_err(ws_err)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // tokio's AsyncWrite uses poll_shutdown (not poll_close). Forward to
        // the WebSocket sink's poll_close, which sends a WS Close frame.
        self.ws.poll_close_unpin(cx).map_err(ws_err)
    }
}
