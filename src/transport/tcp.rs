//! TCP transport implementation.
//!
//! Wraps `tokio::net::TcpStream` / `TcpListener` behind the [`Connect`] and
//! [`Listen`] traits. Sets `TCP_NODELAY` on every connection to minimise
//! latency for the encrypted frame protocol, and optionally tunes
//! `SO_RCVBUF`/`SO_SNDBUF`/`SO_KEEPALIVE` via the `socket_buffer_bytes`
//! field (the tunnel multiplexes all streams over a single TCP connection,
//! so the OS default buffer can bottleneck high-BDP links).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::net::{TcpListener, TcpStream};

use crate::error::Result;

use super::{BoxDuplex, Connect, Listen, Listener};

/// TCP transport. Carries the optional socket-buffer size so it can be
/// applied on every connect/accept. Zero-cost when `socket_buffer_bytes == 0`.
#[derive(Clone, Copy)]
pub struct TcpTransport {
    socket_buffer_bytes: u64,
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self {
            socket_buffer_bytes: 0,
        }
    }
}

impl TcpTransport {
    /// Create with a custom TCP socket buffer size (applied to both
    /// SO_RCVBUF and SO_SNDBUF on every connection). Pass 0 to keep OS defaults.
    pub fn with_socket_buffer(socket_buffer_bytes: u64) -> Self {
        Self { socket_buffer_bytes }
    }
}

/// Apply socket-level tuning to a connected `TcpStream`:
/// - `TCP_NODELAY` (always on — disables Nagle for small frames)
/// - `SO_RCVBUF` / `SO_SNDBUF` (when `buf_bytes > 0`)
/// - `SO_KEEPALIVE` (reclaim half-open connections faster; the app-level
///   heartbeat remains the primary liveness check)
pub(super) fn tune_socket(stream: &TcpStream, buf_bytes: u64) {
    stream.set_nodelay(true).ok();
    if buf_bytes == 0 {
        return;
    }
    // Borrow the underlying OS socket via socket2::SockRef (zero-copy, no
    // ownership transfer). Works on both Unix and Windows.
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(buf_bytes as usize);
    let _ = sock.set_send_buffer_size(buf_bytes as usize);
    // Keepalive: 30s idle, probe every 10s, 3 probes → ~60s to detect a
    // dead peer at the TCP level (faster than the OS default of ~2h).
    let _ = sock.set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(30)));
}

impl Connect for TcpTransport {
    fn connect(&self, addr: &str) -> impl Future<Output = Result<BoxDuplex>> + Send {
        let buf_bytes = self.socket_buffer_bytes;
        async move {
            let stream = TcpStream::connect(addr).await?;
            tune_socket(&stream, buf_bytes);
            Ok(Box::new(stream) as BoxDuplex)
        }
    }
}

impl Listen for TcpTransport {
    fn listen(&self, addr: SocketAddr) -> impl Future<Output = Result<Box<dyn Listener>>> + Send {
        let _ = self.socket_buffer_bytes; // listener socket itself uses OS defaults
        async move {
            let listener = TcpListener::bind(addr).await?;
            Ok(Box::new(TcpTransportListener(listener, self.socket_buffer_bytes)) as Box<dyn Listener>)
        }
    }
}

/// Listener backed by `tokio::net::TcpListener`.
pub struct TcpTransportListener(TcpListener, u64);

impl Listener for TcpTransportListener {
    fn accept(&mut self) -> Pin<Box<dyn Future<Output = Result<(BoxDuplex, SocketAddr)>> + Send + '_>> {
        let buf_bytes = self.1;
        Box::pin(async move {
            let (stream, addr) = self.0.accept().await?;
            tune_socket(&stream, buf_bytes);
            Ok((Box::new(stream) as BoxDuplex, addr))
        })
    }
}
