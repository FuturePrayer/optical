//! KCP transport implementation.
//!
//! Wraps `tokio_kcp::KcpStream` / `KcpListener` behind the [`Connect`] and
//! [`Listen`] traits. KCP is a reliable, low-latency protocol layered over UDP
//! — it trades higher bandwidth (retransmissions) for lower latency than TCP,
//! suiting latency-sensitive forwarding.
//!
//! `KcpStream` already implements `AsyncRead + AsyncWrite + Unpin + Send`, so
//! it satisfies [`Duplex`] via the blanket impl with no adapter needed — this
//! module mirrors [`super::tcp::TcpTransport`] almost exactly.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio_kcp::{KcpConfig, KcpListener, KcpNoDelayConfig, KcpStream};

use crate::error::Result;

use super::{BoxDuplex, Connect, Listen, Listener};

/// Build a low-latency "fastest" KCP configuration.
///
/// - `nodelay = true` (immediate ACK, no delay)
/// - `interval = 10ms` (internal update tick)
/// - `resend = 2` (fast resend on 2 ACKs)
/// - `nc = true` (disable congestion control — trades bandwidth for latency)
/// - `flush_write = true` / `flush_acks_input = true` (flush on write/input
///   so frames aren't held for the next tick)
///
/// This is the configuration actually intended for latency-sensitive
/// forwarding; the crate's `KcpConfig::default()` uses `normal()` (nodelay
/// off, 40ms interval, congestion control on) which is NOT suitable here.
pub fn fastest_kcp_config() -> KcpConfig {
    KcpConfig {
        mtu: 1400,
        nodelay: KcpNoDelayConfig::fastest(),
        wnd_size: (256, 256),
        session_expire: std::time::Duration::from_secs(90),
        flush_write: true,
        flush_acks_input: true,
        stream: false,
        allow_recv_empty_packet: false,
    }
}

/// KCP transport — carries the encrypted tunnel over reliable UDP (KCP).
///
/// `KcpConfig` is `Copy`, so cloning is free.
#[derive(Clone, Copy)]
pub struct KcpTransport {
    config: KcpConfig,
}

impl Default for KcpTransport {
    fn default() -> Self {
        Self {
            config: fastest_kcp_config(),
        }
    }
}

impl KcpTransport {
    /// Create with a custom KCP configuration.
    pub fn new(config: KcpConfig) -> Self {
        Self { config }
    }
}

/// Map a KCP error onto `std::io::Error` so it flows through
/// `OpticalError::Io(#[from] std::io::Error)`. Generic so we don't depend on
/// the concrete (unstable) error type name exported by `tokio_kcp`.
fn kcp_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> std::io::Error {
    std::io::Error::other(e)
}

impl Connect for KcpTransport {
    fn connect(&self, addr: &str) -> impl Future<Output = Result<BoxDuplex>> + Send {
        // KcpConfig is Copy — capture by value.
        let config = self.config;
        async move {
            // KcpStream::connect takes a single SocketAddr (no DNS), so resolve
            // the `host:port` string first, mirroring TcpStream::connect.
            let sock_addr = tokio::net::lookup_host(addr)
                .await?
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        format!("no address resolved for '{addr}'"),
                    )
                })?;
            let stream = KcpStream::connect(&config, sock_addr)
                .await
                .map_err(kcp_err)?;
            Ok(Box::new(stream) as BoxDuplex)
        }
    }
}

impl Listen for KcpTransport {
    fn listen(&self, addr: SocketAddr) -> impl Future<Output = Result<Box<dyn Listener>>> + Send {
        let config = self.config;
        async move {
            let listener = KcpListener::bind(config, addr).await.map_err(kcp_err)?;
            Ok(Box::new(KcpTransportListener(listener)) as Box<dyn Listener>)
        }
    }
}

/// Listener backed by `tokio_kcp::KcpListener`.
pub struct KcpTransportListener(KcpListener);

impl Listener for KcpTransportListener {
    fn accept(&mut self) -> Pin<Box<dyn Future<Output = Result<(BoxDuplex, SocketAddr)>> + Send + '_>> {
        Box::pin(async move {
            let (stream, addr) = self.0.accept().await.map_err(kcp_err)?;
            Ok((Box::new(stream) as BoxDuplex, addr))
        })
    }
}
