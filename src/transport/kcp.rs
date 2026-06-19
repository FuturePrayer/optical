//! KCP transport implementation.
//!
//! Wraps `tokio_kcp::KcpStream` / `KcpListener` behind the [`Connect`] and
//! [`Listen`] traits. KCP is a reliable, low-latency protocol layered over UDP
//! — it trades higher bandwidth (retransmissions) for ~30-40% lower latency
//! than TCP, suiting latency-sensitive forwarding.
//!
//! `KcpStream` already implements `AsyncRead + AsyncWrite + Unpin + Send`, so
//! it satisfies [`Duplex`] via the blanket impl with no adapter needed — this
//! module mirrors [`super::tcp::TcpTransport`] almost exactly.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio_kcp::{KcpConfig, KcpListener, KcpStream};

use crate::error::Result;

use super::{BoxDuplex, Connect, Listen, Listener};

/// KCP transport — carries the encrypted tunnel over reliable UDP (KCP).
///
/// `KcpConfig` is `Copy`, so cloning is free. Uses `KcpConfig::default()`
/// (low-latency nodelay preset suitable for real-time forwarding).
#[derive(Clone, Copy, Default)]
pub struct KcpTransport {
    config: KcpConfig,
}

impl KcpTransport {
    /// Create with a custom KCP configuration.
    #[allow(dead_code)]
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
