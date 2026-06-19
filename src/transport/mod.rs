//! Transport layer abstraction: decouples tunnel I/O from the underlying
//! network protocol (TCP, KCP, UDP, ...).
//!
//! A [`Duplex`] is any type that supports [`AsyncRead`] + [`AsyncWrite`] +
//! `Unpin` + `Send` — i.e. a bidirectional byte stream. The [`Connect`] and
//! [`Listen`] traits abstract connection establishment so that the tunnel
//! module never references `TcpStream` directly.
//!
//! ## Adding a new transport
//!
//! 1. Implement [`Connect`] and/or [`Listen`] for a transport struct.
//! 2. Return [`BoxDuplex`] (a `Box<dyn Duplex>`) from `connect` / `accept`.
//! 3. The existing tunnel + handshake code works unchanged because it is
//!    generic over `impl AsyncRead + AsyncWrite + Unpin + Send`.

pub mod kcp;
pub mod tcp;
pub mod ws;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_kcp::KcpConfig;

use crate::config::TransportKind;
use crate::error::Result;

use kcp::KcpTransport;
use tcp::TcpTransport;
use ws::WsTransport;

/// A type-erased duplex stream (read + write).
///
/// `dyn AsyncRead + AsyncWrite` is not a valid trait object (multiple
/// non-auto principal traits), so we combine them into [`Duplex`].
/// Tokio provides blanket `AsyncRead`/`AsyncWrite` impls for `Box<T>`,
/// so `Box<dyn Duplex>` is itself `AsyncRead + AsyncWrite + Unpin + Send`.
pub type BoxDuplex = Box<dyn Duplex>;

/// Any type that is simultaneously `AsyncRead + AsyncWrite + Unpin + Send`.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> Duplex for T where T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized {}

/// Client-side transport: establishes outbound connections.
///
/// Implementors return a [`BoxDuplex`] which the tunnel layer splits into
/// read/write halves via `tokio::io::split` and feeds into the handshake +
/// multiplexer pipeline.
pub trait Connect: Send + Sync + Clone + 'static {
    /// Connect to `addr` and return a duplex stream.
    fn connect(&self, addr: &str) -> impl Future<Output = Result<BoxDuplex>> + Send;
}

/// Server-side transport: accepts inbound connections.
pub trait Listen: Send + Sync + 'static {
    /// Start listening on `addr` and return a [`Listener`].
    fn listen(&self, addr: SocketAddr) -> impl Future<Output = Result<Box<dyn Listener>>> + Send;
}

/// Accepts incoming transport connections.
///
/// Uses `Pin<Box<dyn Future>>` instead of `impl Future` so that the trait
/// is dyn-compatible (can be used as `Box<dyn Listener>`). The allocation
/// per `accept` call is negligible since connections are infrequent.
pub trait Listener: Send {
    /// Wait for the next incoming connection.
    ///
    /// Returns the duplex stream and the peer's remote address.
    fn accept(&mut self) -> Pin<Box<dyn Future<Output = Result<(BoxDuplex, SocketAddr)>> + Send + '_>>;
}

/// Unified transport dispatcher: implements [`Connect`] + [`Listen`] by
/// delegating to the concrete transport selected either by the `tunnel`
/// address URL scheme (client side) or by [`TransportKind`] (server side).
///
/// `Connect`/`Listen` use `impl Future` (not dyn-compatible), so we cannot
/// `Box<dyn Connect>`. Instead this concrete type branches at the call site,
/// allowing a single node to use different protocols for different peers.
///
/// Cloning is cheap: `KcpConfig` is `Copy` and the other transports are
/// zero-sized.
#[derive(Clone)]
pub struct AnyTransport {
    /// Transport used by the *server* listener (Node2). The client side
    /// ignores this and dispatches per-connection via the URL scheme.
    listen_kind: TransportKind,
    /// KCP configuration (shared by both sides; `Copy`).
    kcp_config: KcpConfig,
}

impl AnyTransport {
    /// Build a server-side transport that listens with `kind`.
    pub fn for_server(kind: TransportKind) -> Self {
        Self {
            listen_kind: kind,
            kcp_config: KcpConfig::default(),
        }
    }

    /// Build a client-side transport that dispatches per `tunnel` URL scheme.
    pub fn for_client() -> Self {
        // listen_kind is unused on the client; default to Tcp.
        Self {
            listen_kind: TransportKind::Tcp,
            kcp_config: KcpConfig::default(),
        }
    }
}

/// Classify a tunnel address by its URL scheme.
///
/// - `host:port` or `tcp://host:port` → TCP (bare form is the default for
///   backwards compatibility with existing configs)
/// - `kcp://host:port` → KCP
/// - `ws://host:port[/path]` → WebSocket (the full URL is preserved since the
///   WS client needs it to build the Host header and request target)
///
/// Returns `(kind, target)` where `target` is the `host:port` form for TCP/KCP
/// and the original URL for WS.
fn parse_transport_addr(addr: &str) -> (TransportKind, &str) {
    if let Some(rest) = addr.strip_prefix("kcp://") {
        (TransportKind::Kcp, rest)
    } else if addr.starts_with("ws://") {
        (TransportKind::Ws, addr)
    } else if let Some(rest) = addr.strip_prefix("tcp://") {
        (TransportKind::Tcp, rest)
    } else {
        (TransportKind::Tcp, addr)
    }
}

impl Connect for AnyTransport {
    fn connect(&self, addr: &str) -> impl Future<Output = Result<BoxDuplex>> + Send {
        let kcp_config = self.kcp_config;
        async move {
            let (kind, target) = parse_transport_addr(addr);
            match kind {
                TransportKind::Tcp => TcpTransport.connect(target).await,
                TransportKind::Kcp => KcpTransport::new(kcp_config).connect(target).await,
                TransportKind::Ws => WsTransport.connect(target).await,
            }
        }
    }
}

impl Listen for AnyTransport {
    fn listen(&self, addr: SocketAddr) -> impl Future<Output = Result<Box<dyn Listener>>> + Send {
        let kind = self.listen_kind;
        let kcp_config = self.kcp_config;
        async move {
            match kind {
                TransportKind::Tcp => TcpTransport.listen(addr).await,
                TransportKind::Kcp => KcpTransport::new(kcp_config).listen(addr).await,
                TransportKind::Ws => WsTransport.listen(addr).await,
            }
        }
    }
}
