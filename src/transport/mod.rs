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

pub mod tcp;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::Result;

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
