//! TCP transport implementation.
//!
//! Wraps `tokio::net::TcpStream` / `TcpListener` behind the [`Connect`] and
//! [`Listen`] traits. Sets `TCP_NODELAY` on every connection to minimise
//! latency for the encrypted frame protocol.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::net::{TcpListener, TcpStream};

use crate::error::Result;

use super::{BoxDuplex, Connect, Listen, Listener};

/// TCP transport — zero-sized, create with `TcpTransport::default()` or `TcpTransport`.
#[derive(Clone, Copy, Default)]
pub struct TcpTransport;

impl Connect for TcpTransport {
    fn connect(&self, addr: &str) -> impl Future<Output = Result<BoxDuplex>> + Send {
        async move {
            let stream = TcpStream::connect(addr).await?;
            stream.set_nodelay(true).ok();
            Ok(Box::new(stream) as BoxDuplex)
        }
    }
}

impl Listen for TcpTransport {
    fn listen(&self, addr: SocketAddr) -> impl Future<Output = Result<Box<dyn Listener>>> + Send {
        async move {
            let listener = TcpListener::bind(addr).await?;
            Ok(Box::new(TcpTransportListener(listener)) as Box<dyn Listener>)
        }
    }
}

/// Listener backed by `tokio::net::TcpListener`.
pub struct TcpTransportListener(TcpListener);

impl Listener for TcpTransportListener {
    fn accept(&mut self) -> Pin<Box<dyn Future<Output = Result<(BoxDuplex, SocketAddr)>> + Send + '_>> {
        Box::pin(async move {
            let (stream, addr) = self.0.accept().await?;
            stream.set_nodelay(true).ok();
            Ok((Box::new(stream) as BoxDuplex, addr))
        })
    }
}
