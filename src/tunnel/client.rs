//! Tunnel client: connects to a tunnel server, handshakes, and maintains
//! the connection with exponential backoff reconnection.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::config::TunnelConfig;
use crate::crypto::handshake::{
    Finished, HandshakeResult, HandshakeRole, HandshakeState, MSG_CLIENT_FINISHED,
    ServerHello,
};
use crate::crypto::pqdsa::DsaKeyPair;
use crate::dial;
use crate::error::{OpticalError, Result};
use crate::transport::Connect;
use crate::tunnel::Tunnel;

/// Write a length-prefixed message to the stream.
///
/// Generic over any `AsyncWrite` so it works with TCP, KCP, or any other
/// transport implementing the trait.
pub async fn write_msg<S: AsyncWrite + Unpin>(stream: &mut S, msg: &[u8]) -> Result<()> {
    let len = msg.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(msg).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a length-prefixed message from the stream.
///
/// Generic over any `AsyncRead` so it works with TCP, KCP, or any other
/// transport implementing the trait.
pub async fn read_msg<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 {
        return Err(OpticalError::Handshake(format!(
            "handshake message too large: {len} bytes"
        )));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Perform the client-side handshake over a duplex stream.
///
/// Works with any type implementing `AsyncRead + AsyncWrite + Unpin`,
/// e.g. `&mut TcpStream`, `&mut Box<dyn Duplex>`, or a KCP stream.
pub async fn client_handshake<S>(
    stream: &mut S,
    psk: [u8; 32],
    dsa_keypair: DsaKeyPair,
) -> Result<HandshakeResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut state = HandshakeState::new(HandshakeRole::Client, psk, dsa_keypair);

    // Step 1: send ClientHello
    let hello = state.client_create_hello()?;
    write_msg(stream, &hello.encode()).await?;
    tracing::debug!("sent ClientHello");

    // Step 2: receive ServerHello
    let msg = read_msg(stream).await?;
    let server_hello = ServerHello::decode(&msg)?;
    state.client_process_server_hello(&server_hello)?;
    tracing::debug!("received ServerHello, keys derived");

    // Step 3: send ClientFinished
    let finished = state.client_create_finished()?;
    write_msg(stream, &finished.encode(MSG_CLIENT_FINISHED)).await?;
    tracing::debug!("sent ClientFinished");

    // Step 4: receive ServerFinished
    let msg = read_msg(stream).await?;
    let server_finished = Finished::decode(&msg)?;
    let result = state.client_verify_server_finished(&server_finished)?;
    tracing::info!("handshake completed (client)");

    Ok(result)
}

/// A tunnel client that maintains a persistent connection to a tunnel server
/// with automatic reconnection.
///
/// Uses a `watch` channel to publish the current `Tunnel` (or `None` if
/// disconnected). Forwarders subscribe to get the current tunnel.
pub struct TunnelClient {
    /// Current tunnel, published via watch channel.
    tunnel_rx: watch::Receiver<Option<Tunnel>>,
    #[allow(dead_code)]
    cancel: CancellationToken,
}

impl TunnelClient {
    /// Start a tunnel client that connects to `addr` and maintains the connection.
    ///
    /// The `transport` parameter controls the underlying network protocol
    /// (TCP, KCP, ...). It must implement [`Connect`] and is cloned for
    /// the background reconnection task.
    pub fn start<C: Connect>(
        transport: C,
        addr: String,
        psk: [u8; 32],
        dsa_keypair: DsaKeyPair,
        config: TunnelConfig,
        parent_cancel: CancellationToken,
    ) -> Self {
        let (tunnel_tx, tunnel_rx) = watch::channel(None);
        let cancel = parent_cancel.child_token();

        let initial = config.reconnect_initial_secs;
        let max = config.reconnect_max_secs;

        tokio::spawn(maintain_connection(
            transport,
            addr,
            psk,
            dsa_keypair,
            config,
            tunnel_tx,
            cancel.clone(),
            initial,
            max,
        ));

        Self { tunnel_rx, cancel }
    }

    /// Wait until a tunnel is available and return a clone.
    pub async fn get_tunnel(&mut self) -> Option<Tunnel> {
        loop {
            if let Some(ref t) = *self.tunnel_rx.borrow() {
                return Some(t.clone());
            }
            // Wait for change
            if self.tunnel_rx.changed().await.is_err() {
                return None;
            }
        }
    }

    /// Get the current tunnel without waiting (may be None).
    pub fn try_get_tunnel(&self) -> Option<Tunnel> {
        self.tunnel_rx.borrow().clone()
    }
}

/// Background task: connect, handshake, create tunnel, reconnect on failure.
async fn maintain_connection<C: Connect>(
    transport: C,
    addr: String,
    psk: [u8; 32],
    dsa_keypair: DsaKeyPair,
    config: TunnelConfig,
    tunnel_tx: watch::Sender<Option<Tunnel>>,
    cancel: CancellationToken,
    initial_delay: u64,
    max_delay: u64,
) {
    let mut delay = initial_delay;
    let mut first_attempt = true;

    loop {
        if cancel.is_cancelled() {
            break;
        }

        // Attempt connection
        let attempt = async {
            tracing::info!("connecting to tunnel server at {}", addr);
            let mut stream = transport.connect(&addr).await?;
            let handshake = client_handshake(&mut stream, psk, dsa_keypair.clone()).await?;
            let (tunnel, open_rx, reverse_rx) =
                Tunnel::new(stream, handshake, config.clone(), Some(&addr));

            // Client side handles incoming OPENs (reverse-tunnel mode: the
            // server may send OPENs back for connections it accepted on a
            // reverse listener). Also drain the reverse_rx — the client
            // never receives RegisterReverse frames.
            let cancel = cancel.clone();
            tokio::spawn(dial::handle_incoming_opens(tunnel.clone(), open_rx, cancel));
            tokio::spawn(drain_reverse_rx(reverse_rx));

            Ok::<Tunnel, anyhow::Error>(tunnel)
        };

        match attempt.await {
            Ok(tunnel) => {
                tracing::info!("tunnel established to {}", addr);
                let _ = tunnel_tx.send(Some(tunnel.clone()));
                delay = initial_delay; // reset backoff
                first_attempt = false;

                // Wait for tunnel to die
                let tunnel_cancel = tunnel.cancel_token();
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    _ = tunnel_cancel.cancelled() => {
                        tracing::warn!("tunnel to {} disconnected, will reconnect", addr);
                        let _ = tunnel_tx.send(None);
                    }
                }
            }
            Err(e) => {
                if first_attempt {
                    tracing::warn!("failed to connect to {}: {e}", addr);
                    first_attempt = false;
                } else {
                    tracing::debug!("reconnect to {} failed: {e}", addr);
                }
                let _ = tunnel_tx.send(None);
            }
        }

        // Backoff before reconnect
        let sleep = Duration::from_secs(delay);
        tracing::debug!("waiting {:?} before reconnect", sleep);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(sleep) => {}
        }
        delay = (delay * 2).min(max_delay);
    }

    let _ = tunnel_tx.send(None);
    tracing::info!("tunnel client to {} stopped", addr);
}

/// Drain incoming RegisterReverse requests (client side never receives them).
async fn drain_reverse_rx(mut reverse_rx: mpsc::Receiver<crate::proto::stream::IncomingReverse>) {
    while reverse_rx.recv().await.is_some() {
        // Client side does not handle RegisterReverse
    }
}
