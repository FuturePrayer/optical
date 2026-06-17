//! Tunnel server: accepts tunnel connections, handshakes, and processes
//! incoming OPEN requests by dialing targets.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use crate::config::TunnelConfig;
use crate::crypto::handshake::{
    ClientHello, Finished, HandshakeResult, HandshakeRole, HandshakeState, MSG_SERVER_FINISHED,
};
use crate::crypto::pqdsa::DsaKeyPair;
use crate::error::Result;
use crate::transport::Listen;
use crate::tunnel::client::{read_msg, write_msg};
use crate::tunnel::Tunnel;

/// Perform the server-side handshake over a duplex stream.
///
/// Works with any type implementing `AsyncRead + AsyncWrite + Unpin`,
/// e.g. `&mut TcpStream`, `&mut Box<dyn Duplex>`, or a KCP stream.
pub async fn server_handshake<S>(
    stream: &mut S,
    psk: [u8; 32],
    dsa_keypair: DsaKeyPair,
) -> Result<HandshakeResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut state = HandshakeState::new(HandshakeRole::Server, psk, dsa_keypair);

    // Step 1: receive ClientHello
    let msg = read_msg(stream).await?;
    let client_hello = ClientHello::decode(&msg)?;
    state.server_process_client_hello(&client_hello)?;
    tracing::debug!("received ClientHello, encapsulated KEM");

    // Step 2: send ServerHello
    let hello = state.server_create_hello()?;
    write_msg(stream, &hello.encode()).await?;
    tracing::debug!("sent ServerHello, keys derived");

    // Step 3: receive ClientFinished
    let msg = read_msg(stream).await?;
    let client_finished = Finished::decode(&msg)?;
    state.server_verify_client_finished(&client_finished)?;
    tracing::debug!("verified ClientFinished");

    // Step 4: send ServerFinished
    let (finished, result) = state.server_create_finished()?;
    write_msg(stream, &finished.encode(MSG_SERVER_FINISHED)).await?;
    tracing::info!("handshake completed (server)");

    Ok(result)
}

/// Run the tunnel server: accept connections, handshake, and handle OPEN requests.
///
/// The `transport` parameter controls the underlying network protocol
/// (TCP, KCP, ...). It must implement [`Listen`].
pub async fn run<L: Listen>(
    transport: L,
    listen_addr: SocketAddr,
    psk: [u8; 32],
    dsa_keypair: DsaKeyPair,
    config: TunnelConfig,
    cancel: CancellationToken,
) -> Result<()> {
    let mut listener = transport.listen(listen_addr).await?;
    tracing::info!("tunnel server listening on {}", listen_addr);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            accept = listener.accept() => {
                let (mut stream, peer_addr) = match accept {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("accept error: {e}");
                        continue;
                    }
                };
                tracing::info!("tunnel connection from {}", peer_addr);

                let psk = psk;
                let dsa_keypair = dsa_keypair.clone();
                let config = config.clone();
                let cancel = cancel.clone();

                tokio::spawn(async move {
                    match server_handshake(&mut stream, psk, dsa_keypair).await {
                        Ok(handshake) => {
                            let (tunnel, open_rx) = Tunnel::new(stream, handshake, config, None);
                            tracing::info!("tunnel established with {}", peer_addr);

                            // Process incoming OPEN requests
                            crate::dial::handle_incoming_opens(tunnel, open_rx, cancel).await;
                        }
                        Err(e) => {
                            tracing::warn!("handshake failed from {}: {e}", peer_addr);
                        }
                    }
                });
            }
        }
    }

    tracing::info!("tunnel server stopped");
    Ok(())
}
