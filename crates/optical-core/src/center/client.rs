//! Node-side config-center client.
//!
//! Connects to a center server, registers the node's identity, receives
//! `ConfigPush` updates (forwarders), applies them via a channel, and
//! periodically reports status. Reuses the tunnel transport layer + PQ
//! handshake for the connection, and the center session codec for frames.
//!
//! Connection maintenance mirrors [`crate::tunnel::client::maintain_connection`]
//! (exponential backoff), but adds **jitter** to avoid thundering-herd
//! reconnects when many nodes point at one center.

use std::time::Duration;

use rand::Rng;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::center::proto::{self, ConfigAckMsg, ConfigPushMsg, NodeRegisterMsg, StatusReportMsg};
use crate::config::{parse_psk, CenterClientConfig};
use crate::crypto::pqdsa::DsaKeyPair;
use crate::metrics;
use crate::proto::frame::FrameType;
use crate::transport::{AnyTransport, Connect};
use crate::tunnel::client::client_handshake;

/// Start the center client as a background task.
///
/// `config` selects the center address, PSK, and report interval. `transport`
/// is the same `AnyTransport` used for tunnels (so `tcp://`/`kcp://`/`ws://`
/// schemes work). `config_push_tx` delivers received `ConfigPushMsg`s to the
/// caller (typically a [`crate::config_manager::ConfigManager`]). `version` is
/// the node's version string, reported in `NodeRegister`.
///
/// The task runs until `cancel` is triggered. Reconnection uses exponential
/// backoff with jitter (initial 1s, max 30s).
pub fn start(
    config: CenterClientConfig,
    transport: AnyTransport,
    dsa_keypair: DsaKeyPair,
    version: &'static str,
    config_push_tx: mpsc::Sender<ConfigPushMsg>,
    cancel: CancellationToken,
) {
    tokio::spawn(run(
        config,
        transport,
        dsa_keypair,
        version,
        config_push_tx,
        cancel,
    ));
}

/// Main loop: connect → register → serve (push/ack/status) until the
/// connection dies, then back off and retry.
async fn run(
    config: CenterClientConfig,
    transport: AnyTransport,
    dsa_keypair: DsaKeyPair,
    version: &'static str,
    config_push_tx: mpsc::Sender<ConfigPushMsg>,
    cancel: CancellationToken,
) {
    let psk = match parse_psk(&config.psk) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("invalid center PSK: {e}");
            return;
        }
    };
    let node_id = dsa_keypair.node_id();

    let initial = Duration::from_secs(1);
    let max = Duration::from_secs(30);
    let mut delay = initial;
    let mut first_attempt = true;

    loop {
        if cancel.is_cancelled() {
            break;
        }

        let session_result = run_one_session(
            &config,
            &transport,
            psk,
            &dsa_keypair,
            node_id.as_str(),
            version,
            &config_push_tx,
            &cancel,
        )
        .await;

        match session_result {
            Ok(()) => {
                tracing::info!("config center session ended cleanly");
                delay = initial;
                first_attempt = false;
            }
            Err(e) => {
                if first_attempt {
                    tracing::warn!("failed to connect to config center: {e}");
                    first_attempt = false;
                } else {
                    tracing::debug!("config center reconnect failed: {e}");
                }
            }
        }

        // Backoff with jitter before reconnect.
        let jitter = rand::thread_rng().gen_range(0.5..1.5);
        let sleep = delay.mul_f64(jitter);
        tracing::debug!("waiting {sleep:?} before reconnecting to center");
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(sleep) => {}
        }
        delay = (delay * 2).min(max);
    }

    tracing::info!("config center client stopped");
}

/// Run one full session: connect, handshake, register, then loop reading
/// frames (ConfigPush / Ping) and periodically sending StatusReport, until the
/// connection breaks or `cancel` fires.
async fn run_one_session(
    config: &CenterClientConfig,
    transport: &AnyTransport,
    psk: [u8; 32],
    dsa_keypair: &DsaKeyPair,
    node_id: &str,
    version: &str,
    config_push_tx: &mpsc::Sender<ConfigPushMsg>,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    tracing::info!("connecting to config center at {}", config.address);
    let mut stream = transport.connect(&config.address).await?;
    let handshake = client_handshake(&mut stream, psk, dsa_keypair.clone()).await?;
    tracing::info!("config center handshake completed (client), node_id={node_id}");

    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let send_cipher = handshake.send_cipher;
    let recv_cipher = handshake.recv_cipher;
    let mut send_counter: u64 = 0;

    // Send NodeRegister.
    let register = NodeRegisterMsg {
        node_id: node_id.to_string(),
        version: version.to_string(),
        capabilities: vec!["tcp".into(), "kcp".into(), "ws".into(), "reverse".into()],
    };
    proto::write_frame(
        &mut write_half,
        &send_cipher,
        send_counter,
        FrameType::NodeRegister,
        &register,
    )
    .await?;
    send_counter += 1;
    tracing::debug!("sent NodeRegister to center");

    let report_interval = Duration::from_secs(config.status_report_interval_secs);
    let mut last_status = tokio::time::Instant::now();

    loop {
        let next_status = tokio::time::sleep_until(last_status + report_interval);
        tokio::pin!(next_status);

        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            res = proto::read_frame(&mut read_half, &recv_cipher) => {
                match res {
                    Ok(Some((ft, plaintext))) => {
                        if let Err(e) = handle_center_frame(
                            ft, &plaintext, &send_cipher, &mut write_half,
                            &mut send_counter, config_push_tx,
                        ).await {
                            tracing::debug!("center session error in handler: {e}");
                            return Err(e);
                        }
                    }
                    Ok(None) => {
                        // Unknown frame type, already skipped by read_frame.
                    }
                    Err(e) => {
                        tracing::debug!("center read error: {e}");
                        return Err(e.into());
                    }
                }
            }
            _ = &mut next_status => {
                let snapshot = metrics::try_get()
                    .map(|r| r.snapshot())
                    .unwrap_or(metrics::Snapshot {
                        uptime_secs: 0,
                        tunnels: vec![],
                        forwarders: vec![],
                    });
                let report = StatusReportMsg {
                    config_version_applied: 0,
                    uptime_secs: snapshot.uptime_secs,
                    snapshot,
                };
                if let Err(e) = proto::write_frame(
                    &mut write_half, &send_cipher, send_counter,
                    FrameType::StatusReport, &report,
                ).await {
                    tracing::debug!("status report send failed: {e}");
                    return Err(e.into());
                }
                send_counter += 1;
                last_status = tokio::time::Instant::now();
            }
        }
    }
}

/// Dispatch one decoded center frame (ConfigPush / Ping / other).
async fn handle_center_frame<W>(
    ft: FrameType,
    plaintext: &[u8],
    send_cipher: &crate::crypto::aead::AeadCipher,
    write_half: &mut W,
    send_counter: &mut u64,
    config_push_tx: &mpsc::Sender<ConfigPushMsg>,
) -> anyhow::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    match ft {
        FrameType::ConfigPush => {
            let push: ConfigPushMsg = serde_json::from_slice(plaintext)
                .map_err(|e| anyhow::anyhow!("invalid ConfigPush payload: {e}"))?;
            let ver = push.config_version;
            tracing::info!(
                config_version = ver,
                forwarders = push.forwarders.len(),
                "received config push from center"
            );
            let apply_ok = config_push_tx.try_send(push).is_ok();
            let ack = ConfigAckMsg {
                config_version: ver,
                ok: apply_ok,
                error: if apply_ok {
                    String::new()
                } else {
                    "config channel full".into()
                },
            };
            proto::write_frame(write_half, send_cipher, *send_counter, FrameType::ConfigAck, &ack)
                .await?;
            *send_counter += 1;
        }
        FrameType::Ping => {
            // Heartbeat ping from center — reply with Pong (empty payload).
            proto::write_frame(
                write_half,
                send_cipher,
                *send_counter,
                FrameType::Pong,
                &serde_json::json!({}),
            )
            .await?;
            *send_counter += 1;
        }
        _ => {
            tracing::trace!(?ft, "ignoring center frame");
        }
    }
    Ok(())
}
