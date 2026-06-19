//! Forward module (Node1 role): listen on local ports and forward traffic
//! through the encrypted tunnel.

pub mod reverse;
pub mod tcp;
pub mod udp;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::admin::TunnelRegistry;
use crate::config::{ForwarderConfig, TunnelConfig};
use crate::crypto::pqdsa::DsaKeyPair;
use crate::metrics;
use crate::transport::Connect;
use crate::tunnel::client::TunnelClient;

/// Run all forwarders defined in the config.
///
/// The `transport` parameter controls the underlying network protocol used
/// to reach tunnel peers (TCP, KCP, ...). It is cloned for each tunnel
/// peer group.
///
/// `tunnel_registry` is populated with each `TunnelClient` so the admin
/// API can access them for ping/bench diagnostics.
///
/// Forwarders with `reverse: true` are handled differently: instead of
/// listening locally, they register with the peer (Node2) which listens
/// and sends connections back through the tunnel. If any reverse
/// registration fails (port conflict or disabled), this function returns
/// an error so the caller can exit the process.
pub async fn run_forwarders<C: Connect>(
    transport: C,
    forwarders: Vec<ForwarderConfig>,
    psk: [u8; 32],
    dsa_keypair: DsaKeyPair,
    tunnel_config: TunnelConfig,
    cancel: CancellationToken,
    tunnel_registry: Arc<TunnelRegistry>,
) -> Result<()> {
    // Group forwarders by tunnel address to share tunnel connections
    let mut by_tunnel: HashMap<String, Vec<ForwarderConfig>> = HashMap::new();
    for fwd in forwarders {
        by_tunnel.entry(fwd.tunnel.clone()).or_default().push(fwd);
    }

    // Shared slot for a fatal error from reverse registration.
    // When set, the token is cancelled to shut down all tasks, and the
    // error is returned from this function.
    let fatal_error: Arc<std::sync::Mutex<Option<anyhow::Error>>> =
        Arc::new(std::sync::Mutex::new(None));

    let mut handles = Vec::new();

    for (tunnel_addr, fwds) in by_tunnel {
        // Split into normal and reverse forwarders
        let (normal_fwds, reverse_fwds): (Vec<_>, Vec<_>) =
            fwds.into_iter().partition(|f| !f.reverse);

        // Register tunnel metrics (pre-register so Tunnel::new can find it)
        if let Some(reg) = metrics::try_get() {
            reg.register_tunnel(&tunnel_addr, metrics::TunnelRole::Client);
        }

        let tunnel_client = TunnelClient::start(
            transport.clone(),
            tunnel_addr.clone(),
            psk,
            dsa_keypair.clone(),
            tunnel_config.clone(),
            cancel.clone(),
        );
        let tunnel_client = Arc::new(Mutex::new(tunnel_client));

        // Register in tunnel registry for admin access
        tunnel_registry.insert(tunnel_addr.clone(), tunnel_client.clone());

        // Spawn normal forwarder listeners
        for fwd in normal_fwds {
            // Register forwarder metrics
            if let Some(reg) = metrics::try_get() {
                reg.register_forwarder(fwd.listen, fwd.proto, &fwd.target);
            }

            let tc = tunnel_client.clone();
            let cancel = cancel.clone();
            let tunnel_cfg = tunnel_config.clone();
            let proto = fwd.proto;
            let listen = fwd.listen;
            let target = fwd.target.clone();

            handles.push(tokio::spawn(async move {
                match proto {
                    crate::config::Protocol::Tcp => {
                        if let Err(e) = tcp::run(listen, target, tc, cancel).await {
                            tracing::error!("TCP forwarder on {} error: {e:#}", listen);
                        }
                    }
                    crate::config::Protocol::Udp => {
                        if let Err(e) = udp::run(listen, target, tc, tunnel_cfg, cancel).await {
                            tracing::error!("UDP forwarder on {} error: {e:#}", listen);
                        }
                    }
                }
            }));
        }

        // Spawn reverse registration task (if any reverse fwds for this tunnel)
        if !reverse_fwds.is_empty() {
            let tc = tunnel_client.clone();
            let cancel = cancel.clone();
            let fatal = fatal_error.clone();

            handles.push(tokio::spawn(async move {
                let result =
                    reverse::register_reverse_forwarders(tc, reverse_fwds, cancel.clone()).await;
                if let Err(e) = result {
                    tracing::error!("reverse registration fatal error: {e:#}");
                    *fatal.lock().unwrap() = Some(e);
                    // Trigger shutdown of all tasks
                    cancel.cancel();
                }
            }));
        }
    }

    // Wait for all handles (they exit when cancel is triggered)
    for handle in handles {
        let _ = handle.await;
    }

    // If a reverse registration had a fatal error, return it
    if let Some(e) = fatal_error.lock().unwrap().take() {
        return Err(e);
    }

    Ok(())
}
