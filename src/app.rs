//! Application orchestration: load config, start tunnel server + forwarders,
//! and drive graceful shutdown via a [`CancellationToken`].

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

use crate::admin::TunnelRegistry;
use crate::config::Config;
use crate::crypto::pqdsa;
use crate::forward::reverse::ReverseRegistry;
use crate::metrics;

/// Console mode: runs the application with signal-based shutdown.
///
/// Spawns a background task that listens for `SIGINT`/`SIGTERM` (Unix) or
/// `Ctrl+C` (Windows) and cancels the token, then delegates to
/// [`run_with_cancel`].
pub async fn run(config_path: &str) -> Result<()> {
    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();

    // Background: wait for a shutdown signal, then cancel.
    tokio::spawn(async move {
        crate::service::wait_for_shutdown_signal().await;
        signal_cancel.cancel();
    });

    run_with_cancel(config_path, cancel).await
}

/// Core orchestration: load config, start tunnel server + forwarders, then
/// wait until `cancel` is triggered and drain all spawned tasks.
///
/// This is shared between console mode ([`run`]) and Windows SCM service mode
/// (the STOP control cancels the token).
pub async fn run_with_cancel(config_path: &str, cancel: CancellationToken) -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::load(config_path).context("failed to load config")?;

    tracing::info!("optical starting up");
    tracing::info!(
        "node1 (forwarder): {}  node2 (tunnel server): {}",
        config.is_node1(),
        config.is_node2()
    );

    // Initialize metrics registry (global, OnceLock)
    metrics::init();
    metrics::history::spawn_sampler(cancel.clone());

    // Tunnel client registry — shared with admin API for ping/bench
    let tunnel_registry = Arc::new(TunnelRegistry::new());

    // Reverse tunnel registry — shared across all tunnel connections on the
    // server side to prevent listen-address conflicts.
    let reverse_registry = Arc::new(ReverseRegistry::new());

    // Load ML-DSA key pair
    let dsa_keypair = pqdsa::load_keypair(&config.mldsa_private_key, &config.mldsa_public_key)
        .context("failed to load ML-DSA key pair")?;
    tracing::info!("ML-DSA-65 key pair loaded");

    let psk = config.psk_bytes().context("invalid PSK")?;

    // Spawn tunnel server (Node2 role) if configured
    let mut handles = Vec::new();

    if let Some(listen_addr) = config.tunnel_listen {
        let psk = psk;
        let dsa_keypair = dsa_keypair.clone();
        let cancel = cancel.clone();
        let tunnel_cfg = config.tunnel.clone();
        let allow_reverse = config.allow_reverse;
        let rev_registry = reverse_registry.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = crate::tunnel::server::run(
                crate::transport::tcp::TcpTransport,
                listen_addr,
                psk,
                dsa_keypair,
                tunnel_cfg,
                allow_reverse,
                rev_registry,
                cancel,
            )
            .await
            {
                tracing::error!("tunnel server error: {e:#}");
            }
        }));
    }

    // Spawn forwarders (Node1 role) if configured.
    // A shared error slot captures fatal errors from reverse registration —
    // when set, the process should exit with a non-zero code.
    let forwarder_error: Arc<std::sync::Mutex<Option<anyhow::Error>>> =
        Arc::new(std::sync::Mutex::new(None));

    if !config.forwarders.is_empty() {
        let forwarders = config.forwarders.clone();
        let psk = psk;
        let dsa_keypair = dsa_keypair.clone();
        let tunnel_cfg = config.tunnel.clone();
        let cancel = cancel.clone();
        let registry = tunnel_registry.clone();
        let fwd_error = forwarder_error.clone();
        handles.push(tokio::spawn(async move {
            let result = crate::forward::run_forwarders(
                crate::transport::tcp::TcpTransport,
                forwarders,
                psk,
                dsa_keypair,
                tunnel_cfg,
                cancel,
                registry,
            )
            .await;
            if let Err(e) = result {
                tracing::error!("forwarder error: {e:#}");
                *fwd_error.lock().unwrap() = Some(e);
            }
        }));
    }

    // Spawn admin API server if configured
    if let Some(admin_addr) = config.admin_listen {
        let registry = tunnel_registry.clone();
        let cancel = cancel.clone();
        handles.push(tokio::spawn(async move {
            crate::admin::run(admin_addr, registry, cancel).await;
        }));
    }

    // Wait for cancellation signal, then drain all tasks.
    cancel.cancelled().await;
    tracing::info!("shutdown triggered, draining tasks...");

    for handle in handles {
        let _ = handle.await;
    }

    tracing::info!("optical shutdown complete");

    // If a forwarder had a fatal error (e.g. reverse registration conflict),
    // propagate it so the process exits with a non-zero code. When running
    // as a service, the SCM/systemd will report the service as stopped.
    if let Some(e) = forwarder_error.lock().unwrap().take() {
        return Err(e);
    }

    Ok(())
}
