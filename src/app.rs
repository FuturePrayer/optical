//! Application orchestration: load config, start tunnel server + forwarders,
//! and drive graceful shutdown via a [`CancellationToken`].

use std::path::PathBuf;
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
    let config = Config::load(config_path).context("failed to load config")?;

    // Initialize logging. The returned guard must be held alive for the whole
    // process lifetime so that the non-blocking file writer flushes on exit.
    let _log_guard = init_logging(&config.log_dir);

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
        let tunnel_transport = config.tunnel_transport;
        handles.push(tokio::spawn(async move {
            if let Err(e) = crate::tunnel::server::run(
                crate::transport::AnyTransport::for_server(tunnel_transport),
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
                crate::transport::AnyTransport::for_client(),
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

    // Drain each task with a bounded timeout. A stuck dial (now bounded by
    // dial_timeout/open_ack_timeout) or a slow peer should not block shutdown
    // indefinitely — systemd/SCM would otherwise force-kill the service.
    let drain_timeout = std::time::Duration::from_secs(30);
    for handle in handles {
        match tokio::time::timeout(drain_timeout, handle).await {
            Ok(_) => {}
            Err(_) => {
                tracing::warn!(
                    "task did not exit within {:?} during shutdown, abandoning",
                    drain_timeout
                );
            }
        }
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

/// Initialize the global tracing subscriber.
///
/// Logs always go to stdout. When `log_dir` is `Some`, logs are *additionally*
/// written to daily-rotating files in that directory
/// (e.g. `optical.log.2026-06-19`).
///
/// Returns the [`WorkerGuard`] for the non-blocking file writer when file
/// logging is enabled. The guard must be held for the lifetime of the process
/// to ensure buffered logs are flushed on exit; dropping it early is safe but
/// may lose the most recent buffered lines.
fn init_logging(log_dir: &Option<PathBuf>) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let stdout_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

    let Some(dir) = log_dir else {
        // stdout-only (backwards-compatible behavior).
        tracing_subscriber::registry()
            .with(env_filter)
            .with(stdout_layer)
            .init();
        return None;
    };

    // Create the log directory if it doesn't exist.
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!(
            "warning: failed to create log dir '{}': {e}; logging to stdout only",
            dir.display()
        );
        tracing_subscriber::registry()
            .with(env_filter)
            .with(stdout_layer)
            .init();
        return None;
    }

    let file_appender = tracing_appender::rolling::daily(dir, "optical.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false) // strip ANSI colors from file output
        .with_writer(non_blocking);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    tracing::info!("logging to daily-rotating files in {}", dir.display());
    Some(guard)
}
