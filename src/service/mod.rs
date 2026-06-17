//! System service management (install / uninstall / start / stop / restart)
//! and cross-platform shutdown signal handling.
//!
//! Platform backends:
//! - Linux: systemd unit file + `systemctl` commands ([`linux`])
//! - Windows: Service Control Manager (SCM) via the `windows-service` crate ([`windows`])

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use self::windows as platform;

/// Fixed service name used across both platforms.
pub const SERVICE_NAME: &str = "optical";

/// A short human-readable description embedded in the service metadata.
pub const SERVICE_DESCRIPTION: &str =
    "optical — post-quantum encrypted tunnel forwarding service";

/// Waits for a shutdown signal.
///
/// - On Unix: listens for both `SIGINT` (Ctrl+C) and `SIGTERM` (systemd default).
/// - On Windows (console mode): waits for Ctrl+C.
///
/// Returns once any shutdown signal is received.
pub async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                tracing::info!("SIGINT received, shutting down...");
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received, shutting down...");
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("failed to listen for ctrl_c: {e}");
            // Block forever as fallback; the runtime will be killed externally.
            std::future::pending::<()>().await;
        }
        tracing::info!("Ctrl+C received, shutting down...");
    }
}

// ---------------------------------------------------------------------------
// Cross-platform service control trait + dispatcher
// ---------------------------------------------------------------------------

/// Installs the service. `config_path` is resolved to an absolute path and
/// embedded into the service definition so the service can locate its config
/// at runtime.
pub fn install(config_path: &str) -> anyhow::Result<()> {
    platform::install(config_path)
}

/// Removes (unregisters) the service.
pub fn uninstall() -> anyhow::Result<()> {
    platform::uninstall()
}

/// Starts the already-registered service.
pub fn start() -> anyhow::Result<()> {
    platform::start()
}

/// Stops the running service.
pub fn stop() -> anyhow::Result<()> {
    platform::stop()
}

/// Restarts the service.
pub fn restart() -> anyhow::Result<()> {
    platform::restart()
}

// ---------------------------------------------------------------------------
// Windows-only: SCM dispatch entry point
// ---------------------------------------------------------------------------

/// On Windows, when launched by SCM (with `--service`), this enters the SCM
/// dispatch loop and blocks until the service stops.
///
/// On non-Windows this is a no-op fallback: systemd launches the binary
/// directly (without `--service`), so this branch is only reached if the flag
/// is passed manually — in which case it runs in console mode.
pub fn run_as_service(config_path: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        platform::run_as_service(config_path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Linux services are launched directly by systemd; --service is a
        // Windows-only concept. If passed here, just run in console mode.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(crate::app::run(config_path))
    }
}
