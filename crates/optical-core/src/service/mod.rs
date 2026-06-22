//! System service management (install / uninstall / start / stop / restart)
//! and cross-platform shutdown signal handling.
//!
//! Platform backends:
//! - Linux: systemd unit file + `systemctl` commands ([`linux`])
//! - Windows: Service Control Manager (SCM) via the `windows-service` crate ([`windows`])
//!
//! All control functions take an [`AppKind`] so the node (`optical`) and the
//! config center (`optical-center`) register under distinct service names.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use self::windows as platform;

use crate::paths::AppKind;

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
/// at runtime. The service is registered under `app_kind.service_name()`.
pub fn install(config_path: &str, app_kind: AppKind) -> anyhow::Result<()> {
    platform::install(config_path, app_kind)
}

/// Removes (unregisters) the service registered under `app_kind.service_name()`.
pub fn uninstall(app_kind: AppKind) -> anyhow::Result<()> {
    platform::uninstall(app_kind)
}

/// Starts the already-registered service.
pub fn start(app_kind: AppKind) -> anyhow::Result<()> {
    platform::start(app_kind)
}

/// Stops the running service.
pub fn stop(app_kind: AppKind) -> anyhow::Result<()> {
    platform::stop(app_kind)
}

/// Restarts the service.
pub fn restart(app_kind: AppKind) -> anyhow::Result<()> {
    platform::restart(app_kind)
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
pub fn run_as_service(config_path: &str, app_kind: AppKind) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        platform::run_as_service(config_path, app_kind)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app_kind;
        // Linux services are launched directly by systemd; --service is a
        // Windows-only concept. If passed here, just run in console mode.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(crate::app::run(config_path))
    }
}
