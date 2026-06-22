//! Windows Service Control Manager (SCM) integration.
//!
//! - `install` / `uninstall`: register/unregister the service with SCM.
//! - `start` / `stop` / `restart`: control the registered service.
//! - `run_as_service`: entered when launched by SCM (with `--service`); uses
//!   `define_windows_service!` + `service_dispatcher::start` to drive the SCM
//!   dispatch loop, reporting RUNNING/STOPPED status and cancelling the
//!   application on a STOP control.
//!
//! The service name comes from [`AppKind::service_name`] (`optical` or
//! `optical-center`), passed into the SCM-launched entry via statics.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio_util::sync::CancellationToken;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::paths::AppKind;

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

// ---------------------------------------------------------------------------
// Pass config path + service name into the SCM-launched service_main via statics.
// ---------------------------------------------------------------------------

/// Holds the config path so the `define_windows_service!`-generated entry
/// point (a plain `fn`, which cannot capture closures) can access it.
static SERVICE_CONFIG: OnceLock<String> = OnceLock::new();

/// Holds the service name (from AppKind) for the same reason as SERVICE_CONFIG.
static SERVICE_NAME: OnceLock<String> = OnceLock::new();

// The macro generates `ffi_service_main` — a C-ABI function the Windows
// dispatcher calls. It delegates to `service_main` below.
windows_service::define_windows_service!(ffi_service_main, service_main);

/// Service entry point invoked by the SCM dispatcher on a background thread.
/// Signature is `fn(Vec<OsString>)` per the `define_windows_service!` contract.
fn service_main(_arguments: Vec<OsString>) {
    let config_path = match SERVICE_CONFIG.get() {
        Some(p) => p.as_str(),
        None => {
            tracing::error!("service launched without config context");
            return;
        }
    };
    let service_name = SERVICE_NAME
        .get()
        .cloned()
        .unwrap_or_else(|| "optical".to_string());

    // Channel used by the SCM control handler to signal STOP.
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

    let event_handler = move |control_event: ServiceControl| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Interrogate => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = match service_control_handler::register(&service_name, event_handler) {
        Ok(handle) => handle,
        Err(e) => {
            tracing::error!("failed to register service control handler: {e}");
            return;
        }
    };

    // Report RUNNING to SCM.
    let _ = report_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP,
        ServiceExitCode::NO_ERROR,
    );

    // Build the tokio runtime + cancellation token and run the app.
    let cancel = CancellationToken::new();
    let watcher_cancel = cancel.clone();

    // SCM STOP → cancel the token.
    std::thread::spawn(move || {
        let _ = stop_rx.recv();
        tracing::info!("SCM STOP received, shutting down...");
        watcher_cancel.cancel();
    });

    let exit_code = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => {
            let result = rt.block_on(crate::app::run_with_cancel(config_path, cancel));
            match result {
                Ok(()) => ServiceExitCode::NO_ERROR,
                Err(e) => {
                    tracing::error!("service error: {e:#}");
                    ServiceExitCode::ServiceSpecific(1)
                }
            }
        }
        Err(e) => {
            tracing::error!("failed to build tokio runtime: {e}");
            ServiceExitCode::ServiceSpecific(1)
        }
    };

    // Report STOPPED to SCM (required, otherwise SCM thinks we're stuck).
    let _ = report_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
    );
}

fn report_status(
    handle: &windows_service::service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
) -> Result<()> {
    handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: accepted,
            exit_code,
            wait_hint: Duration::default(),
            checkpoint: 0,
            process_id: None,
        })
        .context("failed to set service status")
}

/// Entered from `main` when `--service` is passed. Stores the config path and
/// service name, connects to the SCM dispatcher, and blocks until the service
/// stops.
pub fn run_as_service(config_path: &str, app_kind: AppKind) -> Result<()> {
    let service_name = app_kind.service_name();
    // Store config + service name for the service_main callback.
    SERVICE_CONFIG
        .set(config_path.to_owned())
        .map_err(|_| anyhow::anyhow!("service config already initialized"))?;
    let _ = SERVICE_NAME.set(service_name.to_string());

    service_dispatcher::start(service_name, ffi_service_main)
        .context("failed to start service control dispatcher")
}

// ---------------------------------------------------------------------------
// Service install / uninstall / start / stop / restart
// ---------------------------------------------------------------------------

/// Connect to the SCM; returns a clear error if not running as admin.
fn require_admin(manager_access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, manager_access).with_context(|| {
        "failed to connect to Service Control Manager — administrator privileges required"
    })
}

fn current_exe() -> Result<PathBuf> {
    std::env::current_exe().context("failed to determine current executable path")
}

fn resolve_absolute(config_path: &str) -> Result<PathBuf> {
    let p = std::path::Path::new(config_path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()?.join(p)
    };
    match abs.canonicalize() {
        Ok(c) => Ok(c),
        Err(_) => Ok(abs),
    }
}

/// Open the service with the requested access.
fn open_service(service_name: &str, access: ServiceAccess) -> Result<windows_service::service::Service> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .context("failed to connect to Service Control Manager")?;
    manager
        .open_service(service_name, access)
        .with_context(|| format!("failed to open service '{service_name}' (is it installed?)"))
}

pub fn install(config_path: &str, app_kind: AppKind) -> Result<()> {
    let service_name = app_kind.service_name();
    let exe = current_exe()?;
    let config = resolve_absolute(config_path)?;
    let config_str = config.to_string_lossy().into_owned();

    let manager = require_admin(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;

    // If the service already exists, fail with a helpful message.
    if manager
        .open_service(service_name, ServiceAccess::QUERY_STATUS)
        .is_ok()
    {
        bail!("service '{service_name}' is already installed; run `{service_name} uninstall` first");
    }

    let service_info = ServiceInfo {
        name: service_name.into(),
        display_name: service_name.into(),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            "run".into(),
            "--config".into(),
            config_str.into(),
            "--service".into(),
        ],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    // Create with CHANGE_CONFIG so we can set the description on the handle.
    let service = manager
        .create_service(&service_info, ServiceAccess::CHANGE_CONFIG)
        .context("failed to create service")?;

    service
        .set_description(app_kind.service_description())
        .context("failed to set service description")?;

    println!("Service '{service_name}' installed.");
    println!("Run `{service_name} start` to start it now, or use `services.msc`.");
    Ok(())
}

pub fn uninstall(app_kind: AppKind) -> Result<()> {
    let service_name = app_kind.service_name();
    let service = open_service(service_name, ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;

    // Best-effort stop before deleting.
    let _ = stop_internal(&service);

    service.delete().context("failed to delete service")?;
    println!("Service '{service_name}' uninstalled.");
    Ok(())
}

pub fn start(app_kind: AppKind) -> Result<()> {
    let service_name = app_kind.service_name();
    let service = open_service(service_name, ServiceAccess::START)?;
    service
        .start(&Vec::<OsString>::new())
        .context("failed to start service")?;
    println!("Service '{service_name}' started.");
    Ok(())
}

pub fn stop(app_kind: AppKind) -> Result<()> {
    let service_name = app_kind.service_name();
    let service = open_service(service_name, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    stop_internal(&service)?;
    println!("Service '{service_name}' stopped.");
    Ok(())
}

/// Send a STOP control and wait for the service to reach Stopped state.
fn stop_internal(service: &windows_service::service::Service) -> Result<()> {
    let status = service
        .query_status()
        .context("failed to query status")?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }
    service.stop().context("failed to send stop control")?;

    // Poll until stopped (max ~30s).
    let mut waited = 0u64;
    while waited < 30_000 {
        std::thread::sleep(Duration::from_millis(500));
        waited += 500;
        let status = service
            .query_status()
            .context("failed to query status")?;
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }
    }
    bail!("timed out waiting for service to stop");
}

pub fn restart(app_kind: AppKind) -> Result<()> {
    let service_name = app_kind.service_name();
    stop(app_kind)?;
    // Brief pause to let the SCM settle.
    std::thread::sleep(Duration::from_millis(500));
    start(app_kind)?;
    println!("Service '{service_name}' restarted.");
    Ok(())
}
