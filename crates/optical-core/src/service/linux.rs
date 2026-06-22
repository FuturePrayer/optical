//! Linux systemd service management.
//!
//! Generates a unit file at `/etc/systemd/system/<service>.service` and drives
//! it via `systemctl`. All operations require root privileges. The service
//! name comes from [`AppKind::service_name`] (`optical` or `optical-center`).

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::paths::AppKind;

/// Path to the generated systemd unit file for the given app kind.
fn unit_path(app_kind: AppKind) -> String {
    format!("/etc/systemd/system/{}.service", app_kind.service_name())
}

/// Ensure the process is running as root; systemd writes require it.
/// Uses `id -u` (ubiquitous on Linux) to avoid a libc dependency.
fn ensure_root() -> Result<()> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("failed to invoke `id` to check privileges")?;
    if !output.status.success() {
        bail!("`id -u` failed; cannot determine effective UID");
    }
    let uid_str = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if uid_str != "0" {
        bail!("this operation requires root privileges (try running with sudo)");
    }
    Ok(())
}

/// Resolve `config_path` to an absolute path (relative to CWD).
fn resolve_absolute(config_path: &str) -> Result<String> {
    let p = Path::new(config_path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()?.join(p)
    };
    // Canonicalize if the file already exists (strips `..`, symlinks, etc.).
    match abs.canonicalize() {
        Ok(c) => Ok(c.to_string_lossy().into_owned()),
        Err(_) => Ok(abs.to_string_lossy().into_owned()),
    }
}

/// Detect the absolute path of the currently running executable.
fn current_exe() -> Result<String> {
    let exe = std::env::current_exe().context("failed to determine current executable path")?;
    Ok(exe.to_string_lossy().into_owned())
}

/// Build the systemd unit file content.
fn build_unit(app_kind: AppKind, binary: &str, config: &str) -> String {
    format!(
        r#"[Unit]
Description={desc}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} run --config {cfg}
Restart=on-failure
RestartSec=5
# Let systemd capture stdout/stderr into the journal
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#,
        desc = app_kind.service_description(),
        bin = binary,
        cfg = config,
    )
}

/// Runs `systemctl <args>...`, returning an error on non-zero exit.
fn systemctl(args: &[&str]) -> Result<()> {
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .context("failed to invoke systemctl (is systemd installed?)")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "systemctl {} failed: {} {}",
            args.join(" "),
            stdout.trim(),
            stderr.trim()
        );
    }
    Ok(())
}

pub fn install(config_path: &str, app_kind: AppKind) -> Result<()> {
    let service_name = app_kind.service_name();
    let unit = unit_path(app_kind);
    ensure_root()?;
    let binary = current_exe()?;
    let config = resolve_absolute(config_path)?;

    let content = build_unit(app_kind, &binary, &config);
    fs::write(&unit, content)
        .with_context(|| format!("failed to write unit file to {unit}"))?;
    tracing::info!("unit file written to {unit}");

    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", service_name])?;
    println!("Service '{service_name}' installed and enabled.");
    println!("Run `{service_name} start` to start it now, or `systemctl start {service_name}`.");
    Ok(())
}

pub fn uninstall(app_kind: AppKind) -> Result<()> {
    let service_name = app_kind.service_name();
    let unit = unit_path(app_kind);
    ensure_root()?;
    // Best-effort stop before removing.
    let _ = systemctl(&["stop", service_name]);
    systemctl(&["disable", service_name])?;
    if Path::new(&unit).exists() {
        fs::remove_file(&unit)
            .with_context(|| format!("failed to remove {unit}"))?;
    }
    systemctl(&["daemon-reload"])?;
    println!("Service '{service_name}' uninstalled.");
    Ok(())
}

pub fn start(app_kind: AppKind) -> Result<()> {
    let service_name = app_kind.service_name();
    ensure_root()?;
    systemctl(&["start", service_name])?;
    println!("Service '{service_name}' started.");
    Ok(())
}

pub fn stop(app_kind: AppKind) -> Result<()> {
    let service_name = app_kind.service_name();
    ensure_root()?;
    systemctl(&["stop", service_name])?;
    println!("Service '{service_name}' stopped.");
    Ok(())
}

pub fn restart(app_kind: AppKind) -> Result<()> {
    let service_name = app_kind.service_name();
    ensure_root()?;
    systemctl(&["restart", service_name])?;
    println!("Service '{service_name}' restarted.");
    Ok(())
}
