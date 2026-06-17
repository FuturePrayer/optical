//! Linux systemd service management.
//!
//! Generates a unit file at `/etc/systemd/system/optical.service` and drives
//! it via `systemctl`. All operations require root privileges.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use super::SERVICE_DESCRIPTION;
use super::SERVICE_NAME;

/// Path to the generated systemd unit file.
const UNIT_PATH: &str = "/etc/systemd/system/optical.service";

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
fn build_unit(binary: &str, config: &str) -> String {
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
        desc = SERVICE_DESCRIPTION,
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

pub fn install(config_path: &str) -> Result<()> {
    ensure_root()?;
    let binary = current_exe()?;
    let config = resolve_absolute(config_path)?;

    let unit = build_unit(&binary, &config);
    fs::write(UNIT_PATH, unit)
        .with_context(|| format!("failed to write unit file to {UNIT_PATH}"))?;
    tracing::info!("unit file written to {UNIT_PATH}");

    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", SERVICE_NAME])?;
    println!("Service '{SERVICE_NAME}' installed and enabled.");
    println!("Run `optical start` to start it now, or `systemctl start {SERVICE_NAME}`.");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    ensure_root()?;
    // Best-effort stop before removing.
    let _ = systemctl(&["stop", SERVICE_NAME]);
    systemctl(&["disable", SERVICE_NAME])?;
    if Path::new(UNIT_PATH).exists() {
        fs::remove_file(UNIT_PATH)
            .with_context(|| format!("failed to remove {UNIT_PATH}"))?;
    }
    systemctl(&["daemon-reload"])?;
    println!("Service '{SERVICE_NAME}' uninstalled.");
    Ok(())
}

pub fn start() -> Result<()> {
    ensure_root()?;
    systemctl(&["start", SERVICE_NAME])?;
    println!("Service '{SERVICE_NAME}' started.");
    Ok(())
}

pub fn stop() -> Result<()> {
    ensure_root()?;
    systemctl(&["stop", SERVICE_NAME])?;
    println!("Service '{SERVICE_NAME}' stopped.");
    Ok(())
}

pub fn restart() -> Result<()> {
    ensure_root()?;
    systemctl(&["restart", SERVICE_NAME])?;
    println!("Service '{SERVICE_NAME}' restarted.");
    Ok(())
}
