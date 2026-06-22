//! Self-update: check GitHub Releases for a newer version and replace the
//! running binary in place.
//!
//! Uses a lightweight synchronous HTTP client (ureq) — `update` is a one-shot
//! CLI operation that does not need the tokio runtime, matching the style of
//! `service::install()` and other synchronous CLI commands.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::paths::AppKind;
use crate::service;

/// Current version, embedded at compile time.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Detect which app kind this binary is (node vs center) from the running
/// executable's file name. Used to pick the correct service name for restart
/// and (in Phase D) the correct release asset name. Falls back to `Node` if
/// the name doesn't contain "center".
fn detect_app_kind() -> AppKind {
    match std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
    {
        Some(name) if name.contains("center") => AppKind::Center,
        _ => AppKind::Node,
    }
}

/// GitHub Releases API endpoint for the latest release (public repo, no auth).
const RELEASES_API: &str = "https://api.github.com/repos/FuturePrayer/optical/releases/latest";

/// User-Agent string (GitHub API requires a User-Agent header).
const USER_AGENT: &str = concat!(
    "optical/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/FuturePrayer/optical)"
);

/// Asset file name for the current platform + app kind (runtime selection).
/// Must match the names produced by `.github/workflows/release.yml`.
///
/// The node binary downloads `optical-<target>` and the center binary
/// downloads `optical-center-<target>` — each only replaces itself, never the
/// other. Returns `None` on unsupported platforms.
fn asset_name_for(app_kind: AppKind) -> Option<String> {
    let prefix = match app_kind {
        AppKind::Node => "optical",
        AppKind::Center => "optical-center",
    };
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        Some(format!("{prefix}-x86_64-pc-windows-msvc.exe"))
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Some(format!("{prefix}-x86_64-unknown-linux-musl"))
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
    )))]
    {
        None
    }
}

/// Download/API timeout (covers slow networks for a ~10MB binary).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// GitHub Release JSON (only the fields we need).
#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// Entry point for the `optical update` subcommand.
///
/// - `check`: only report whether an update is available; do not download.
/// - `force`: download even when the latest version is not newer.
/// - `restart`: restart the system service after a successful update.
pub fn run_update(check: bool, force: bool, restart: bool) -> Result<()> {
    let app_kind = detect_app_kind();
    let current = semver::Version::parse(CURRENT_VERSION)
        .context("failed to parse current (compiled-in) version")?;

    println!("optical — self-update");
    println!("  current version: v{current}");

    // Resolve the release asset name for THIS binary (node vs center).
    let asset_name = asset_name_for(app_kind).ok_or_else(|| {
        anyhow!(
            "self-update is not supported on this platform/architecture \
             (only x86_64 Windows and x86_64 Linux-musl are published)"
        )
    })?;

    // Inform the user if a proxy was detected from the environment.
    if let Some(proxy) = ureq::Proxy::try_from_env() {
        println!("  using proxy: {}", proxy.uri());
    }

    // Fetch the latest release info from GitHub.
    let release = fetch_latest_release()?;
    let latest_tag = &release.tag_name;
    let latest = parse_tag(latest_tag)?;

    println!("  latest release:  {latest_tag}");

    // Decide whether an update is needed.
    let need_update = force || latest > current;
    if !need_update {
        println!();
        println!("Already up to date.");
        return Ok(());
    }

    if latest == current && force {
        println!("  (--force: reinstalling same version)");
    } else {
        println!("  update available: v{current} -> {latest_tag}");
    }

    if check {
        println!();
        println!("Run `optical update` (without --check) to perform the update.");
        return Ok(());
    }

    // Find the matching asset for this binary (node or center) + platform.
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .ok_or_else(|| {
            anyhow!(
                "no release asset matching '{asset_name}' found. \
                 Available assets: [{}]",
                release
                    .assets
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    // Find the SHA256 checksum asset published alongside the binary by the
    // release CI. Refusing to update without integrity verification guards
    // against a compromised GitHub account or CDN serving a tampered binary.
    let checksum_name = format!("{asset_name}.sha256");
    let checksum_asset = release
        .assets
        .iter()
        .find(|a| a.name == checksum_name)
        .ok_or_else(|| {
            anyhow!(
                "no SHA256 checksum asset matching '{checksum_name}' found. \
                 Refusing to update without integrity verification. \
                 Available assets: [{}]",
                release
                    .assets
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    println!(
        "  downloading {} ({}) ...",
        asset.name,
        format_bytes(asset.size)
    );

    // Download to a temp file in the same directory as the current exe
    // (same-directory rename is atomic on Linux; Windows uses .bak rename).
    let exe_path = current_exe_path()?;
    let temp_path = make_temp_path(&exe_path);
    download_asset(&asset.browser_download_url, &temp_path)?;

    // Verify SHA256 integrity before replacing the running binary.
    let expected_hash = fetch_checksum(&checksum_asset.browser_download_url)?;
    if let Err(e) = verify_sha256(&temp_path, &expected_hash) {
        // Keep the downloaded temp file for manual inspection.
        eprintln!("  integrity verification FAILED; keeping downloaded file for inspection:");
        eprintln!("    {}", temp_path.display());
        return Err(e).context(
            "SHA256 mismatch — refusing to install a binary that failed integrity verification",
        );
    }
    println!("  SHA256 verified OK");

    // Replace the running binary (platform-specific).
    replace_binary(&exe_path, &temp_path)?;
    println!("  installed: {}", exe_path.display());

    if restart {
        let app_kind = detect_app_kind();
        println!("  restarting service ...");
        match service::restart(app_kind) {
            Ok(()) => println!("  service restarted."),
            Err(e) => {
                // Restart failure (e.g. service not installed) is non-fatal —
                // the binary was updated successfully.
                eprintln!("  warning: service restart failed: {e}");
                eprintln!("  (binary updated; restart the service manually if needed)");
            }
        }
    } else {
        println!();
        println!("Update complete. Restart optical to apply the new version.");
        if cfg!(target_os = "windows") {
            println!("  (if running as a service: optical restart)");
        }
    }

    Ok(())
}

/// Build a ureq agent with the configured global timeout.
///
/// Proxy support: reads the standard `HTTPS_PROXY`/`https_proxy`/
/// `HTTP_PROXY`/`http_proxy`/`ALL_PROXY`/`all_proxy` environment variables
/// (via `ureq::Proxy::try_from_env()`). The `NO_PROXY`/`no_proxy` variable
/// is also honored to bypass the proxy for specific hosts. If no proxy
/// environment variable is set, the agent connects directly.
fn build_agent() -> ureq::Agent {
    let mut builder = ureq::config::Config::builder()
        .timeout_global(Some(REQUEST_TIMEOUT));

    if let Some(proxy) = ureq::Proxy::try_from_env() {
        builder = builder.proxy(Some(proxy));
    }

    ureq::Agent::new_with_config(builder.build())
}

/// Query the GitHub Releases API for the latest release.
fn fetch_latest_release() -> Result<GitHubRelease> {
    let agent = build_agent();

    let response = agent
        .get(RELEASES_API)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| anyhow!("GitHub API request failed: {e}"))?;

    let mut body = String::new();
    response
        .into_body()
        .into_reader()
        .read_to_string(&mut body)
        .map_err(|e| anyhow!("failed to read GitHub API response: {e}"))?;

    let release: GitHubRelease =
        serde_json::from_str(&body).context("failed to parse GitHub release JSON")?;

    Ok(release)
}

/// Parse a git tag like "v0.2.0" into a semver [`semver::Version`].
fn parse_tag(tag: &str) -> Result<semver::Version> {
    let trimmed = tag.trim_start_matches('v');
    semver::Version::parse(trimmed)
        .with_context(|| format!("failed to parse release tag '{tag}' as semver"))
}

/// Resolve the path of the currently running executable.
fn current_exe_path() -> Result<PathBuf> {
    std::env::current_exe().context("failed to determine current executable path")
}

/// Build a temp file path next to the exe for the download.
fn make_temp_path(exe_path: &Path) -> PathBuf {
    let mut name = exe_path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| "optical".into());
    name.push(".download.tmp");
    exe_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

/// Download an asset URL to `dest` via streaming copy.
fn download_asset(url: &str, dest: &Path) -> Result<()> {
    let agent = build_agent();

    let response = agent
        .get(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| anyhow!("download request failed: {e}"))?;

    let result: Result<()> = (|| {
        let mut reader = response.into_body().into_reader();
        let mut file = fs::File::create(dest)
            .with_context(|| format!("failed to create temp file at {}", dest.display()))?;
        std::io::copy(&mut reader, &mut file).context("failed to write downloaded data")?;
        file.sync_all().ok();
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(dest);
    }
    result
}

/// Fetch the SHA256 checksum asset (a small text file) and extract the hex hash.
///
/// The file is produced by `sha256sum` in the release CI, with the format
/// `<64 hex chars>  <filename>`. Only the leading 64 hex chars are used.
fn fetch_checksum(url: &str) -> Result<String> {
    let agent = build_agent();
    let response = agent
        .get(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| anyhow!("checksum download request failed: {e}"))?;

    let mut body = String::new();
    response
        .into_body()
        .into_reader()
        .read_to_string(&mut body)
        .map_err(|e| anyhow!("failed to read checksum response: {e}"))?;

    // sha256sum format: "<hash>  <filename>" — take the first whitespace-delimited token.
    let hash = body
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("checksum file is empty or malformed"))?;
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!(
            "checksum file does not contain a valid 64-char hex SHA256: got '{hash}'"
        );
    }
    Ok(hash.to_ascii_lowercase())
}

/// Compute the SHA256 of the file at `path` and compare against `expected`
/// (lowercase hex). Returns an error on mismatch.
fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open downloaded file {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).context("failed to hash downloaded file")?;
    let actual = hex::encode(hasher.finalize());
    if actual != expected {
        anyhow::bail!("SHA256 mismatch: expected {expected}, computed {actual}");
    }
    Ok(())
}

/// Replace the running binary with the downloaded one (platform-specific).
fn replace_binary(exe_path: &Path, temp_path: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        replace_binary_windows(exe_path, temp_path)
    }
    #[cfg(target_os = "linux")]
    {
        replace_binary_linux(exe_path, temp_path)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (exe_path, temp_path);
        anyhow::bail!("self-update is only supported on Windows and Linux");
    }
}

/// Windows: rename running exe -> `.bak`, move new binary to original path.
///
/// Windows allows renaming a running exe but not overwriting/deleting it.
/// The `.bak` file (which the current process keeps running from) is left
/// behind and cleaned up on the next `optical update`.
#[cfg(target_os = "windows")]
fn replace_binary_windows(exe_path: &Path, temp_path: &Path) -> Result<()> {
    let bak_path = exe_path.with_extension("bak");

    // Clean up a leftover .bak from a previous (successful) update.
    // By now the old process that was renamed to .bak has exited.
    if bak_path.exists() {
        let _ = fs::remove_file(&bak_path);
    }

    // Rename the running exe to .bak (Windows permits this).
    fs::rename(exe_path, &bak_path).with_context(|| {
        format!(
            "failed to rename running binary to {} \
             (may need administrator privileges)",
            bak_path.display()
        )
    })?;

    // Move the downloaded temp file into place.
    if let Err(e) = fs::rename(temp_path, exe_path) {
        // Restore the original binary before bailing out.
        let _ = fs::rename(&bak_path, exe_path);
        return Err(e).context("failed to move new binary into place");
    }

    // .bak is intentionally left behind (current process is running from it);
    // it will be cleaned up on the next `optical update`.
    Ok(())
}

/// Linux: atomic rename of temp file over the running exe.
///
/// Linux keeps the old inode alive for the running process; the new file
/// takes the path immediately. Permission bits are copied from the original.
#[cfg(target_os = "linux")]
fn replace_binary_linux(exe_path: &Path, temp_path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Copy permission bits from the original binary so the executable bit
    // is preserved (the temp file was created with default permissions).
    let mode = fs::metadata(exe_path)
        .map(|m| m.permissions().mode())
        .unwrap_or(0o755);
    fs::set_permissions(temp_path, fs::Permissions::from_mode(mode))
        .context("failed to set permissions on downloaded binary")?;

    fs::rename(temp_path, exe_path).with_context(|| {
        format!(
            "failed to replace binary at {} (may need root privileges)",
            exe_path.display()
        )
    })?;

    Ok(())
}

/// Format a byte count for human-readable display.
fn format_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{}B", n)
    } else if n < 1024 * 1024 {
        format!("{:.1}KB", n as f64 / 1024.0)
    } else {
        format!("{:.1}MB", n as f64 / (1024.0 * 1024.0))
    }
}
