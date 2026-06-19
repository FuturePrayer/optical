//! Application orchestration: load config, start tunnel server + forwarders,
//! and drive graceful shutdown via a [`CancellationToken`].

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

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
    let _log_guard = init_logging(&config.log_dir, config.log_max_size_mb, config.log_retention_days);

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
        let socket_buf = config.tunnel.socket_buffer_bytes;
        let kcp_config = crate::transport::kcp::fastest_kcp_config();
        handles.push(tokio::spawn(async move {
            if let Err(e) = crate::tunnel::server::run(
                crate::transport::AnyTransport::for_server(tunnel_transport, socket_buf, kcp_config),
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
        let socket_buf = config.tunnel.socket_buffer_bytes;
        let kcp_config = crate::transport::kcp::fastest_kcp_config();
        handles.push(tokio::spawn(async move {
            let result = crate::forward::run_forwarders(
                crate::transport::AnyTransport::for_client(socket_buf, kcp_config),
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
/// written to rolling files in that directory. Rotation is triggered by two
/// conditions (whichever fires first):
/// - **Daily**: a new date (UTC) opens a new file.
/// - **Size cap**: when `max_size_mb > 0` and the current file reaches
///   `max_size_mb` MiB, a new file with an incremented sequence suffix opens.
///
/// File naming: `optical.log.YYYY-MM-DD[.N]` where `.N` is the sequence
/// number within a day (omitted for the first file).
///
/// Retention: files older than `retention_days` (by mtime) are deleted on
/// startup and after each daily rotation. Set `retention_days = 0` to disable.
///
/// Returns the [`WorkerGuard`] for the non-blocking file writer when file
/// logging is enabled. The guard must be held for the lifetime of the process
/// to ensure buffered logs are flushed on exit; dropping it early is safe but
/// may lose the most recent buffered lines.
fn init_logging(
    log_dir: &Option<PathBuf>,
    max_size_mb: u64,
    retention_days: u64,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
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

    // Purge files older than retention_days on startup.
    if retention_days > 0 {
        purge_old_logs(dir, retention_days);
    }

    let writer = RollingWriter::new(dir.clone(), max_size_mb, retention_days);
    let (non_blocking, guard) = tracing_appender::non_blocking(writer);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(non_blocking);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    let max_size_str = if max_size_mb == 0 { "unlimited".to_string() } else { max_size_mb.to_string() };
    let retention_str = if retention_days == 0 { "unlimited".to_string() } else { retention_days.to_string() };
    tracing::info!(
        "logging to rolling files in {} (max_size={}MB, retention={}days)",
        dir.display(),
        max_size_str,
        retention_str
    );
    Some(guard)
}

/// Delete log files in `dir` whose modification time is older than
/// `retention_days` days. Only files matching the `optical.log.*` prefix are
/// considered. Errors are logged at warn level and do not abort logging.
fn purge_old_logs(dir: &Path, retention_days: u64) {
    let cutoff = match SystemTime::now().checked_sub(Duration::from_secs(retention_days * 86400)) {
        Some(t) => t,
        None => return,
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, dir = %dir.display(), "failed to read log dir for retention purge");
            return;
        }
    };
    let mut purged = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.starts_with("optical.log.") {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if let Ok(mtime) = meta.modified() {
                if mtime < cutoff {
                    if std::fs::remove_file(&path).is_ok() {
                        purged += 1;
                    }
                }
            }
        }
    }
    if purged > 0 {
        tracing::info!("purged {purged} log file(s) older than {retention_days} day(s)");
    }
}

/// A `tracing` writer that rotates log files by date (daily) and/or size.
///
/// Thread-safe via an internal `Mutex`. The `non_blocking` wrapper from
/// `tracing-appender` feeds bytes here from a dedicated writer thread, so
/// contention is minimal (only that thread calls `write_all`).
struct RollingWriter {
    inner: Mutex<RollingWriterInner>,
}

struct RollingWriterInner {
    dir: PathBuf,
    max_bytes: u64,
    retention_days: u64,
    file: std::fs::File,
    current_date: String,
    seq: u32,
    written: u64,
}

impl RollingWriterInner {
    /// Check whether rotation is needed and perform it if so. Called after
    /// each write. Rotation triggers when:
    /// - the date has changed (daily rotation), or
    /// - max_bytes > 0 and the current file exceeds it (size rotation).
    fn maybe_rotate(&mut self) {
        let today = today_utc();
        if today != self.current_date {
            self.current_date = today;
            self.seq = 0;
            self.open_new_file();
            if self.retention_days > 0 {
                purge_old_logs(&self.dir, self.retention_days);
            }
            return;
        }
        if self.max_bytes > 0 && self.written >= self.max_bytes {
            self.seq += 1;
            self.open_new_file();
        }
    }

    fn open_new_file(&mut self) {
        let path = log_path(&self.dir, &self.current_date, self.seq);
        self.file = open_log_file(&path);
        self.written = 0;
    }
}

impl RollingWriter {
    fn new(dir: PathBuf, max_size_mb: u64, retention_days: u64) -> Self {
        let max_bytes = max_size_mb.saturating_mul(1024 * 1024);
        let date = today_utc();
        let seq = highest_seq_for_date(&dir, &date);
        let path = log_path(&dir, &date, seq);
        let file = open_log_file(&path);
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Self {
            inner: Mutex::new(RollingWriterInner {
                dir,
                max_bytes,
                retention_days,
                file,
                current_date: date,
                seq,
                written,
            }),
        }
    }
}

/// Today's date in UTC as "YYYY-MM-DD".
fn today_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs_to_date(secs)
}

/// Convert Unix seconds to a "YYYY-MM-DD" UTC date string (no chrono dep).
fn secs_to_date(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    // Civil-from-days algorithm (Howard Hinnant). Day 0 = 1970-01-01.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Build the log file path for a given date and sequence.
fn log_path(dir: &Path, date: &str, seq: u32) -> PathBuf {
    let name = if seq == 0 {
        format!("optical.log.{date}")
    } else {
        format!("optical.log.{date}.{seq}")
    };
    dir.join(name)
}

/// Find the highest existing sequence number for a given date in `dir`, so
/// that a restart continues appending to a fresh file instead of overwriting.
fn highest_seq_for_date(dir: &Path, date: &str) -> u32 {
    let prefix = format!("optical.log.{date}");
    let mut max_seq: u32 = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == prefix.as_str() {
                continue;
            }
            if let Some(rest) = name.strip_prefix(&format!("{prefix}.")) {
                if let Ok(n) = rest.parse::<u32>() {
                    if n > max_seq {
                        max_seq = n;
                    }
                }
            }
        }
    }
    max_seq
}

/// Open (or create) a log file for appending.
fn open_log_file(path: &Path) -> std::fs::File {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|e| {
            eprintln!("warning: failed to open log file {}: {e}", path.display());
            #[cfg(unix)]
            {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/null")
                    .unwrap_or_else(|_| std::fs::File::create("/dev/null").unwrap())
            }
            #[cfg(windows)]
            {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("NUL")
                    .unwrap_or_else(|_| std::fs::File::create("NUL").unwrap())
            }
        })
}

impl std::io::Write for RollingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.file.write_all(buf)?;
        inner.written += buf.len() as u64;
        inner.maybe_rotate();
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.file.flush()
    }
}
