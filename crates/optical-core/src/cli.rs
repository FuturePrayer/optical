//! CLI subcommand implementations shared by the `optical` and `optical-center`
//! binaries.
//!
//! These functions are invoked from each binary's `main.rs` after `clap`
//! parsing. They contain the actual logic (admin HTTP requests, status
//! formatting, keygen, init), so the two binaries stay thin dispatchers.
//!
//! Functions that touch platform default paths (`cli_keygen`, `cli_init`)
//! take an [`AppKind`] so node and center use distinct directories.

use std::path::PathBuf;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::paths::{self, AppKind};

/// Minimal HTTP client: send a request to the admin endpoint and return
/// (status_code, json_body).
pub async fn admin_request(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> anyhow::Result<(u16, String)> {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to admin endpoint {addr}: {e}"))?;

    let body = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    let response_str = String::from_utf8_lossy(&response).into_owned();
    let body_start = response_str
        .find("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response"))?;

    let first_line = response_str.lines().next().unwrap_or("");
    let status: u16 = first_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

    Ok((status, response_str[body_start + 4..].to_string()))
}

#[derive(Deserialize)]
struct StatusResponse {
    uptime_secs: u64,
    tunnels: Vec<TunnelStatusJson>,
    forwarders: Vec<ForwarderStatusJson>,
}

#[derive(Deserialize)]
struct TunnelStatusJson {
    addr: String,
    role: String,
    state: String,
    rtt_us: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    reconnect_count: u32,
    frames_dropped: u64,
    uptime_secs: u64,
}

#[derive(Deserialize)]
struct ForwarderStatusJson {
    listen: String,
    proto: String,
    target: String,
    active_streams: u32,
    total_streams: u32,
    bytes_sent: u64,
    bytes_recv: u64,
}

#[derive(Deserialize)]
struct PingResponseJson {
    rtts_us: Vec<u64>,
    avg_us: u64,
    min_us: u64,
    max_us: u64,
    loss: u32,
    count: u32,
}

#[derive(Deserialize)]
struct BenchResponseJson {
    throughput_mbps: f64,
    bytes_sent: u64,
    bytes_recv: u64,
    elapsed_secs: f64,
}

#[derive(Deserialize)]
struct ErrorResponseJson {
    error: String,
}

pub fn format_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{}B", n)
    } else if n < 1024 * 1024 {
        format!("{:.1}KB", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1}MB", n as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}GB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub fn format_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{}h {}m", h, m)
    } else if m > 0 {
        format!("{}m {}s", m, s)
    } else {
        format!("{}s", s)
    }
}

pub fn format_rtt(us: u64) -> String {
    if us == 0 {
        return "—".to_string();
    }
    if us < 1000 {
        format!("{}μs", us)
    } else {
        format!("{:.2}ms", us as f64 / 1000.0)
    }
}

/// `status` subcommand — show real-time tunnel and forwarder status.
pub async fn cli_status(admin: &str) -> anyhow::Result<()> {
    let (status, body) = admin_request(admin, "GET", "/status", None).await?;
    if status != 200 {
        let err: ErrorResponseJson = serde_json::from_str(&body).unwrap_or(ErrorResponseJson {
            error: body.clone(),
        });
        anyhow::bail!("admin error ({}): {}", status, err.error);
    }

    let resp: StatusResponse = serde_json::from_str(&body)?;

    println!("optical — status (uptime: {})", format_uptime(resp.uptime_secs));
    println!();

    if resp.tunnels.is_empty() {
        println!("Tunnels: (none)");
    } else {
        println!("Tunnels:");
        for t in &resp.tunnels {
            let state = if t.state == "connected" {
                "CONNECTED"
            } else {
                "DISCONNECTED"
            };
            let drop_info = if t.frames_dropped > 0 {
                format!("  drops: {}", t.frames_dropped)
            } else {
                String::new()
            };
            println!(
                "  {:<10} {:<30} {:<12} RTT: {:<8} up: {:<8} ↑{}  ↓{}  reconnects: {}{}",
                t.role,
                t.addr,
                state,
                format_rtt(t.rtt_us),
                format_uptime(t.uptime_secs),
                format_bytes(t.bytes_sent),
                format_bytes(t.bytes_recv),
                t.reconnect_count,
                drop_info
            );
        }
    }

    println!();

    if resp.forwarders.is_empty() {
        println!("Forwarders: (none)");
    } else {
        println!("Forwarders:");
        for f in &resp.forwarders {
            println!(
                "  {} ({}) → {:<25} streams: {}/{}  ↑{}  ↓{}",
                f.listen,
                f.proto,
                f.target,
                f.active_streams,
                f.total_streams,
                format_bytes(f.bytes_sent),
                format_bytes(f.bytes_recv)
            );
        }
    }

    Ok(())
}

/// `ping` subcommand — measure tunnel latency via PING/PONG.
pub async fn cli_ping(admin: &str, tunnel: &str, count: u32) -> anyhow::Result<()> {
    println!("PING {} (via tunnel)", tunnel);

    let body = serde_json::json!({ "tunnel": tunnel, "count": count }).to_string();
    let (status, resp_body) = admin_request(admin, "POST", "/ping", Some(&body)).await?;

    if status != 200 {
        let err: ErrorResponseJson = serde_json::from_str(&resp_body).unwrap_or(ErrorResponseJson {
            error: resp_body.clone(),
        });
        anyhow::bail!("admin error ({}): {}", status, err.error);
    }

    let resp: PingResponseJson = serde_json::from_str(&resp_body)?;

    for (i, rtt) in resp.rtts_us.iter().enumerate() {
        println!("  seq={}  rtt={}", i + 1, format_rtt(*rtt));
    }

    println!();
    println!("--- {} ping statistics ---", tunnel);
    let loss_pct = if resp.count > 0 {
        resp.loss as f64 * 100.0 / resp.count as f64
    } else {
        0.0
    };
    println!(
        "{} probes, {} lost ({:.1}% loss)",
        resp.count, resp.loss, loss_pct
    );
    if !resp.rtts_us.is_empty() {
        println!(
            "rtt min/avg/max = {}/{}/{}",
            format_rtt(resp.min_us),
            format_rtt(resp.avg_us),
            format_rtt(resp.max_us)
        );
    }

    Ok(())
}

/// `bench` subcommand — measure tunnel throughput via ECHO/ECHO_REPLY.
pub async fn cli_bench(admin: &str, tunnel: &str, duration: u64, size: usize) -> anyhow::Result<()> {
    println!(
        "BENCH {} — {}s, {}B payload",
        tunnel, duration, size
    );
    println!("  (running, please wait...)");

    let body = serde_json::json!({
        "tunnel": tunnel,
        "duration_secs": duration,
        "payload_size": size
    })
    .to_string();
    let (status, resp_body) = admin_request(admin, "POST", "/bench", Some(&body)).await?;

    if status != 200 {
        let err: ErrorResponseJson = serde_json::from_str(&resp_body).unwrap_or(ErrorResponseJson {
            error: resp_body.clone(),
        });
        anyhow::bail!("admin error ({}): {}", status, err.error);
    }

    let resp: BenchResponseJson = serde_json::from_str(&resp_body)?;

    println!();
    println!(
        "Throughput: {:.2} Mbps ({}/{} in {:.1}s)",
        resp.throughput_mbps,
        format_bytes(resp.bytes_recv),
        format_bytes(resp.bytes_sent),
        resp.elapsed_secs
    );

    Ok(())
}

// ── keygen / init ────────────────────────────────────────────────────────────

/// Resolve a default key path for the given scope and app kind, or error with
/// guidance.
fn resolve_default_path(
    scope: paths::Scope,
    app_kind: AppKind,
    f: fn(paths::Scope, AppKind) -> Option<PathBuf>,
    kind: &str,
) -> anyhow::Result<PathBuf> {
    f(scope, app_kind).ok_or_else(|| {
        anyhow::anyhow!(
            "cannot determine default {kind} path for {scope} scope \
             (set HOME/APPDATA or pass --{kind} explicitly)"
        )
    })
}

/// `keygen` subcommand — generate an ML-DSA-65 key pair, defaulting to
/// platform-appropriate paths when none are given.
pub fn cli_keygen(
    app_kind: AppKind,
    system: bool,
    private_key: Option<PathBuf>,
    public_key: Option<PathBuf>,
) -> anyhow::Result<()> {
    let scope = if system {
        paths::Scope::System
    } else {
        paths::Scope::User
    };

    let private_key = match private_key {
        Some(p) => p,
        None => resolve_default_path(scope, app_kind, paths::default_private_key_path, "private-key")?,
    };
    let public_key = match public_key {
        Some(p) => p,
        None => resolve_default_path(scope, app_kind, paths::default_public_key_path, "public-key")?,
    };

    crate::crypto::pqdsa::keygen_to_files(&private_key, &public_key)?;
    paths::set_private_key_permissions(&private_key)?;

    println!("ML-DSA-65 key pair generated:");
    println!("  private key: {}", private_key.display());
    println!("  public key:  {}", public_key.display());
    if system {
        println!("  (system scope)");
    }
    println!();
    println!("To also generate a config file, run: {} init", app_kind.subdir());

    Ok(())
}

/// `init` subcommand — generate keys + PSK + config file from the template.
pub fn cli_init(
    app_kind: AppKind,
    template: paths::InitTemplate,
    system: bool,
    user: bool,
    config_dir: Option<PathBuf>,
    force: bool,
) -> anyhow::Result<()> {
    // Template ownership check: the `center` template is only meaningful for
    // the optical-center binary (which has the `center` feature). Reject it
    // here as a defensive guard even though the node binary's clap definition
    // doesn't expose it.
    if template == paths::InitTemplate::Center && app_kind != AppKind::Center {
        anyhow::bail!(
            "the 'center' template is only available in `optical-center init`. \
             Use `{} init --template standalone` or `--template managed-node`.",
            app_kind.subdir()
        );
    }

    if system && user {
        anyhow::bail!("--system and --user are mutually exclusive");
    }

    let base = if let Some(dir) = config_dir {
        dir
    } else {
        let scope = if system {
            paths::Scope::System
        } else {
            paths::Scope::User
        };
        paths::base_dir(scope, app_kind).ok_or_else(|| {
            anyhow::anyhow!(
                "cannot determine default directory for {scope} scope \
                 (set HOME/APPDATA or use --config-dir)"
            )
        })?
    };

    let config_path = base.join("config.yml");
    let keys_dir = base.join("keys");
    let logs_dir = base.join("logs");
    let priv_key = keys_dir.join("node.key");
    let pub_key = keys_dir.join("node.pub");

    // Guard against clobbering existing files unless --force.
    if !force {
        let mut existing = Vec::new();
        if config_path.exists() {
            existing.push(&config_path);
        }
        if priv_key.exists() {
            existing.push(&priv_key);
        }
        if pub_key.exists() {
            existing.push(&pub_key);
        }
        if !existing.is_empty() {
            eprintln!("The following files already exist:");
            for p in &existing {
                eprintln!("  {}", p.display());
            }
            anyhow::bail!("refusing to overwrite existing files; use --force to proceed");
        }
    }

    // Generate the key pair.
    std::fs::create_dir_all(&keys_dir)?;
    crate::crypto::pqdsa::keygen_to_files(&priv_key, &pub_key)?;
    paths::set_private_key_permissions(&priv_key)?;

    // Generate PSK(s) and render the config from the template.
    // The center template needs two PSKs: one for the tunnel trust domain
    // and one for the center management domain.
    let psk = crate::crypto::kdf::generate_psk();
    let psk_hex = format!("hex:{}", hex::encode(psk));
    let center_psk_hex = if template == paths::InitTemplate::Center {
        let center_psk = crate::crypto::kdf::generate_psk();
        Some(format!("hex:{}", hex::encode(center_psk)))
    } else {
        None
    };
    let config_content = paths::render_config(
        template,
        &psk_hex,
        center_psk_hex.as_deref(),
        &priv_key,
        &pub_key,
        &logs_dir,
    );
    std::fs::write(&config_path, config_content)?;

    // Compute this node's identity (SHA-256 of the public key) — printed for
    // the managed-node template so the user can register it on the center.
    let node_id = if template == paths::InitTemplate::ManagedNode {
        Some(crate::crypto::pqdsa::fingerprint_vk(
            &std::fs::read(&pub_key)?,
        ))
    } else {
        None
    };

    // Summary + role-specific guidance.
    println!("{} — initialization complete (template: {template})", app_kind.subdir());
    println!();
    println!("Generated files:");
    println!("  config:      {}", config_path.display());
    println!("  private key: {}", priv_key.display());
    println!("  public key:  {}", pub_key.display());
    println!("  PSK:         generated (embedded in config as 'hex:...')");
    if template == paths::InitTemplate::Center {
        println!("  center PSK:  generated (the second 'hex:...' in config, for center.psk)");
    }
    println!();
    println!("IMPORTANT — edit the config file before starting the service:");
    println!("  {}", config_path.display());
    println!();
    match template {
        paths::InitTemplate::Standalone => {
            println!("  - Set the correct 'tunnel_listen' (Node2) and/or 'forwarders' (Node1)");
            println!("    for this node's role; remove whichever role it should NOT play.");
            println!("  - Share the same PSK with peer nodes in the trust domain.");
        }
        paths::InitTemplate::ManagedNode => {
            println!("  - Set 'center.address' to your config center's address.");
            println!("  - Set 'center.psk' to the center's management-domain PSK (center_psk).");
            if let Some(id) = &node_id {
                println!("  - Register this node on the center. Its node_id is:");
                println!("      {id}");
            }
            println!("  - Do NOT set 'forwarders' here — they are pushed by the center.");
        }
        paths::InitTemplate::Center => {
            println!("  - Change 'center_admin_token' to a strong secret (browser login).");
            println!("  - The tunnel PSK ('psk') must match your nodes' 'psk'.");
            println!("  - The center PSK ('center_psk') must match your nodes' 'center.psk'.");
            println!("  - Add nodes to the whitelist via the web UI, or pre-seed nodes.json.");
        }
    }
    println!();
    println!("Then run:");
    println!("  {} run --config \"{}\"", app_kind.subdir(), config_path.display());

    Ok(())
}

/// `psk-gen` subcommand — generate a random 32-byte PSK (hex-encoded).
pub fn cli_psk_gen() {
    let psk = crate::crypto::kdf::generate_psk();
    println!("hex:{}", hex::encode(psk));
}
