mod admin;
mod app;
mod config;
mod crypto;
mod dial;
mod error;
mod forward;
mod metrics;
mod paths;
mod proto;
mod service;
mod transport;
mod tunnel;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// optical — post-quantum encrypted tunnel forwarding tool
#[derive(Parser)]
#[command(name = "optical", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the tunnel node with a config file (console mode)
    Run {
        /// Path to YAML config file
        #[arg(short, long)]
        config: String,
        /// Internal: run as a Windows service via SCM dispatch.
        /// Set automatically by the service registration; not for manual use.
        #[arg(long, hide = true)]
        service: bool,
    },
    /// Register optical as a system service
    Install {
        /// Path to YAML config file (resolved to absolute and embedded in the service)
        #[arg(short, long)]
        config: String,
    },
    /// Remove the optical system service
    Uninstall,
    /// Start the optical system service
    Start,
    /// Stop the optical system service
    Stop,
    /// Restart the optical system service
    Restart,
    /// Generate a new ML-DSA-65 key pair
    Keygen {
        /// Use system-level default paths (requires admin/root).
        /// Mutually exclusive with explicit path overrides.
        #[arg(long)]
        system: bool,
        /// Output path for private key
        /// (default: <user-dir>/keys/node.key, or <system-dir>/keys/node.key with --system)
        #[arg(long)]
        private_key: Option<PathBuf>,
        /// Output path for public key
        /// (default: <user-dir>/keys/node.pub, or <system-dir>/keys/node.pub with --system)
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
    /// Initialize a new node: generate keys, PSK, and a config file from the template
    Init {
        /// Use system-level paths (requires admin/root).
        ///   Linux: /etc/optical/    Windows: %PROGRAMDATA%\optical\
        #[arg(long)]
        system: bool,
        /// Use user-level paths (default).
        ///   Linux: ~/.config/optical/    Windows: %APPDATA%\optical\
        #[arg(long)]
        user: bool,
        /// Override the base directory for config + keys
        #[arg(long)]
        config_dir: Option<PathBuf>,
        /// Overwrite existing config / key files
        #[arg(long)]
        force: bool,
    },
    /// Generate a random 32-byte PSK (hex-encoded)
    PskGen,
    /// Show real-time tunnel and forwarder status
    Status {
        /// Admin endpoint address
        #[arg(long, default_value = "127.0.0.1:9100")]
        admin: String,
    },
    /// Measure tunnel latency (RTT) via PING/PONG
    Ping {
        /// Admin endpoint address
        #[arg(long, default_value = "127.0.0.1:9100")]
        admin: String,
        /// Tunnel address to ping (must match config)
        #[arg(long)]
        tunnel: String,
        /// Number of ping probes
        #[arg(short, long, default_value = "10")]
        count: u32,
    },
    /// Measure tunnel throughput via ECHO/ECHO_REPLY
    Bench {
        /// Admin endpoint address
        #[arg(long, default_value = "127.0.0.1:9100")]
        admin: String,
        /// Tunnel address to benchmark
        #[arg(long)]
        tunnel: String,
        /// Test duration in seconds
        #[arg(short, long, default_value = "10")]
        duration: u64,
        /// Payload size per ECHO frame in bytes
        #[arg(short, long, default_value = "65535")]
        size: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { config, service } => {
            if service {
                // Windows: enter SCM dispatch loop (blocks until service stops).
                service::run_as_service(&config)?;
            } else {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(app::run(&config))?;
            }
        }
        Commands::Install { config } => {
            service::install(&config)?;
        }
        Commands::Uninstall => {
            service::uninstall()?;
        }
        Commands::Start => {
            service::start()?;
        }
        Commands::Stop => {
            service::stop()?;
        }
        Commands::Restart => {
            service::restart()?;
        }
        Commands::Keygen {
            system,
            private_key,
            public_key,
        } => {
            cli_keygen(system, private_key, public_key)?;
        }
        Commands::Init {
            system,
            user,
            config_dir,
            force,
        } => {
            cli_init(system, user, config_dir, force)?;
        }
        Commands::PskGen => {
            let psk = crypto::kdf::generate_psk();
            println!("hex:{}", hex::encode(psk));
        }
        Commands::Status { admin } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(cli_status(&admin))?;
        }
        Commands::Ping {
            admin,
            tunnel,
            count,
        } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(cli_ping(&admin, &tunnel, count))?;
        }
        Commands::Bench {
            admin,
            tunnel,
            duration,
            size,
        } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(cli_bench(&admin, &tunnel, duration, size))?;
        }
    }

    Ok(())
}

// ── CLI subcommand implementations ──────────────────────────────────────────

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Minimal HTTP client: send a request to the admin endpoint and return
/// (status_code, json_body).
async fn admin_request(
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
    state: String,
    rtt_us: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    reconnect_count: u32,
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

fn format_bytes(n: u64) -> String {
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

fn format_uptime(secs: u64) -> String {
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

fn format_rtt(us: u64) -> String {
    if us == 0 {
        return "—".to_string();
    }
    if us < 1000 {
        format!("{}μs", us)
    } else {
        format!("{:.2}ms", us as f64 / 1000.0)
    }
}

async fn cli_status(admin: &str) -> anyhow::Result<()> {
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
            println!(
                "  {:<30} {:<12} RTT: {:<8} up: {:<8} ↑{}  ↓{}  reconnects: {}",
                t.addr,
                state,
                format_rtt(t.rtt_us),
                format_uptime(t.uptime_secs),
                format_bytes(t.bytes_sent),
                format_bytes(t.bytes_recv),
                t.reconnect_count
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

async fn cli_ping(admin: &str, tunnel: &str, count: u32) -> anyhow::Result<()> {
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

async fn cli_bench(admin: &str, tunnel: &str, duration: u64, size: usize) -> anyhow::Result<()> {
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

/// Resolve a default key path for the given scope, or error with guidance.
fn resolve_default_path(
    scope: paths::Scope,
    f: fn(paths::Scope) -> Option<PathBuf>,
    kind: &str,
) -> anyhow::Result<PathBuf> {
    f(scope).ok_or_else(|| {
        anyhow::anyhow!(
            "cannot determine default {kind} path for {scope} scope \
             (set HOME/APPDATA or pass --{kind} explicitly)"
        )
    })
}

/// `optical keygen` — generate an ML-DSA-65 key pair, defaulting to
/// platform-appropriate paths when none are given.
fn cli_keygen(
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
        None => resolve_default_path(scope, paths::default_private_key_path, "private-key")?,
    };
    let public_key = match public_key {
        Some(p) => p,
        None => resolve_default_path(scope, paths::default_public_key_path, "public-key")?,
    };

    crypto::pqdsa::keygen_to_files(&private_key, &public_key)?;
    paths::set_private_key_permissions(&private_key)?;

    println!("ML-DSA-65 key pair generated:");
    println!("  private key: {}", private_key.display());
    println!("  public key:  {}", public_key.display());
    if system {
        println!("  (system scope)");
    }
    println!();
    println!("To also generate a config file, run: optical init");

    Ok(())
}

/// `optical init` — generate keys + PSK + config file from the template.
fn cli_init(
    system: bool,
    user: bool,
    config_dir: Option<PathBuf>,
    force: bool,
) -> anyhow::Result<()> {
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
        paths::base_dir(scope).ok_or_else(|| {
            anyhow::anyhow!(
                "cannot determine default directory for {scope} scope \
                 (set HOME/APPDATA or use --config-dir)"
            )
        })?
    };

    let config_path = base.join("config.yml");
    let keys_dir = base.join("keys");
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
    crypto::pqdsa::keygen_to_files(&priv_key, &pub_key)?;
    paths::set_private_key_permissions(&priv_key)?;

    // Generate a PSK and render the config from the template.
    let psk = crypto::kdf::generate_psk();
    let psk_hex = format!("hex:{}", hex::encode(psk));
    let config_content = paths::render_config(&psk_hex, &priv_key, &pub_key);
    std::fs::write(&config_path, config_content)?;

    // Summary + reminder.
    println!("optical — initialization complete");
    println!();
    println!("Generated files:");
    println!("  config:      {}", config_path.display());
    println!("  private key: {}", priv_key.display());
    println!("  public key:  {}", pub_key.display());
    println!("  PSK:         generated (embedded in config as 'hex:...')");
    println!();
    println!("IMPORTANT — edit the config file before starting the service:");
    println!("  {}", config_path.display());
    println!();
    println!("  - Set the correct 'tunnel_listen' (Node2) and/or 'forwarders' (Node1)");
    println!("    for this node's role; remove whichever role it should NOT play.");
    println!("  - Share the same PSK and this node's public key with peer nodes.");
    println!("  - Distribute peer public keys if signature verification is enabled.");
    println!();
    println!("Then run:");
    println!("  optical run --config \"{}\"", config_path.display());

    Ok(())
}
