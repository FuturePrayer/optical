//! `optical` — post-quantum encrypted tunnel forwarding node.
//!
//! Thin CLI dispatcher over the `optical-core` library. This binary contains
//! node functionality (forwarding, tunnel server/client, dial, admin API) and
//! the node-side CenterClient (so it can connect to a config center when its
//! config includes a `center:` block). It contains **no** config-center
//! server code — that lives in the `optical-center` binary.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use optical_core::paths::AppKind;

/// Available config templates for the node binary's `init`. The `center`
/// template is deliberately NOT exposed here (it's optical-center only).
#[derive(Clone, Debug, ValueEnum)]
enum NodeTemplate {
    /// Standalone node: local forwarders/tunnel_listen, no center.
    Standalone,
    /// Managed node: connects to a config center; forwarders pushed remotely.
    ManagedNode,
}

impl NodeTemplate {
    fn to_core(self) -> optical_core::paths::InitTemplate {
        match self {
            NodeTemplate::Standalone => optical_core::paths::InitTemplate::Standalone,
            NodeTemplate::ManagedNode => optical_core::paths::InitTemplate::ManagedNode,
        }
    }
}

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
        /// Config template to generate.
        ///   standalone    — local forwarders/tunnel_listen, no center (default)
        ///   managed-node  — connects to a config center; forwarders pushed remotely
        #[arg(long, value_enum, default_value_t = NodeTemplate::Standalone)]
        template: NodeTemplate,
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
    /// Check for a newer version and update the optical binary in place
    Update {
        /// Only check whether an update is available; do not download.
        #[arg(long)]
        check: bool,
        /// Force update even when the latest version is not newer.
        #[arg(long)]
        force: bool,
        /// Restart the system service after a successful update.
        #[arg(long)]
        restart: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let app_kind = AppKind::Node;

    match cli.command {
        Commands::Run { config, service } => {
            if service {
                // Windows: enter SCM dispatch loop (blocks until service stops).
                optical_core::service::run_as_service(&config, app_kind)?;
            } else {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(optical_core::app::run(&config))?;
            }
        }
        Commands::Install { config } => {
            optical_core::service::install(&config, app_kind)?;
        }
        Commands::Uninstall => {
            optical_core::service::uninstall(app_kind)?;
        }
        Commands::Start => {
            optical_core::service::start(app_kind)?;
        }
        Commands::Stop => {
            optical_core::service::stop(app_kind)?;
        }
        Commands::Restart => {
            optical_core::service::restart(app_kind)?;
        }
        Commands::Keygen {
            system,
            private_key,
            public_key,
        } => {
            optical_core::cli::cli_keygen(app_kind, system, private_key, public_key)?;
        }
        Commands::Init {
            template,
            system,
            user,
            config_dir,
            force,
        } => {
            optical_core::cli::cli_init(
                app_kind,
                template.to_core(),
                system,
                user,
                config_dir,
                force,
            )?;
        }
        Commands::PskGen => {
            optical_core::cli::cli_psk_gen();
        }
        Commands::Status { admin } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(optical_core::cli::cli_status(&admin))?;
        }
        Commands::Ping {
            admin,
            tunnel,
            count,
        } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(optical_core::cli::cli_ping(&admin, &tunnel, count))?;
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
            rt.block_on(optical_core::cli::cli_bench(&admin, &tunnel, duration, size))?;
        }
        Commands::Update {
            check,
            force,
            restart,
        } => {
            optical_core::updater::run_update(check, force, restart)?;
        }
    }

    Ok(())
}
