//! `optical-center` — optical config center with embedded web UI.
//!
//! This binary combines:
//! - **Node functionality** (same as `optical`: forwarding, tunnel
//!   server/client, dial, admin API) — it can act as a regular node.
//! - **Config center functionality** (server, REST/SSE admin API, embedded
//!   web UI) — gated behind the `center` feature of `optical-core`.
//!
//! Phase A (this file): shares the node CLI surface so the binary builds and
//! runs identically to `optical` for node commands. The center server,
//! management API, and web UI are added in Phase B/C.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use optical_core::paths::AppKind;

/// Available config templates for `optical-center init`. Includes `center`,
/// which the node binary does not expose.
#[derive(Clone, Debug, ValueEnum)]
enum CenterTemplate {
    /// Standalone node: local forwarders/tunnel_listen, no center.
    Standalone,
    /// Managed node: connects to a config center; forwarders pushed remotely.
    ManagedNode,
    /// Config center server: center_listen + web admin + embedded UI.
    Center,
}

impl CenterTemplate {
    fn to_core(self) -> optical_core::paths::InitTemplate {
        match self {
            CenterTemplate::Standalone => optical_core::paths::InitTemplate::Standalone,
            CenterTemplate::ManagedNode => optical_core::paths::InitTemplate::ManagedNode,
            CenterTemplate::Center => optical_core::paths::InitTemplate::Center,
        }
    }
}

/// optical-center — post-quantum config center with embedded web UI
#[derive(Parser)]
#[command(name = "optical-center", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the config center (also acts as a tunnel node if forwarders /
    /// tunnel_listen are configured)
    Run {
        /// Path to YAML config file
        #[arg(short, long)]
        config: String,
        /// Internal: run as a Windows service via SCM dispatch.
        #[arg(long, hide = true)]
        service: bool,
    },
    /// Register optical-center as a system service
    Install {
        #[arg(short, long)]
        config: String,
    },
    /// Remove the optical-center system service
    Uninstall,
    /// Start the optical-center system service
    Start,
    /// Stop the optical-center system service
    Stop,
    /// Restart the optical-center system service
    Restart,
    /// Generate a new ML-DSA-65 key pair
    Keygen {
        #[arg(long)]
        system: bool,
        #[arg(long)]
        private_key: Option<PathBuf>,
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
    /// Initialize: generate keys, PSK, and a config file from the template
    Init {
        /// Config template to generate.
        ///   standalone    — local forwarders/tunnel_listen, no center (default)
        ///   managed-node  — connects to a config center; forwarders pushed remotely
        ///   center        — config center server + web admin (optical-center only)
        #[arg(long, value_enum, default_value_t = CenterTemplate::Standalone)]
        template: CenterTemplate,
        /// Use system-level paths (requires admin/root).
        ///   Linux: /etc/optical-center/    Windows: %PROGRAMDATA%\optical-center\
        #[arg(long)]
        system: bool,
        /// Use user-level paths (default).
        ///   Linux: ~/.config/optical-center/    Windows: %APPDATA%\optical-center\
        #[arg(long)]
        user: bool,
        #[arg(long)]
        config_dir: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Generate a random 32-byte PSK (hex-encoded)
    PskGen,
    /// Show real-time tunnel and forwarder status (node role)
    Status {
        #[arg(long, default_value = "127.0.0.1:9100")]
        admin: String,
    },
    /// Measure tunnel latency (RTT) via PING/PONG (node role)
    Ping {
        #[arg(long, default_value = "127.0.0.1:9100")]
        admin: String,
        #[arg(long)]
        tunnel: String,
        #[arg(short, long, default_value = "10")]
        count: u32,
    },
    /// Measure tunnel throughput via ECHO/ECHO_REPLY (node role)
    Bench {
        #[arg(long, default_value = "127.0.0.1:9100")]
        admin: String,
        #[arg(long)]
        tunnel: String,
        #[arg(short, long, default_value = "10")]
        duration: u64,
        #[arg(short, long, default_value = "65535")]
        size: usize,
    },
    /// Check for a newer version and update the optical-center binary in place
    Update {
        #[arg(long)]
        check: bool,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        restart: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let app_kind = AppKind::Center;

    match cli.command {
        Commands::Run { config, service } => {
            if service {
                optical_core::service::run_as_service(&config, app_kind)?;
            } else {
                // Phase A: run as a plain node. Phase B adds the center server.
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
