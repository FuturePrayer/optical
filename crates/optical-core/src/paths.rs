//! Platform-specific default paths for config files and keys, plus config
//! template rendering and private-key permission hardening.
//!
//! Two scopes are supported:
//! - **System-level** ([`Scope::System`]): machine-wide, used when running as
//!   a service. Requires admin/root to write.
//!   - Linux: `/etc/<app>/`
//!   - Windows: `%PROGRAMDATA%\<app>\`
//! - **User-level** ([`Scope::User`], default): per-user, used for foreground
//!   / dev runs.
//!   - Linux: `$XDG_CONFIG_HOME/<app>/` or `~/.config/<app>/`
//!   - Windows: `%APPDATA%\<app>\`
//!
//! `<app>` is `optical` for the node binary and `optical-center` for the
//! config-center binary (see [`AppKind`]).

use std::path::{Path, PathBuf};

/// Which application is asking for paths — the node binary or the config
/// center binary. Determines the subdirectory name (`optical` vs
/// `optical-center`) used in system/user paths and the service name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppKind {
    /// The `optical` node binary.
    Node,
    /// The `optical-center` config center binary.
    Center,
}

impl AppKind {
    /// The subdirectory name used under the system/user base dirs.
    pub fn subdir(self) -> &'static str {
        match self {
            AppKind::Node => "optical",
            AppKind::Center => "optical-center",
        }
    }

    /// The systemd / SCM service name.
    pub fn service_name(self) -> &'static str {
        self.subdir()
    }

    /// A short human-readable description for service metadata.
    pub fn service_description(self) -> &'static str {
        match self {
            AppKind::Node => "optical — post-quantum encrypted tunnel forwarding service",
            AppKind::Center => "optical-center — post-quantum config center service",
        }
    }
}

impl std::fmt::Display for AppKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.subdir())
    }
}

/// The deployment scope determining the default base directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Machine-wide directory (requires admin/root to write).
    System,
    /// Per-user directory (default).
    User,
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::System => write!(f, "system"),
            Scope::User => write!(f, "user"),
        }
    }
}

/// The embedded config template (from `config.example.yml` at build time).
/// Path is relative to this file (`crates/optical-core/src/`), pointing up to
/// the workspace root where `config.example.yml` lives.
pub const CONFIG_TEMPLATE: &str = include_str!("../../../config.example.yml");

/// The all-zero placeholder PSK embedded in the templates (includes `hex:` prefix).
const PSK_PLACEHOLDER: &str =
    "hex:0000000000000000000000000000000000000000000000000000000000000000";

/// Placeholder for the center management-domain PSK (center template only).
/// Distinct from `PSK_PLACEHOLDER` so both can coexist in the same file.
const CENTER_PSK_PLACEHOLDER: &str =
    "hex:1111111111111111111111111111111111111111111111111111111111111111";

/// Which config template `init` generates. Determines which fields the
/// rendered config contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitTemplate {
    /// 独立运行节点:本地配 forwarders/tunnel_listen,不连配置中心。
    /// This is the default and matches pre-template-selection behavior.
    Standalone,
    /// 被配置中心纳管的节点:含 `center:` 块,forwarders 由中心下发。
    ManagedNode,
    /// 配置中心服务端:含 `center_listen`/`center_admin_listen` 等。
    /// Only `optical-center init` may select this template.
    Center,
}

impl std::fmt::Display for InitTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitTemplate::Standalone => write!(f, "standalone"),
            InitTemplate::ManagedNode => write!(f, "managed-node"),
            InitTemplate::Center => write!(f, "center"),
        }
    }
}

// ── Directory resolution ─────────────────────────────────────────────────────

/// Compute the base directory for the given scope and app kind.
///
/// Returns `None` for [`Scope::User`] when the user home / app-data directory
/// cannot be determined.
pub fn base_dir(scope: Scope, app_kind: AppKind) -> Option<PathBuf> {
    match scope {
        Scope::System => Some(system_dir(app_kind)),
        Scope::User => user_dir(app_kind),
    }
}

/// System-level directory for config and keys.
pub fn system_dir(app_kind: AppKind) -> PathBuf {
    let subdir = app_kind.subdir();
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"));
        base.join(subdir)
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc").join(subdir)
    }
}

/// User-level directory for config and keys.
///
/// Returns `None` if the home directory cannot be determined.
pub fn user_dir(app_kind: AppKind) -> Option<PathBuf> {
    let subdir = app_kind.subdir();
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .map(|p| p.join(subdir))
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() && xdg != "/" {
                return Some(PathBuf::from(xdg).join(subdir));
            }
        }
        std::env::var("HOME")
            .ok()
            .filter(|h| !h.is_empty())
            .map(|h| PathBuf::from(h).join(".config").join(subdir))
    }
}

/// Default config file path (`config.yml`) for a scope.
#[allow(dead_code)]
pub fn default_config_path(scope: Scope, app_kind: AppKind) -> Option<PathBuf> {
    base_dir(scope, app_kind).map(|d| d.join("config.yml"))
}

/// Default private key path (`keys/node.key`) for a scope.
pub fn default_private_key_path(scope: Scope, app_kind: AppKind) -> Option<PathBuf> {
    base_dir(scope, app_kind).map(|d| d.join("keys").join("node.key"))
}

/// Default public key path (`keys/node.pub`) for a scope.
pub fn default_public_key_path(scope: Scope, app_kind: AppKind) -> Option<PathBuf> {
    base_dir(scope, app_kind).map(|d| d.join("keys").join("node.pub"))
}

// ── Config template rendering ────────────────────────────────────────────────

/// Normalize a path for embedding in a YAML double-quoted string.
///
/// Backslashes are converted to forward slashes so the path is safe inside
/// YAML double-quoted scalars (where `\` is an escape character). Both Rust's
/// `Path` and the OS accept forward slashes on Windows.
fn yaml_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Render a config file from the given template.
///
/// `psk_hex` is the tunnel trust-domain PSK (`"hex:<64 hex>"`).
/// `center_psk_hex` is the center management-domain PSK, required only for
/// [`InitTemplate::Center`] (pass `None` for the other templates).
/// `log_dir_path` is the directory for rolling log files.
///
/// A generation notice is prepended reminding the user to edit the file.
pub fn render_config(
    template: InitTemplate,
    psk_hex: &str,
    center_psk_hex: Option<&str>,
    private_key_path: &Path,
    public_key_path: &Path,
    log_dir_path: &Path,
) -> String {
    let priv_str = yaml_path(private_key_path);
    let pub_str = yaml_path(public_key_path);
    let log_str = yaml_path(log_dir_path);

    let header = "# ── Generated by `optical init` — EDIT BEFORE USE ────────────────────────\n\
                  # This file was auto-generated with a random PSK and a new ML-DSA-65 key\n\
                  # pair. Review and modify every setting below before starting the service.\n\
                  #\n";

    let raw = match template {
        InitTemplate::Standalone => STANDALONE_TEMPLATE,
        InitTemplate::ManagedNode => MANAGED_NODE_TEMPLATE,
        InitTemplate::Center => CENTER_TEMPLATE,
    };

    let mut body = raw
        .replace(PSK_PLACEHOLDER, psk_hex)
        .replace("\"./keys/node.key\"", &format!("\"{priv_str}\""))
        .replace("\"./keys/node.pub\"", &format!("\"{pub_str}\""))
        .replace("\"./logs\"", &format!("\"{log_str}\""));

    if let Some(center_psk) = center_psk_hex {
        body = body.replace(CENTER_PSK_PLACEHOLDER, center_psk);
    }

    format!("{header}{body}")
}

// ── Role-specific templates ────────────────────────────────────────────────
//
// Each template is a self-contained YAML config containing only the fields
// relevant to that role, with placeholder PSKs and key paths that
// `render_config` substitutes. The full reference (with every field
// documented) remains in `config.example.yml` (CONFIG_TEMPLATE).

/// Standalone node: local forwarders + optional tunnel_listen, no center.
const STANDALONE_TEMPLATE: &str = "\
# Pre-shared key for the tunnel trust domain (generate with `optical psk-gen`).
# Format: \"hex:\" followed by 64 hex chars (32 bytes). All nodes sharing this
# PSK form one trust domain — keep it secret.
psk: \"hex:0000000000000000000000000000000000000000000000000000000000000000\"

# ML-DSA-65 key pair paths (generated by `optical init`).
mldsa_private_key: \"./keys/node.key\"
mldsa_public_key: \"./keys/node.pub\"

# ── Node2 role: tunnel server (omit to disable) ────────────────────────────
tunnel_listen: \"0.0.0.0:9000\"
tunnel_transport: tcp
allow_reverse: true

# ── Node1 role: local forwarders (omit to disable) ─────────────────────────
# Each forwarder listens locally and tunnels traffic to a peer, which dials
# the target. The `tunnel` address URL scheme selects the transport.
forwarders:
  - listen: \"0.0.0.0:8080\"
    proto: tcp
    tunnel: \"tcp://peer.example.com:9000\"
    target: \"127.0.0.1:80\"
    reverse: false

# ── Admin API (local diagnostics) ──────────────────────────────────────────
admin_listen: \"127.0.0.1:9100\"

# ── Logging ────────────────────────────────────────────────────────────────
log_dir: \"./logs\"
log_max_size_mb: 50
log_retention_days: 30

# ── Tunnel runtime parameters ──────────────────────────────────────────────
tunnel:
  heartbeat_interval_secs: 15
  heartbeat_timeout_secs: 45
  reconnect_initial_secs: 1
  reconnect_max_secs: 30
  udp_idle_secs: 60
  dial_timeout_secs: 10
  open_ack_timeout_secs: 15
  socket_buffer_bytes: 4194304
";

/// Managed node: connects to a config center; forwarders are pushed by the
/// center. No local forwarders/tunnel_listen.
const MANAGED_NODE_TEMPLATE: &str = "\
# Pre-shared key for the tunnel trust domain. Must match the center's `psk`
# (the center also runs a tunnel server that this node's forwarders dial).
psk: \"hex:0000000000000000000000000000000000000000000000000000000000000000\"

# ML-DSA-65 key pair paths (generated by `optical init`).
mldsa_private_key: \"./keys/node.key\"
mldsa_public_key: \"./keys/node.pub\"

# ── Config center client ───────────────────────────────────────────────────
# When present, this node connects to the center, registers its identity
# (SHA-256 of the ML-DSA public key), and receives `forwarders` via encrypted
# ConfigPush frames — hot-applied without restarting. Local `forwarders` and
# `tunnel_listen` are ignored when `center` is set.
center:
  # REPLACE with your center's address (tcp/kcp/ws scheme supported).
  address: \"tcp://CENTER_ADDRESS:7000\"
  # Center management-domain PSK — must match the center's `center_psk`.
  psk: \"hex:0000000000000000000000000000000000000000000000000000000000000000\"
  status_report_interval_secs: 15

# ── Admin API (local diagnostics) ──────────────────────────────────────────
admin_listen: \"127.0.0.1:9100\"

# ── Logging ────────────────────────────────────────────────────────────────
log_dir: \"./logs\"
log_max_size_mb: 50
log_retention_days: 30

# ── Tunnel runtime parameters ──────────────────────────────────────────────
tunnel:
  heartbeat_interval_secs: 15
  heartbeat_timeout_secs: 45
  reconnect_initial_secs: 1
  reconnect_max_secs: 30
  udp_idle_secs: 60
  dial_timeout_secs: 10
  open_ack_timeout_secs: 15
  socket_buffer_bytes: 4194304
";

/// Config center server (optical-center only). Runs the center server +
/// optionally a tunnel server (dual-role).
const CENTER_TEMPLATE: &str = "\
# Pre-shared key for the tunnel trust domain. The center also acts as a tunnel
# server; nodes' forwarders dial this. Must match the nodes' `psk`.
psk: \"hex:0000000000000000000000000000000000000000000000000000000000000000\"

# ML-DSA-65 key pair paths (generated by `optical-center init`).
mldsa_private_key: \"./keys/node.key\"
mldsa_public_key: \"./keys/node.pub\"

# ── Node2 role: tunnel server (accept nodes' forwarder tunnels) ────────────
tunnel_listen: \"0.0.0.0:9000\"
tunnel_transport: tcp
allow_reverse: true

# ── Config center server role ──────────────────────────────────────────────
# Nodes connect here (PQ handshake) to register and receive config pushes.
center_listen: \"0.0.0.0:7000\"
# Center management-domain PSK — must match each node's `center.psk`.
# Distinct from the tunnel `psk` above.
center_psk: \"hex:1111111111111111111111111111111111111111111111111111111111111111\"
# Where nodes.json (whitelist + assigned configs) is stored.
center_data_dir: \".\"

# ── Web admin (browser UI + REST/SSE API) ──────────────────────────────────
# Open http://<this-host>:9100 in a browser and enter the token below.
center_admin_listen: \"0.0.0.0:9100\"
# REPLACE this token with your own secret (used for browser login).
center_admin_token: \"CHANGE_ME\"

# ── Node-role admin API (local diagnostics) ────────────────────────────────
admin_listen: \"127.0.0.1:9101\"

# ── Logging ────────────────────────────────────────────────────────────────
log_dir: \"./logs\"
log_max_size_mb: 50
log_retention_days: 30

# ── Tunnel runtime parameters ──────────────────────────────────────────────
tunnel:
  heartbeat_interval_secs: 15
  heartbeat_timeout_secs: 45
  reconnect_initial_secs: 1
  reconnect_max_secs: 30
  udp_idle_secs: 60
  dial_timeout_secs: 10
  open_ack_timeout_secs: 15
  socket_buffer_bytes: 4194304
";

// ── Private key permission hardening ─────────────────────────────────────────

/// Restrict permissions on the private key file.
///
/// - Unix: `chmod 0600` (owner read/write only).
/// - Windows: no-op (relies on directory ACL inheritance; explicit ACL
///   hardening is not yet implemented).
pub fn set_private_key_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
