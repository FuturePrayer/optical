//! Node registry: the center's in-memory + persistent store of known nodes,
//! their approval status, and the config assigned to each.
//!
//! Approval model (per the confirmed design): **whitelist auto-approve**.
//! A node whose `node_id` is in the whitelist is approved automatically on
//! connect and immediately receives its assigned config. Nodes not in the
//! whitelist land in a `Pending` state visible via the admin API for manual
//! review.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::center::proto::StatusReportMsg;
use crate::config::ForwarderConfig;

/// Approval state of a node.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    /// Awaiting manual approval (not in the whitelist).
    Pending,
    /// Approved (in the whitelist); may receive config.
    Approved,
    /// Manually rejected / blacklisted.
    Rejected,
}

/// A node's record in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: String,
    pub status: NodeStatus,
    /// Config version assigned to this node (0 = none yet).
    pub config_version: u64,
    /// The forwarders assigned to this node (None until approved+configured).
    #[serde(default)]
    pub forwarders: Vec<ForwarderConfig>,
    /// Node2 (tunnel server) config assigned by the center. Persists across
    /// restarts. None = no Node2 config assigned (node uses local config).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_config: Option<crate::center::proto::NodeServerConfig>,
    /// Last reported version string.
    #[serde(default)]
    pub last_version: Option<String>,
    /// Human-friendly name assigned by the admin (e.g. "edge-tokyo"). Persists
    /// across restarts. None = unnamed (UI falls back to node_id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether the node is currently connected.
    #[serde(skip)]
    pub online: bool,
    /// The TCP peer address of the center session (set on connect, transient).
    /// Shows the address the center sees (NAT-dependent).
    #[serde(skip)]
    pub remote_addr: Option<String>,
    /// Last seen status report (None until the first report arrives).
    #[serde(skip)]
    pub last_status: Option<StatusReportMsg>,
    /// Wall-clock instant of the last status report (for staleness checks).
    #[serde(skip)]
    pub last_seen: Option<Instant>,
}

/// The center's node registry. Shared across all sessions + the admin API.
pub struct NodeRegistry {
    inner: Mutex<HashMap<String, NodeRecord>>,
    persist_path: Option<PathBuf>,
}

impl NodeRegistry {
    /// Create an in-memory registry. If `persist_path` is given, load from it
    /// on construction and save on every mutation.
    pub fn new(persist_path: Option<PathBuf>) -> Self {
        let mut reg = Self {
            inner: Mutex::new(HashMap::new()),
            persist_path,
        };
        reg.load();
        reg
    }

    /// Load the registry from disk (best-effort).
    fn load(&mut self) {
        let Some(path) = &self.persist_path else { return };
        let Ok(data) = std::fs::read(path) else {
            return; // file doesn't exist yet — fine
        };
        // Only the persistent subset (whitelist + approved configs) is stored;
        // transient fields (online/last_status) are skipped via #[serde(skip)].
        let entries: Vec<NodeRecord> = match serde_json::from_slice(&data) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("failed to parse node registry {}: {e}", path.display());
                return;
            }
        };
        let mut map = self.inner.lock().unwrap();
        for rec in entries {
            map.insert(rec.node_id.clone(), rec);
        }
        tracing::info!("loaded {} node(s) from {}", map.len(), path.display());
    }

    /// Persist the whitelist + approved configs to disk (best-effort).
    fn save(&self) {
        let Some(path) = &self.persist_path else { return };
        let map = self.inner.lock().unwrap();
        let entries: Vec<&NodeRecord> = map.values().filter(|r| r.status != NodeStatus::Pending).collect();
        match serde_json::to_vec_pretty(&entries) {
            Ok(data) => {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(path, data) {
                    tracing::warn!("failed to write node registry {}: {e}", path.display());
                }
            }
            Err(e) => tracing::warn!("failed to serialize node registry: {e}"),
        }
    }

    /// Register or update a node on connect. Returns the (possibly updated)
    /// record and whether the node is approved (auto-approved if in the
    /// whitelist). `peer_addr` is the TCP peer address seen by the center
    /// (NAT-dependent); stored for display in the node list.
    pub fn on_connect(
        &self,
        node_id: &str,
        version: &str,
        peer_addr: std::net::SocketAddr,
    ) -> (NodeRecord, bool) {
        let mut map = self.inner.lock().unwrap();
        let approved;
        let rec = map.entry(node_id.to_string()).or_insert_with(|| {
            // Unknown node → Pending (waits for manual whitelist add).
            NodeRecord {
                node_id: node_id.to_string(),
                status: NodeStatus::Pending,
                config_version: 0,
                forwarders: vec![],
                server_config: None,
                last_version: None,
                name: None,
                online: true,
                remote_addr: None,
                last_status: None,
                last_seen: None,
            }
        });
        // Existing record: if it was Approved (whitelisted) keep it approved.
        approved = rec.status == NodeStatus::Approved;
        rec.online = true;
        rec.last_version = Some(version.to_string());
        rec.remote_addr = Some(peer_addr.to_string());
        let snapshot = rec.clone();
        drop(map);
        (snapshot, approved)
    }

    /// Mark a node offline (connection dropped).
    pub fn on_disconnect(&self, node_id: &str) {
        let mut map = self.inner.lock().unwrap();
        if let Some(rec) = map.get_mut(node_id) {
            rec.online = false;
        }
    }

    /// Record a status report from a node.
    pub fn on_status(&self, node_id: &str, report: StatusReportMsg) {
        let mut map = self.inner.lock().unwrap();
        if let Some(rec) = map.get_mut(node_id) {
            rec.last_status = Some(report);
            rec.last_seen = Some(Instant::now());
        }
    }

    /// Add a node to the whitelist (approve it). Optionally assign a config.
    /// Add a node to the whitelist (approve it). Optionally assign forwarders
    /// and Node2 (tunnel server) configuration.
    pub fn approve(
        &self,
        node_id: &str,
        forwarders: Vec<ForwarderConfig>,
        server_config: Option<crate::center::proto::NodeServerConfig>,
    ) -> bool {
        let mut map = self.inner.lock().unwrap();
        if let Some(rec) = map.get_mut(node_id) {
            rec.status = NodeStatus::Approved;
            rec.forwarders = forwarders.clone();
            rec.server_config = server_config.clone();
            rec.config_version = rec.config_version.wrapping_add(1).max(1);
            drop(map);
            self.save();
            true
        } else {
            // Node never connected — create an approved record anyway so it's
            // whitelisted when it does connect.
            map.insert(
                node_id.to_string(),
                NodeRecord {
                    node_id: node_id.to_string(),
                    status: NodeStatus::Approved,
                    config_version: 1,
                    forwarders,
                    server_config,
                    last_version: None,
                    name: None,
                    online: false,
                    remote_addr: None,
                    last_status: None,
                    last_seen: None,
                },
            );
            drop(map);
            self.save();
            true
        }
    }

    /// Reject (blacklist) a node.
    pub fn reject(&self, node_id: &str) {
        let mut map = self.inner.lock().unwrap();
        if let Some(rec) = map.get_mut(node_id) {
            rec.status = NodeStatus::Rejected;
        }
        drop(map);
        self.save();
    }

    /// Rename a node (set or clear its display name). Pass `None` to clear.
    /// Returns false if the node is not in the registry.
    pub fn rename(&self, node_id: &str, name: Option<String>) -> bool {
        let mut map = self.inner.lock().unwrap();
        if let Some(rec) = map.get_mut(node_id) {
            rec.name = name;
            drop(map);
            self.save();
            true
        } else {
            false
        }
    }

    /// Remove a node entirely (revoke).
    pub fn remove(&self, node_id: &str) -> bool {
        let mut map = self.inner.lock().unwrap();
        let existed = map.remove(node_id).is_some();
        drop(map);
        if existed {
            self.save();
        }
        existed
    }

    /// Get a snapshot of a node's record.
    pub fn get(&self, node_id: &str) -> Option<NodeRecord> {
        self.inner.lock().unwrap().get(node_id).cloned()
    }

    /// List all node records.
    pub fn list(&self) -> Vec<NodeRecord> {
        self.inner.lock().unwrap().values().cloned().collect()
    }

    /// List all nodes as API views (including the transient `online` field,
    /// which `#[serde(skip)]` omits from the persisted NodeRecord JSON). Used
    /// by the REST API so the frontend can distinguish online/offline nodes.
    pub fn list_api(&self) -> Vec<NodeApiView> {
        self.inner.lock().unwrap().values().map(NodeApiView::from).collect()
    }

    /// Get a single node as an API view (including `online`).
    pub fn get_api(&self, node_id: &str) -> Option<NodeApiView> {
        self.inner.lock().unwrap().get(node_id).map(NodeApiView::from)
    }

    /// Count nodes by status.
    pub fn counts(&self) -> NodeCounts {
        let map = self.inner.lock().unwrap();
        let mut c = NodeCounts::default();
        for r in map.values() {
            c.total += 1;
            if r.online {
                c.online += 1;
            } else {
                c.offline += 1;
            }
            match r.status {
                NodeStatus::Pending => c.pending += 1,
                NodeStatus::Approved => c.approved += 1,
                NodeStatus::Rejected => c.rejected += 1,
            }
        }
        c
    }
}

/// Aggregate node counts for the overview dashboard.
#[derive(Debug, Default, Serialize)]
pub struct NodeCounts {
    pub total: usize,
    pub online: usize,
    pub offline: usize,
    pub pending: usize,
    pub approved: usize,
    pub rejected: usize,
}

/// API view of a node record: same as [`NodeRecord`] but **always serializes
/// the transient fields** (`online`, `last_status`) that `#[serde(skip)]`
/// omits from the persisted JSON. The REST API (`/api/nodes`,
/// `/api/nodes/:id`) returns this so the frontend can tell online from
/// offline nodes.
#[derive(Debug, Clone, Serialize)]
pub struct NodeApiView {
    pub node_id: String,
    pub status: NodeStatus,
    pub config_version: u64,
    pub forwarders: Vec<crate::config::ForwarderConfig>,
    /// Node2 (tunnel server) config assigned by the center.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_config: Option<crate::center::proto::NodeServerConfig>,
    pub last_version: Option<String>,
    /// Human-friendly name (None = unnamed; UI shows node_id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether the node is currently connected (transient — accurate at the
    /// moment of the API call).
    pub online: bool,
    /// TCP peer address seen by the center (NAT-dependent; transient).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    /// Last received status report (None until the first StatusReport frame).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_status: Option<crate::center::proto::StatusReportMsg>,
}

impl From<&NodeRecord> for NodeApiView {
    fn from(r: &NodeRecord) -> Self {
        Self {
            node_id: r.node_id.clone(),
            status: r.status,
            config_version: r.config_version,
            forwarders: r.forwarders.clone(),
            server_config: r.server_config.clone(),
            last_version: r.last_version.clone(),
            name: r.name.clone(),
            online: r.online,
            remote_addr: r.remote_addr.clone(),
            last_status: r.last_status.clone(),
        }
    }
}
