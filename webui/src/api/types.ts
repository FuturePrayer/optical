// API response types, mirroring the Rust serde structs in center/registry.rs
// and center/events.rs.

export interface NodeCounts {
  total: number;
  online: number;
  offline: number;
  pending: number;
  approved: number;
  rejected: number;
}

export type NodeStatus = 'pending' | 'approved' | 'rejected';

export interface ForwarderConfig {
  listen: string;
  proto: 'tcp' | 'udp';
  tunnel: string;
  target: string;
  reverse: boolean;
}

/// Node2 (tunnel server) configuration pushed by the center.
export interface NodeServerConfig {
  tunnel_listen: string | null;
  tunnel_transport: 'tcp' | 'kcp' | 'ws';
  allow_reverse: boolean;
}

export interface Snapshot {
  uptime_secs: number;
  tunnels: TunnelSnapshot[];
  forwarders: ForwarderSnapshot[];
}

export interface TunnelSnapshot {
  addr: string;
  role: string;
  state: string;
  rtt_us: number;
  bytes_sent: number;
  bytes_recv: number;
  reconnect_count: number;
  frames_dropped: number;
  uptime_secs: number;
}

export interface ForwarderSnapshot {
  listen: string;
  proto: string;
  target: string;
  active_streams: number;
  total_streams: number;
  bytes_sent: number;
  bytes_recv: number;
}

export interface StatusReportMsg {
  config_version_applied: number;
  uptime_secs: number;
  snapshot: Snapshot;
}

export interface NodeRecord {
  node_id: string;
  status: NodeStatus;
  config_version: number;
  forwarders: ForwarderConfig[];
  // Node2 (tunnel server) config assigned by the center.
  server_config?: NodeServerConfig;
  last_version: string | null;
  // Human-friendly name (None = unnamed; UI falls back to node_id).
  name?: string;
  // Transient fields (skipped in serde on the Rust side, so may be absent):
  online?: boolean;
  // TCP peer address seen by the center (NAT-dependent).
  remote_addr?: string;
  last_status?: StatusReportMsg | null;
}

// SSE event types (tagged union via "type" field).
export type CenterEvent =
  | { type: 'NodeOnline'; node_id: string }
  | { type: 'NodeOffline'; node_id: string }
  | { type: 'NodeStatus'; node_id: string }
  | { type: 'NodeRegistered'; node_id: string; version: string }
  | { type: 'ConfigPushed'; node_id: string; config_version: number }
  | { type: 'PendingRequest'; node_id: string };
