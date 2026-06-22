//! Admin HTTP-JSON API for tunnel observability.
//!
//! Exposes endpoints for querying real-time status, metrics history, and
//! running diagnostic ping/bench tests against active tunnels.
//!
//! The HTTP server is intentionally minimal (no external HTTP framework):
//! request parsing is hand-written for the small set of routes we support.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::metrics;
use crate::tunnel::client::TunnelClient;

// ── TunnelRegistry: shared map of tunnel clients for admin access ───────────

/// Registry of active tunnel clients, keyed by tunnel peer address.
/// Shared between the forward module (which populates it) and the admin
/// server (which reads it for ping/bench).
pub struct TunnelRegistry {
    clients: RwLock<HashMap<String, Arc<Mutex<TunnelClient>>>>,
}

impl TunnelRegistry {
    pub fn new() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert(&self, addr: String, client: Arc<Mutex<TunnelClient>>) {
        self.clients.write().unwrap().insert(addr, client);
    }

    pub fn get(&self, addr: &str) -> Option<Arc<Mutex<TunnelClient>>> {
        self.clients.read().unwrap().get(addr).cloned()
    }
}

// ── Request / Response types ────────────────────────────────────────────────

#[derive(Deserialize)]
struct PingRequest {
    tunnel: String,
    #[serde(default = "default_ping_count")]
    count: u32,
}

fn default_ping_count() -> u32 {
    10
}

#[derive(Serialize)]
struct PingResponse {
    rtts_us: Vec<u64>,
    avg_us: u64,
    min_us: u64,
    max_us: u64,
    loss: u32,
    count: u32,
}

#[derive(Deserialize)]
struct BenchRequest {
    tunnel: String,
    #[serde(default = "default_bench_duration")]
    duration_secs: u64,
    #[serde(default = "default_bench_size")]
    payload_size: usize,
}

fn default_bench_duration() -> u64 {
    10
}

fn default_bench_size() -> usize {
    65535
}

#[derive(Serialize)]
struct BenchResponse {
    throughput_mbps: f64,
    bytes_sent: u64,
    bytes_recv: u64,
    elapsed_secs: f64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ── HTTP server ─────────────────────────────────────────────────────────────

/// Run the admin HTTP server on `addr` until `cancel` is triggered.
pub async fn run(addr: SocketAddr, registry: Arc<TunnelRegistry>, cancel: CancellationToken) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            tracing::info!("admin API listening on http://{}", addr);
            l
        }
        Err(e) => {
            tracing::error!("failed to bind admin API on {}: {e}", addr);
            return;
        }
    };

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            accept = listener.accept() => {
                let (stream, _peer) = match accept {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("admin accept error: {e}");
                        continue;
                    }
                };
                let registry = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, registry).await {
                        tracing::debug!("admin connection error: {e}");
                    }
                });
            }
        }
    }

    tracing::info!("admin server stopped");
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    registry: Arc<TunnelRegistry>,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Read request line
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("");
    let path = parts.get(1).copied().unwrap_or("/");

    // Read headers
    let mut content_length: usize = 0;
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header).await?;
        if n == 0 || header.trim().is_empty() {
            break;
        }
        if let Some(val) = header.to_lowercase().strip_prefix("content-length:") {
            content_length = val.trim().parse().unwrap_or(0);
        }
    }

    // Read body
    let mut body = Vec::new();
    if content_length > 0 {
        body.resize(content_length, 0u8);
        reader.read_exact(&mut body).await?;
    }

    // Route
    let (status, json) = route(method, path, &body, &registry).await;

    // Send response
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        json.len(),
        json
    );
    write_half.write_all(response.as_bytes()).await?;
    write_half.flush().await?;

    Ok(())
}

async fn route(
    method: &str,
    path: &str,
    body: &[u8],
    registry: &TunnelRegistry,
) -> (u16, String) {
    // Strip query string
    let path_only = path.split('?').next().unwrap_or(path);

    match (method, path_only) {
        ("GET", "/status") => {
            let reg = match metrics::try_get() {
                Some(r) => r,
                None => return json_err(500, "metrics not initialized"),
            };
            let snap = reg.snapshot();
            json_ok(serde_json::to_string(&snap).unwrap_or_default())
        }

        ("GET", "/metrics") => {
            let reg = match metrics::try_get() {
                Some(r) => r,
                None => return json_err(500, "metrics not initialized"),
            };
            let history = reg.history.lock().unwrap();
            let samples: Vec<_> = history.samples().iter().collect();
            json_ok(serde_json::to_string(&samples).unwrap_or_default())
        }

        ("POST", "/ping") => {
            let req: PingRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => return json_err(400, &format!("invalid request body: {e}")),
            };
            handle_ping(req, registry).await
        }

        ("POST", "/bench") => {
            let req: BenchRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => return json_err(400, &format!("invalid request body: {e}")),
            };
            handle_bench(req, registry).await
        }

        _ => json_err(404, "not found"),
    }
}

async fn handle_ping(req: PingRequest, registry: &TunnelRegistry) -> (u16, String) {
    let tc = match registry.get(&req.tunnel) {
        Some(c) => c,
        None => return json_err(404, &format!("tunnel '{}' not found", req.tunnel)),
    };

    let tunnel = {
        let tc = tc.lock().await;
        tc.try_get_tunnel()
    };

    let tunnel = match tunnel {
        Some(t) if t.is_alive() => t,
        _ => return json_err(503, "tunnel not connected"),
    };

    let count = req.count.max(1).min(100);
    let mut rtts = Vec::with_capacity(count as usize);
    let mut loss = 0u32;

    for _ in 0..count {
        match tunnel.ping_once().await {
            Ok(rtt) => rtts.push(rtt.as_micros() as u64),
            Err(_) => loss += 1,
        }
        // Small pause between probes
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    let avg_us = if rtts.is_empty() {
        0
    } else {
        rtts.iter().sum::<u64>() / rtts.len() as u64
    };
    let min_us = rtts.iter().copied().min().unwrap_or(0);
    let max_us = rtts.iter().copied().max().unwrap_or(0);

    json_ok(serde_json::to_string(&PingResponse {
        rtts_us: rtts,
        avg_us,
        min_us,
        max_us,
        loss,
        count,
    })
    .unwrap_or_default())
}

async fn handle_bench(req: BenchRequest, registry: &TunnelRegistry) -> (u16, String) {
    let tc = match registry.get(&req.tunnel) {
        Some(c) => c,
        None => return json_err(404, &format!("tunnel '{}' not found", req.tunnel)),
    };

    let tunnel = {
        let tc = tc.lock().await;
        tc.try_get_tunnel()
    };

    let tunnel = match tunnel {
        Some(t) if t.is_alive() => t,
        _ => return json_err(503, "tunnel not connected"),
    };

    let duration = std::time::Duration::from_secs(req.duration_secs.max(1).min(120));
    let result = tunnel.bench(duration, req.payload_size).await;

    json_ok(
        serde_json::to_string(&BenchResponse {
            throughput_mbps: result.throughput_mbps,
            bytes_sent: result.bytes_sent,
            bytes_recv: result.bytes_recv,
            elapsed_secs: result.elapsed_secs,
        })
        .unwrap_or_default(),
    )
}

fn json_ok(body: String) -> (u16, String) {
    (200, body)
}

fn json_err(status: u16, msg: &str) -> (u16, String) {
    (
        status,
        serde_json::to_string(&ErrorResponse {
            error: msg.to_string(),
        })
        .unwrap_or_default(),
    )
}
