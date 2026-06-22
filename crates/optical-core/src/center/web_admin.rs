//! Config-center web admin: REST API (`/api/*`), SSE (`/api/events`), and the
//! embedded React web UI (static assets served from the binary).
//!
//! This is the HTTP surface that the browser SPA talks to. It reuses the
//! hand-written HTTP parsing style of [`crate::admin`] but adds:
//! - Bearer-token authentication (the `center.admin_token` config field).
//! - Long-lived SSE connections for real-time event push.
//! - Static-asset serving for the embedded web UI (`/`, `/assets/*`).
//!
//! Runs as its own HTTP listener (`center_admin_listen`), separate from the
//! node-role admin API, so the two never collide on one port.

use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::center::events::{CenterEvent, EventHub};
use crate::center::registry::NodeStatus;
use crate::center::server::push_config;
use crate::center::state::CenterState;
use crate::config::ForwarderConfig;

/// Run the center web admin server on `addr` until `cancel` is triggered.
pub async fn run(
    addr: SocketAddr,
    state: CenterState,
    admin_token: Option<Arc<String>>,
    cancel: CancellationToken,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            tracing::info!("center web admin listening on http://{}", addr);
            l
        }
        Err(e) => {
            tracing::error!("failed to bind center web admin on {}: {e}", addr);
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
                        tracing::warn!("center admin accept error: {e}");
                        continue;
                    }
                };
                let state = state.clone();
                let token = admin_token.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, state, token).await {
                        tracing::debug!("center admin connection error: {e}");
                    }
                });
            }
        }
    }
    tracing::info!("center web admin stopped");
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    state: CenterState,
    admin_token: Option<Arc<String>>,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Read request line.
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("");
    let path = parts.get(1).copied().unwrap_or("/");

    // Read headers (capture Authorization + token query).
    let mut content_length: usize = 0;
    let mut auth_header: Option<String> = None;
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header).await?;
        if n == 0 || header.trim().is_empty() {
            break;
        }
        let lower = header.to_lowercase();
        if let Some(val) = lower.strip_prefix("authorization:") {
            auth_header = Some(val.trim().to_string());
        }
        if let Some(val) = lower.strip_prefix("content-length:") {
            content_length = val.trim().parse().unwrap_or(0);
        }
    }

    // Read body.
    let mut body = Vec::new();
    if content_length > 0 {
        body.resize(content_length, 0u8);
        reader.read_exact(&mut body).await?;
    }

    // Extract query string + token param (for SSE, which can't set headers).
    let (path_only, query) = split_path_query(path);
    let token_param = query_get(query, "token");

    // Static web UI assets (HTML/JS/CSS) are served WITHOUT auth: the browser
    // loads them before it can attach a token, and the token is only needed
    // for the /api/* data calls (which the SPA adds at runtime). API routes
    // (including SSE) require the token.
    if path_only.starts_with("/api/") {
        // Auth: require Bearer token (header) or ?token= (query) if configured.
        if let Some(expected) = &admin_token {
            // Bearer prefix is case-insensitive (curl sends "Bearer", some
            // clients send "bearer"). auth_header was lowercased on read.
            let provided: Option<String> = auth_header
                .as_deref()
                .and_then(|h| h.strip_prefix("bearer "))
                .map(|s| s.to_string())
                .or_else(|| token_param.map(|s| s.to_string()));
            if provided.as_deref() != Some(expected.as_str()) {
                let resp = http_json(401, r#"{"error":"unauthorized"}"#);
                write_half.write_all(resp.as_bytes()).await?;
                return Ok(());
            }
        }
    }

    // SSE: long-lived connection for /api/events.
    if method == "GET" && path_only == "/api/events" {
        return serve_sse(write_half, &state.hub).await;
    }

    // Static web UI: serve embedded assets for any non-/api path.
    if !path_only.starts_with("/api/") {
        return serve_webui(&mut write_half, path_only).await;
    }

    // REST API routing.
    let (status, json) = route_api(method, path_only, &body, &state).await;
    let resp = http_json(status, &json);
    write_half.write_all(resp.as_bytes()).await?;
    Ok(())
}

/// Serve the embedded web UI. `path` is the request path (e.g. "/", "/nodes",
/// "/assets/index-abc123.js"). SPA routes fall back to index.html.
async fn serve_webui(
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
    path: &str,
) -> std::io::Result<()> {
    match crate::webui::serve(path) {
        Some((body, content_type)) => {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
                ct = content_type,
                len = body.len(),
            );
            write_half.write_all(header.as_bytes()).await?;
            write_half.write_all(&body).await?;
        }
        None => {
            let resp = http_json(404, r#"{"error":"not found"}"#);
            write_half.write_all(resp.as_bytes()).await?;
        }
    }
    Ok(())
}

/// Serve Server-Sent Events: subscribe to the hub and stream events as they
/// arrive. Keeps the connection open until the client disconnects.
async fn serve_sse(
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    hub: &EventHub,
) -> std::io::Result<()> {
    // SSE response headers.
    let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
    write_half.write_all(header.as_bytes()).await?;
    write_half.flush().await?;

    let mut rx = hub.subscribe().await;
    // Send an initial "hello" so the client knows the stream is alive.
    write_half.write_all(b": connected\n\n").await?;
    write_half.flush().await?;

    loop {
        match rx.recv().await {
            Ok(event) => {
                let json = serde_json::to_string(&event).unwrap_or_else(|_| "{}".into());
                let msg = format!("data: {json}\n\n");
                if write_half.write_all(msg.as_bytes()).await.is_err() {
                    break; // client disconnected
                }
                if write_half.flush().await.is_err() {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                // Subscriber was slow; skip missed events and continue.
                continue;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

// ── REST API routing ───────────────────────────────────────────────────────

async fn route_api(
    method: &str,
    path: &str,
    body: &[u8],
    state: &CenterState,
) -> (u16, String) {
    match (method, path) {
        // Overview / KPI counts.
        ("GET", "/api/overview") => {
            let counts = state.registry.counts();
            json_ok(serde_json::to_string(&counts).unwrap_or_default())
        }

        // Node list (all nodes) — uses list_api() so the transient `online`
        // field is included (NodeRecord skips it for persistence).
        ("GET", "/api/nodes") => {
            let nodes = state.registry.list_api();
            json_ok(serde_json::to_string(&nodes).unwrap_or_default())
        }

        // Single node detail.
        ("GET", p) if p.starts_with("/api/nodes/") => {
            let node_id = &p["/api/nodes/".len()..];
            match state.registry.get_api(node_id) {
                Some(view) => json_ok(serde_json::to_string(&view).unwrap_or_default()),
                None => json_err(404, "node not found"),
            }
        }

        // Pending nodes (awaiting approval).
        ("GET", "/api/pending") => {
            let pending: Vec<_> = state
                .registry
                .list_api()
                .into_iter()
                .filter(|n| n.status == NodeStatus::Pending)
                .collect();
            json_ok(serde_json::to_string(&pending).unwrap_or_default())
        }

        // Approve a node + assign config (body = forwarders JSON array).
        ("POST", p) if p.starts_with("/api/nodes/") && p.ends_with("/approve") => {
            let node_id = &p["/api/nodes/".len()..p.len() - "/approve".len()];
            let forwarders: Vec<ForwarderConfig> = match serde_json::from_slice(body) {
                Ok(f) => f,
                Err(e) => return json_err(400, &format!("invalid forwarders JSON: {e}")),
            };
            let delivered = push_config(&state.registry, &state.sessions, node_id, forwarders).await;
            let _ = state
                .hub
                .broadcast(CenterEvent::ConfigPushed {
                    node_id: node_id.to_string(),
                    config_version: state
                        .registry
                        .get(node_id)
                        .map(|r| r.config_version)
                        .unwrap_or(0),
                })
                .await;
            json_ok(format!(r#"{{"delivered":{delivered}}}"#))
        }

        // Reject (blacklist) a node.
        ("POST", p) if p.starts_with("/api/nodes/") && p.ends_with("/reject") => {
            let node_id = &p["/api/nodes/".len()..p.len() - "/reject".len()];
            state.registry.reject(node_id);
            json_ok(r#"{"ok":true}"#.to_string())
        }

        // Remove (revoke) a node entirely.
        ("DELETE", p) if p.starts_with("/api/nodes/") => {
            let node_id = &p["/api/nodes/".len()..];
            let existed = state.registry.remove(node_id);
            json_ok(format!(r#"{{"removed":{existed}}}"#))
        }

        // Whitelist management: list approved node_ids.
        ("GET", "/api/whitelist") => {
            let wl: Vec<_> = state
                .registry
                .list()
                .into_iter()
                .filter(|n| n.status == NodeStatus::Approved)
                .map(|n| n.node_id)
                .collect();
            json_ok(serde_json::to_string(&wl).unwrap_or_default())
        }

        // Push a config update to a node (same as approve but for already-approved nodes).
        ("POST", "/api/config/push") => {
            let req: ConfigPushRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => return json_err(400, &format!("invalid request: {e}")),
            };
            let delivered =
                push_config(&state.registry, &state.sessions, &req.node_id, req.forwarders).await;
            json_ok(format!(r#"{{"delivered":{delivered}}}"#))
        }

        _ => json_err(404, "not found"),
    }
}

#[derive(Deserialize)]
struct ConfigPushRequest {
    node_id: String,
    forwarders: Vec<ForwarderConfig>,
}

// ── HTTP helpers ───────────────────────────────────────────────────────────

fn split_path_query(path: &str) -> (&str, Option<&str>) {
    match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    }
}

fn query_get<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    let q = query?;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

fn http_json(status: u16, body: &str) -> String {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn json_ok(body: String) -> (u16, String) {
    (200, body)
}

fn json_err(status: u16, msg: &str) -> (u16, String) {
    #[derive(Serialize)]
    struct ErrResp {
        error: String,
    }
    (
        status,
        serde_json::to_string(&ErrResp {
            error: msg.to_string(),
        })
        .unwrap_or_default(),
    )
}
