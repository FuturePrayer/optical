//! Embedded web UI assets, served by the config-center admin server.
//!
//! The React SPA (in `webui/` at the workspace root) is built to
//! `webui/dist/` by `crates/optical-center/build.rs` and embedded into the
//! binary at compile time via `rust-embed`. At request time, [`serve`] returns
//! the matching asset (with a correct `Content-Type`) or falls back to
//! `index.html` for SPA client-side routes.
//!
//! Only compiled under the `center` feature (it pulls in `rust-embed`).

use rust_embed::RustEmbed;

/// The embedded web UI asset tree. `folder` is relative to this crate's
/// `Cargo.toml`, pointing to the workspace-root `webui/dist/` produced by the
/// build script.
///
/// When `webui/dist/` does not yet exist (e.g. during early development before
/// the frontend is built), `rust-embed` embeds an empty tree and [`serve`]
/// returns a friendly placeholder instead of failing to compile.
#[derive(RustEmbed)]
#[folder = "../../webui/dist/"]
struct WebuiAsset;

/// Serve a path from the embedded assets. Returns `(body, content_type)`.
///
/// - Exact asset match (e.g. `/assets/index-abc.js`) → that file.
/// - SPA fallback: any non-asset path (e.g. `/`, `/nodes/:id`) → `index.html`,
///   so the React Router can handle client-side routing.
/// - If no assets are embedded at all (frontend not built), returns a
///   placeholder HTML page telling the operator to build the frontend.
pub fn serve(path: &str) -> Option<(Vec<u8>, &'static str)> {
    let clean = path.trim_start_matches('/');

    // Try exact asset match first.
    if !clean.is_empty() {
        if let Some(file) = WebuiAsset::get(clean) {
            let ct = mime_for(clean);
            return Some((file.data.to_vec(), ct));
        }
    }

    // SPA fallback → index.html.
    if let Some(file) = WebuiAsset::get("index.html") {
        return Some((file.data.to_vec(), "text/html; charset=utf-8"));
    }

    // No frontend built yet — return a build-instruction placeholder.
    Some((
        PLACEHOLDER_HTML.as_bytes().to_vec(),
        "text/html; charset=utf-8",
    ))
}

/// Map a file extension to a MIME type. Falls back to octet-stream.
fn mime_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "map" => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

const PLACEHOLDER_HTML: &str = r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>optical-center</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:4rem auto;padding:0 1rem;color:#333}
code{background:#f4f4f4;padding:.1em .3em;border-radius:3px}</style></head>
<body>
<h1>optical-center</h1>
<p>The config-center backend is running, but the web UI has not been built yet.</p>
<p>To build the frontend, run from the workspace root:</p>
<pre><code>cd webui &amp;&amp; npm install &amp;&amp; npm run build</code></pre>
<p>Then rebuild <code>optical-center</code> so the assets are embedded.</p>
</body></html>"#;
