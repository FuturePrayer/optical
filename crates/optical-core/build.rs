//! Build script for optical-core.
//!
//! Builds the React web UI (`webui/dist/`) **only when the `center` feature is
//! enabled**, so that `webui.rs`'s `#[derive(RustEmbed)]` finds the assets at
//! compile time. The plain `optical` node binary (no `center` feature) skips
//! this entirely and has no Node.js requirement.
//!
//! This build script lives in `optical-core` (not `optical-center`) because
//! `webui.rs` and its `RustEmbed` derive are in `optical-core` — cargo compiles
//! dependencies before dependents, so `optical-core`'s build script runs
//! before `rust-embed` expands the macro.
//!
//! Set `OPTICAL_SKIP_WEBUI=1` to skip the frontend build (useful for fast
//! Rust-only rebuilds when `dist/` already exists).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Only build the frontend when the `center` feature is active. The node-
    // only build (`optical` binary) must not require Node.js.
    let center_enabled = env::var("CARGO_FEATURE_CENTER").is_ok();
    if !center_enabled {
        return;
    }

    if env::var("OPTICAL_SKIP_WEBUI").is_ok() {
        println!("cargo:warning=OPTICAL_SKIP_WEBUI set, skipping web UI build");
        return;
    }

    // Locate the webui directory (workspace root / webui).
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let webui_dir = manifest_dir.join("../../webui");
    let dist_dir = webui_dir.join("dist");

    // Locate npm. On Windows it's npm.cmd; on Unix it's npm.
    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };

    // Install deps if node_modules is missing.
    let node_modules = webui_dir.join("node_modules");
    if !node_modules.exists() {
        println!("cargo:warning=installing web UI dependencies (npm install)...");
        let status = Command::new(npm)
            .arg("install")
            .current_dir(&webui_dir)
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => panic!("npm install failed with status {s} — is Node.js installed?"),
            Err(e) => panic!("failed to run npm install: {e} — is Node.js on PATH?"),
        }
    }

    // Build the frontend.
    println!("cargo:warning=building web UI (npm run build)...");
    let status = Command::new(npm)
        .args(["run", "build"])
        .current_dir(&webui_dir)
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("cargo:warning=web UI built → {}", dist_dir.display());
        }
        Ok(s) => panic!("npm run build failed with status {s}"),
        Err(e) => panic!("failed to run npm run build: {e}"),
    }
}
