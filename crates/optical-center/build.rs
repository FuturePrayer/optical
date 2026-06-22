//! Build script for optical-center.
//!
//! Builds the React web UI (`webui/dist/`) so that `optical-core`'s `webui`
//! module (under the `center` feature) can embed it via `rust-embed`.
//!
//! - When `OPTICAL_SKIP_WEBUI` is set, the build is skipped (the previously-
//!   built `dist/` is used, or rust-embed embeds an empty tree). Useful for
//!   fast Rust-only rebuilds during development.
//! - Otherwise, runs `npm ci` (or `npm install` if no lockfile) +
//!   `npm run build` in `../../webui`.
//!
//! Requires Node.js + npm on the PATH at build time.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Re-run if the build script itself changes.
    println!("cargo:rerun-if-changed=build.rs");

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
            Ok(s) => {
                panic!("npm install failed with status {s} — is Node.js installed?");
            }
            Err(e) => {
                panic!("failed to run npm install: {e} — is Node.js on PATH?");
            }
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
        Ok(s) => {
            panic!("npm run build failed with status {s}");
        }
        Err(e) => {
            panic!("failed to run npm run build: {e}");
        }
    }
}
