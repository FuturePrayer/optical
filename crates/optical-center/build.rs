//! Build script for optical-center.
//!
//! The web UI is built by `optical-core`'s build script (which runs first,
//! since optical-center depends on optical-core — cargo compiles dependencies
//! before dependents). This script is a no-op stub retained for future
//! center-specific build steps.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}

