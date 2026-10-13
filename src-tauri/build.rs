fn main() {
    tauri_build::build();
    #[cfg(feature = "fuse-mount")]
    ensure_bundle_fuse_lib();
}

/// Bundle a stub `libfuse` into the .app when `--features fuse-mount` is on
/// and no real libfuse was found on the system (macFUSE not installed at
/// build time). The stub exports `fuse_mount_compat25` and returns -1, so the
/// app runs fine for browsing/editing and only the mount action requires
/// macFUSE at runtime.
#[cfg(feature = "fuse-mount")]
fn ensure_bundle_fuse_lib() {
    // Check whether the tauri CLI is linking against a real libfuse:
    // if the *tauri build* binary we were spawned from has none, and the
    // system has no libfuse dylib either, then we must provide the stub.
    let real = ["libfuse.dylib", "libfuse.2.dylib", "libosxfuse.dylib"]
        .iter()
        .any(|n| {
            [
                "/opt/homebrew/lib",
                "/usr/local/lib",
                "/usr/lib",
                "/Library/Apple/System/Library/Frameworks",
            ]
            .iter()
            .any(|dir| std::path::Path::new(dir).join(n).exists())
        });
    if real {
        return; // real macFUSE/osxfuse present — tauri links it normally
    }
    let stub = std::env::var("FUSE_STUB_LIB").unwrap_or_else(|_| {
        format!(
            "{}/stub/libfuse.dylib",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )
    });
    let out = std::env::var("OUT_DIR").unwrap();
    let dir = format!("{out}/stub");
    std::fs::create_dir_all(&dir).ok();
    let dst = format!("{dir}/libfuse.dylib");
    if std::process::Command::new("cp").arg(&stub).arg(&dst).status().is_ok() {
        println!("cargo:rustc-link-search=native={dir}");
        // Rewrite the recorded install_name so the bundled copy relocates to a
        // relative @rpath id (the build script's OUT_DIR isn't portable).
        let mut cmd = std::process::Command::new("install_name_tool");
        cmd.args(["-id", "@rpath/libfuse.dylib", &dst]);
        cmd.env_remove("PKG_CONFIG");
        if cmd.status().is_ok() {
            // The rewritten id is recorded by the linker from the dylib itself.
        } else {
            eprintln!("warning: could not rewrite stub install_name");
        }
    }
    println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../Frameworks");
    println!("cargo:rustc-link-lib=fuse");
    println!("cargo:rerun-if-env-changed=FUSE_STUB_LIB");
    println!("cargo:rerun-if-changed={stub}");
}
