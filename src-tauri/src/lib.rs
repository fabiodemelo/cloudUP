//! CloudMounter — mount cloud storage (S3, WebDAV and more) as a local drive.

pub mod backend;
mod commands;
pub mod config;
pub mod error;
pub mod mount;
mod s3;
mod webdav;

/// Entry point used by `main.rs` and the library consumers.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            // connections
            commands::list_connections,
            commands::save_connection,
            commands::delete_connection,
            commands::get_secret,
            commands::test_connection,
            commands::list_buckets,
            // file browser
            commands::browse,
            commands::read_file,
            commands::read_text,
            commands::write_text,
            commands::mkdir_entry,
            commands::remove_entry,
            commands::download,
            commands::upload,
            commands::open_path,
            // mounting
            commands::mount_available,
            commands::mount_availability_note,
            commands::list_mounted,
            commands::mount_connection,
            commands::unmount_connection,
            // misc
            commands::functional_types,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
