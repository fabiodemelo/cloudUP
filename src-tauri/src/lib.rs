//! CloudUp — mount cloud storage (S3, WebDAV and more) as a local drive.

pub mod backend;
mod boxprovider;
mod commands;
pub mod config;
pub mod error;
pub mod mega;
pub mod mount;
pub mod sftp;
mod dropbox;
mod ftp;
mod gdrive;
mod oauth;
mod onedrive;
mod pcloud;
mod s3;
mod swift;
mod webdav;

/// Entry point used by `main.rs` and the library consumers.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            // connections
            commands::list_connections,
            commands::save_connection,
            commands::delete_connection,
            commands::get_secret,
            commands::test_connection,
            commands::connect_oauth,
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
            commands::check_for_updates,
            commands::install_update,
        ])
        .build(tauri::generate_context!())
        .expect("error building app")
        .run(|_app, event| {
            // Unmount every active drive when the app exits, so no stale
            // FUSE mounts are left behind. (Dropping a BackgroundSession
            // performs the unmount.)
            if let tauri::RunEvent::Exit = event {
                mount::unmount_all();
            }
        });
}
