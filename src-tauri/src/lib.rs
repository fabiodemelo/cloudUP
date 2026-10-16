//! CloudUp — mount cloud storage (S3, WebDAV and more) as a local drive.

pub mod backend;
mod boxprovider;
mod commands;
pub mod config;
pub mod error;
pub mod mega;
pub mod mount;
pub mod sftp;
#[cfg(target_os = "macos")]
mod about;
mod dropbox;
#[cfg(target_os = "macos")]
mod dragout;
mod ftp;
mod gdrive;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
mod oauth;
mod onedrive;
mod pcloud;
mod s3;
mod swift;
pub mod sync;
mod webdav;

/// Argument for a background start (window hidden). The Finder extension
/// passes it, and so did the 1.1.x login item (a LaunchAgent); the
/// SMAppService login item can't pass arguments, see
/// `macos::launched_as_login_item`.
pub(crate) const LOGIN_ARG: &str = "--login";

/// Entry point used by `main.rs` and the library consumers.
pub fn run() {
    use tauri::Manager;
    let builder = tauri::Builder::default()
        // Must be first: a second launch (login item, Dock, Finder) hands over
        // to the running copy, which owns the drive servers, and exits.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if args.iter().any(|a| a == LOGIN_ARG) {
                return;
            }
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init());
    // The Mac App Store build has no self-updater (App Review 2.4.5).
    #[cfg(all(feature = "updater", not(feature = "mas")))]
    let builder = builder.plugin(
        tauri_plugin_updater::Builder::new()
            .pubkey(include_str!("../cloudup.updater.key.pub"))
            .build(),
    );
    builder
        .invoke_handler(tauri::generate_handler![
            // connections
            commands::list_connections,
            commands::save_connection,
            commands::delete_connection,
            commands::get_secret,
            commands::get_field_secret,
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
            commands::upload_paths,
            commands::drag_out,
            commands::open_path,
            // mounting
            commands::mount_available,
            commands::mount_availability_note,
            commands::list_mounted,
            commands::mount_connection,
            commands::unmount_connection,
            commands::get_launch_at_login,
            commands::set_launch_at_login,
            commands::take_mount_errors,
            // account and sync
            sync::account_status,
            sync::account_register,
            sync::account_verify,
            sync::account_resend,
            sync::account_login,
            sync::account_logout,
            sync::account_sync,
            sync::account_devices,
            sync::account_revoke_device,
            sync::account_change_password,
            sync::account_recover,
            sync::account_reset,
            sync::account_reset_finish,
            sync::account_delete,
            // misc
            commands::functional_types,
            #[cfg(all(feature = "updater", not(feature = "mas")))]
            commands::check_for_updates,
            #[cfg(all(feature = "updater", not(feature = "mas")))]
            commands::install_update,
        ])
        .setup(|app| {
            #[cfg(target_os = "macos")]
            {
                // Standard app menu, with About showing our panel (credits link).
                use tauri::menu::{Menu, MenuItem, PredefinedMenuItem as P, Submenu};
                let h = app.handle();
                let about = MenuItem::with_id(h, "about", "About CloudUp", true, None::<&str>)?;
                let app_menu = Submenu::with_items(h, "CloudUp", true, &[
                    &about, &P::separator(h)?, &P::services(h, None)?, &P::separator(h)?,
                    &P::hide(h, None)?, &P::hide_others(h, None)?, &P::show_all(h, None)?,
                    &P::separator(h)?, &P::quit(h, None)?,
                ])?;
                let edit = Submenu::with_items(h, "Edit", true, &[
                    &P::undo(h, None)?, &P::redo(h, None)?, &P::separator(h)?,
                    &P::cut(h, None)?, &P::copy(h, None)?, &P::paste(h, None)?, &P::select_all(h, None)?,
                ])?;
                let window = Submenu::with_items(h, "Window", true, &[
                    &P::minimize(h, None)?, &P::maximize(h, None)?, &P::separator(h)?, &P::close_window(h, None)?,
                ])?;
                app.set_menu(Menu::with_items(h, &[&app_menu, &edit, &window])?)?;
                app.on_menu_event(|app, e| {
                    if e.id() == "about" {
                        let _ = app.run_on_main_thread(about::show);
                    }
                });
            }
            // Started by the login item or the Finder extension: stay in the
            // background.
            #[cfg(target_os = "macos")]
            let at_login = macos::launched_as_login_item();
            #[cfg(not(target_os = "macos"))]
            let at_login = false;
            if at_login || std::env::args().any(|a| a == LOGIN_ARG) {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            // The 1.1.x login item (a LaunchAgent plist) becomes an
            // SMAppService login item, once.
            #[cfg(target_os = "macos")]
            std::thread::spawn(macos::migrate_legacy_login_item);
            // Mount the drives marked "mount automatically".
            tauri::async_runtime::spawn(commands::mount_auto());
            // Sync connections with the CloudUp account, when signed in.
            sync::start(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Focused(true) = event {
                sync::kick(sync::Trigger::Focus);
            }
            // Mounted drives are served by this process: closing the window
            // hides it instead of quitting, so the drives keep working.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if !mount::list_mounted().is_empty() {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error building app")
        .run(|app, event| match event {
            // Dock icon clicked while the window is hidden: show it again
            // (but not when the login item re-opens a running CloudUp).
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { .. } if !macos::launched_as_login_item() => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            // Unmount every drive when the app quits so none are left stale.
            tauri::RunEvent::Exit => mount::unmount_all(),
            _ => {}
        });
}
