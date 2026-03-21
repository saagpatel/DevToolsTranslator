#![forbid(unsafe_code)]

#[cfg(feature = "desktop_shell")]
fn main() {
    use dtt_desktop_core::{
        create_pairing_context_from_storage, open_desktop_storage, start_ws_bridge,
        DesktopIngestService, DesktopUiFacade,
    };
    use std::sync::Mutex;
    use tauri_plugin_deep_link::DeepLinkExt;

    let storage_path = std::env::temp_dir().join("dtt-desktop.sqlite3");
    let storage = open_desktop_storage(&storage_path).expect("open desktop sqlite");
    let pairing_context =
        create_pairing_context_from_storage(&storage).expect("create pairing context");
    let ingest = DesktopIngestService::new(storage).expect("initialize ingest service");
    let mut facade = DesktopUiFacade::new(ingest);

    // The bridge uses its own storage handle pointed at the same sqlite file.
    let bridge_storage =
        open_desktop_storage(&storage_path).expect("open desktop sqlite bridge handle");
    let bridge_ingest =
        DesktopIngestService::new(bridge_storage).expect("initialize bridge ingest service");
    let bridge =
        start_ws_bridge(pairing_context.clone(), bridge_ingest).expect("start websocket bridge");
    facade.attach_bridge(pairing_context, bridge);

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            focus_main_window(app);
        }))
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            focus_main_window(app.handle());
            #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
            {
                let _ = app.deep_link().register("dtt");
            }
            Ok(())
        })
        .manage(Mutex::new(facade))
        .invoke_handler(dtt_desktop_core::tauri_commands::build_invoke_handler())
        .run(tauri::generate_context!())
        .expect("run tauri desktop shell");
}

#[cfg(feature = "desktop_shell")]
fn focus_main_window(app: &tauri::AppHandle) {
    use tauri::Manager;

    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(not(feature = "desktop_shell"))]
fn main() {}
