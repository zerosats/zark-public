//! Tauri shell for the Zark desktop wallet.
//!
//! The shell is deliberately thin: `runtime/main.mjs` coordinates wallet
//! actions and the Rust wallet CLI remains the protocol authority. The webview
//! renders display projections and sends user intents through `perform`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod backend;
mod runtime;

use backend::{Backend, Output};
use serde::Serialize;
use serde_json::{Map, Value};
use std::sync::{Arc, OnceLock};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_dialog::DialogExt;

/// Set once at startup; `None` when the runtime could not be started.
struct Shell {
    backend: OnceLock<Option<Arc<Backend>>>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletMessage {
    event: Option<backend::BackendEvent>,
    is_reply: bool,
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    preview: bool,
    preview_screen: Option<String>,
    platform: &'static str,
}

fn preview() -> bool {
    std::env::var("ZARK_PREVIEW").as_deref() == Ok("1")
}

fn window_title() -> String {
    if preview() {
        return "Zark · Preview".into();
    }
    // A packaged app opens its single default wallet without a profile name.
    let Ok(profile) = std::env::var("ZARK_PROFILE") else {
        return "Zark".into();
    };
    let mut letters = profile.chars();
    let capitalized = letters
        .next()
        .map(|first| first.to_uppercase().chain(letters).collect::<String>())
        .unwrap_or_default();
    format!("Zark · {capitalized}")
}

fn backend(app: &AppHandle) -> Option<Arc<Backend>> {
    app.state::<Shell>().backend.get().cloned().flatten()
}

/// Starts the runtime once the page is listening, so no event is missed.
#[tauri::command]
fn start(app: AppHandle) {
    let shell = app.state::<Shell>();
    shell.backend.get_or_init(|| {
        let emitter = app.clone();
        let sink = Box::new(move |output: Output| {
            let message = match output {
                Output::Event { event, is_reply } => WalletMessage {
                    event: Some(*event),
                    is_reply,
                    error: None,
                },
                Output::Error(error) => WalletMessage {
                    event: None,
                    is_reply: false,
                    error: Some(error),
                },
            };
            let _ = emitter.emit_to("main", "wallet", message);
        });
        match runtime::locate(app.path().resource_dir().ok()) {
            Ok(found) => Backend::start(&found.node, &[found.entry.as_path()], &found.env, sink),
            Err(message) => {
                sink(Output::Error(message.into()));
                None
            }
        }
    });
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        preview: preview(),
        // Visual QA only, and only with synthetic preview data.
        preview_screen: std::env::var("ZARK_PREVIEW_SCREEN")
            .ok()
            .filter(|_| preview()),
        platform: std::env::consts::OS,
    }
}

/// Sends one wallet action and resolves once the runtime replies or fails.
#[tauri::command]
async fn perform(app: AppHandle, action: String, args: Map<String, Value>) -> Result<(), ()> {
    let Some(backend) = backend(&app) else {
        return Ok(());
    };
    let wait = backend.request(&action, args);
    let _ = tauri::async_runtime::spawn_blocking(move || wait.recv()).await;
    Ok(())
}

#[tauri::command]
fn is_running(app: AppHandle) -> bool {
    backend(&app).is_some_and(|backend| backend.is_running())
}

/// Native file picker for a signed funding transaction.
#[tauri::command]
async fn pick_transaction(app: AppHandle) -> Option<String> {
    let file = app
        .dialog()
        .file()
        .set_title("Signed transaction")
        .blocking_pick_file()?;
    file.into_path()
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

/// QR code for a receive address, rendered natively as SVG markup.
#[tauri::command]
fn qr_svg(value: String) -> Result<String, ()> {
    let code = qrcode::QrCode::with_error_correction_level(value.as_bytes(), qrcode::EcLevel::M)
        .map_err(|_| ())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .quiet_zone(false)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

/// Hides the window and lets the runtime finish its saved step before exiting.
fn drain_and_exit(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    let app = app.clone();
    std::thread::spawn(move || {
        if let Some(backend) = backend(&app) {
            backend.shutdown();
        }
        app.exit(0);
    });
}

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Shell {
            backend: OnceLock::new(),
        })
        .invoke_handler(tauri::generate_handler![
            start,
            app_info,
            perform,
            is_running,
            pick_transaction,
            qr_svg
        ])
        .setup(|app| {
            let builder =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title(window_title())
                    .inner_size(760.0, 680.0)
                    .min_inner_size(600.0, 560.0)
                    .focused(true);
            #[cfg(target_os = "macos")]
            let builder = builder
                .title_bar_style(tauri::TitleBarStyle::Overlay)
                .hidden_title(true);
            builder.build()?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                drain_and_exit(window.app_handle());
            }
        })
        .build(tauri::generate_context!())
        .expect("Zark desktop failed to start");
    app.run(|app, event| {
        // Quit from the menu or keyboard drains like closing the window; the
        // programmatic exit after draining carries an explicit code.
        if let RunEvent::ExitRequested {
            code: None, api, ..
        } = event
        {
            api.prevent_exit();
            drain_and_exit(app);
        }
    });
}
