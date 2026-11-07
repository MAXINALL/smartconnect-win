#![windows_subsystem = "windows"]

mod clipboard;
mod discovery;
mod fex_stream;
mod gui;
mod identity;
mod invite;
mod nfs;
mod pairing;
mod proto;
mod server;
mod settings;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use anyhow::Result;
use clap::Parser;
use tracing::info;

use crate::clipboard::ClipboardManager;
use crate::identity::Identity;
use crate::pairing::PairingStore;
use crate::server::{run_daemon, DaemonState, SharedState};
use crate::settings::SettingsStore;

#[derive(Parser, Debug)]
#[command(name = "smartconnect", about = "Lenovo Smart Connect (Ready For) Windows Client")]
struct Args {
    /// Send a file directly to the connected tablet
    #[arg(short, long)]
    send: Option<PathBuf>,

    /// Run daemon in background headless mode (no GUI window)
    #[arg(long)]
    daemon: bool,

    /// Open desktop GUI window (default)
    #[arg(long)]
    gui: bool,

    /// Custom TLS WebSocket port (default: 52020)
    #[arg(long, default_value_t = 52020)]
    ws_port: u16,

    /// Custom Management API port (default: 52021)
    #[arg(long, default_value_t = 52021)]
    api_port: u16,

    /// Positional file paths passed via Share Sheet, OpenWith, or SendTo
    #[arg(value_name = "FILES")]
    files: Vec<PathBuf>,
}

impl Args {
    fn from_iter_safe() -> Self {
        let filtered: Vec<String> = std::env::args()
            .filter(|a| !a.starts_with("-ServerName:"))
            .collect();
        Self::try_parse_from(filtered).unwrap_or_else(|_| Self {
            send: None,
            daemon: false,
            gui: false,
            ws_port: 52020,
            api_port: 52021,
            files: Vec::new(),
        })
    }
}

fn try_collect_share_target_files() -> Option<Vec<PathBuf>> {
    use windows::core::Interface;
    use windows::ApplicationModel::Activation::{ActivationKind, ShareTargetActivatedEventArgs};
    use windows::ApplicationModel::AppInstance;
    use windows::ApplicationModel::DataTransfer::StandardDataFormats;
    use windows::Storage::IStorageItem;

    let act_args = AppInstance::GetActivatedEventArgs().ok()?;
    if act_args.Kind().ok()? != ActivationKind::ShareTarget {
        return None;
    }
    let share_args: ShareTargetActivatedEventArgs = act_args.cast().ok()?;
    let share_op = share_args.ShareOperation().ok()?;
    let _ = share_op.ReportStarted();

    let mut out = Vec::new();
    if let Ok(data) = share_op.Data() {
        if let Ok(fmt_items) = StandardDataFormats::StorageItems() {
            if data.Contains(&fmt_items).unwrap_or(false) {
                if let Ok(op) = data.GetStorageItemsAsync() {
                    if let Ok(items) = op.get() {
                        let count = items.Size().unwrap_or(0);
                        for i in 0..count {
                            if let Ok(item) = items.GetAt(i) {
                                let si: IStorageItem = item;
                                if let Ok(p) = si.Path() {
                                    let s = p.to_string_lossy();
                                    if !s.is_empty() {
                                        out.push(PathBuf::from(s));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = share_op.ReportCompleted();
    Some(out)
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("[PANIC] {info}\n");
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(r"D:\Temp\Web\temp\sc-target\release\daemon.log")
        {
            let _ = f.write_all(msg.as_bytes());
        }
    }));
    if let Ok(f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"D:\Temp\Web\temp\sc-target\release\daemon.log")
    {
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(f))
            .try_init();
    }
    if let Err(e) = run_app() {
        tracing::error!("run_app error: {e:#}");
    }
}

fn run_app() -> Result<()> {
    // Check if activated via Windows 11 Share Sheet (windows.shareTarget)
    if let Some(shared_files) = try_collect_share_target_files() {
        if !shared_files.is_empty() {
            return handle_send_files(shared_files, 52021);
        }
        return Ok(());
    }

    let args = Args::from_iter_safe();

    // If --send or positional file paths are passed, send files to active daemon
    let mut send_list = Vec::new();
    if let Some(p) = args.send {
        send_list.push(p);
    }
    for p in args.files {
        send_list.push(p);
    }
    if !send_list.is_empty() {
        return handle_send_files(send_list, args.api_port);
    }

    let root_dir = get_app_dir()?;

    // Single-instance check: try HTTP POST /api/show-window; if our daemon replies, wake its window and exit cleanly
    if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], args.api_port)),
        std::time::Duration::from_millis(200),
    ) {
        use std::io::{Read, Write};
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
        let req = format!(
            "POST /api/show-window HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            args.api_port
        );
        if stream.write_all(req.as_bytes()).is_ok() {
            let mut buf = [0u8; 256];
            if let Ok(n) = stream.read(&mut buf) {
                let s = String::from_utf8_lossy(&buf[..n]);
                if s.contains("200 OK") && s.contains("\"ok\"") {
                    return Ok(());
                }
            }
        }
    }

    let identity = Arc::new(Identity::load_or_create(&root_dir, None)?);
    let pairing = Arc::new(Mutex::new(PairingStore::load(&root_dir)?));
    let settings = Arc::new(Mutex::new(SettingsStore::load(&root_dir)?));
    let clipboard = Arc::new(ClipboardManager::new());
    let fex_registry = Arc::new(crate::fex_stream::StreamRegistry::default());
    let nfs_target = Arc::new(Mutex::new(None));

    let (shutdown_tx, _) = tokio::sync::broadcast::channel(4);

    let state: SharedState = Arc::new(DaemonState {
        root_dir: root_dir.clone(),
        identity,
        pairing,
        settings,
        clipboard,
        fex_registry,
        nfs_target,
        connected: Arc::new(AtomicBool::new(false)),
        reconnecting: Arc::new(AtomicBool::new(false)),
        reconnect_nudge: Arc::new(tokio::sync::Notify::new()),
        connect_lock: Arc::new(tokio::sync::Mutex::new(())),
        tablet_mdns_addr: Arc::new(Mutex::new(None)),
        current_invite: Arc::new(Mutex::new(None)),
        pending_files: Arc::new(Mutex::new(Vec::new())),
        show_window_requested: Arc::new(AtomicBool::new(false)),
        connected_device_name: Arc::new(Mutex::new(String::new())),
        connected_device_id: Arc::new(Mutex::new(String::new())),
        connected_ip: Arc::new(Mutex::new(String::new())),
        ws_sender: Arc::new(tokio::sync::Mutex::new(None)),
        transfers: Arc::new(Mutex::new(Vec::new())),
        clipboard_history: Arc::new(Mutex::new(Vec::new())),
        shutdown_tx: shutdown_tx.clone(),
    });

    // Start background tokio runtime
    let ws_port = args.ws_port;
    let api_port = args.api_port;

    if args.daemon {
        info!("Running in headless daemon mode. Press Ctrl+C to exit.");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime");

        let shutdown_tx_clone = shutdown_tx.clone();
        rt.spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            shutdown_tx_clone.send(()).ok();
        });

        rt.block_on(async move {
            if let Err(e) = run_daemon(state, ws_port, api_port).await {
                tracing::error!("Daemon error: {:#}", e);
            }
        });
        return Ok(());
    }

    // Otherwise run background daemon thread + Desktop GUI on main thread
    let daemon_state = state.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime");

        rt.block_on(async move {
            if let Err(e) = run_daemon(daemon_state, ws_port, api_port).await {
                tracing::error!("Daemon error: {:#}", e);
            }
        });
    });

    // Wait a brief moment for API to start
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Run Desktop GUI with WebView2 and Tray on main thread
    gui::run_gui(state)?;

    Ok(())
}

fn get_app_dir() -> Result<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if dir.join("ui").exists() || dir.join("paired.json").exists() {
                return Ok(dir.to_path_buf());
            }
        }
    }
    let p = PathBuf::from(r"D:\Temp\Turbo\mta-share\smartconnect-win");
    Ok(p)
}

pub fn handle_send_files(file_paths: Vec<PathBuf>, api_port: u16) -> Result<()> {
    let mut abs_files = Vec::new();
    for p in file_paths {
        if p.exists() {
            let abs = p.canonicalize().unwrap_or(p);
            let s = abs.to_string_lossy().to_string();
            let clean = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
            abs_files.push(clean);
        }
    }
    if abs_files.is_empty() {
        std::process::exit(1);
    }

    let body = serde_json::json!({
        "files": abs_files
    });

    let mut client = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], api_port)),
        std::time::Duration::from_millis(300),
    );
    if client.is_err() {
        // Auto-spawn background daemon from main unpackaged binary if not running yet
        let cur_exe = std::env::current_exe().ok();
        let spawn_exe = cur_exe
            .filter(|p| p.file_name().and_then(|n| n.to_str()).map(|s| s.eq_ignore_ascii_case("smartconnect.exe")).unwrap_or(false))
            .unwrap_or_else(|| PathBuf::from(r"D:\Temp\Turbo\mta-share\smartconnect-win\smartconnect.exe"));
        let _ = std::process::Command::new(spawn_exe).spawn();
        for _ in 0..8 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            client = std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], api_port)),
                std::time::Duration::from_millis(300),
            );
            if client.is_ok() {
                break;
            }
        }
    }
    if client.is_err() {
        std::process::exit(1);
    }

    // HTTP POST via native stream
    use std::io::{Read, Write};
    let mut stream = client.unwrap();
    let body_str = serde_json::to_string(&body)?;
    let req = format!(
        "POST /api/drop-send HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        api_port, body_str.len(), body_str
    );
    stream.write_all(req.as_bytes())?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;

    if !resp.contains("200 OK") {
        std::process::exit(1);
    }
    Ok(())
}
