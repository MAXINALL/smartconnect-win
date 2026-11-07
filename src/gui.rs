use anyhow::Result;
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::{Window, WindowBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};
use wry::{DragDropEvent, WebContext, WebView, WebViewBuilder};

use crate::server::SharedState;

pub fn sync_app_ico() {
    let size = 128u32;
    let rgba = generate_icon_rgba(size);
    let mut png_bytes = Vec::new();
    {
        use image::ImageEncoder;
        let encoder = image::codecs::png::PngEncoder::new(&mut png_bytes);
        if encoder
            .write_image(&rgba, size, size, image::ExtendedColorType::Rgba8)
            .is_err()
        {
            return;
        }
    }

    let png_len = png_bytes.len() as u32;
    let mut ico = Vec::with_capacity(22 + png_bytes.len());
    // ICONDIR (6 bytes): reserved=0, type=1 (ICO), count=1
    ico.extend_from_slice(&0u16.to_le_bytes());
    ico.extend_from_slice(&1u16.to_le_bytes());
    ico.extend_from_slice(&1u16.to_le_bytes());
    // ICONDIRENTRY (16 bytes)
    ico.push(size as u8); // width (128)
    ico.push(size as u8); // height (128)
    ico.push(0); // color count
    ico.push(0); // reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // color planes
    ico.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
    ico.extend_from_slice(&png_len.to_le_bytes()); // size of image data
    ico.extend_from_slice(&22u32.to_le_bytes()); // offset of image data
    ico.extend_from_slice(&png_bytes);

    for path in [
        r"D:\Temp\Web\temp\sc-target\app.ico",
        r"D:\Temp\Web\temp\sc-target\release\app.ico",
        r"D:\Temp\Turbo\mta-share\smartconnect-win\app.ico",
    ] {
        let _ = std::fs::write(path, &ico);
    }
}

pub fn run_gui(state: SharedState) -> Result<()> {
    sync_app_ico();
    let event_loop = EventLoopBuilder::new().build();

    // 1. Build Tray Menu
    let tray_menu = Menu::new();
    let open_item = MenuItem::new("打开主界面", true, None);
    let quit_item = MenuItem::new("退出", true, None);
    tray_menu.append(&open_item).ok();
    tray_menu.append(&quit_item).ok();

    // 2. Generate 64x64 Official PC+Tablet Link Icon for Tray & Window
    let icon_rgba = generate_icon_rgba(64);
    let tray_icon_img = Icon::from_rgba(icon_rgba.clone(), 64, 64)?;
    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("联想超级互联")
        .with_icon(tray_icon_img)
        .build()?;

    let open_id = open_item.id().clone();
    let quit_id = quit_item.id().clone();

    // 3. Initial Window & WebView
    let mut window: Option<Window> = None;
    let mut _webview: Option<WebView> = None;

    // Helper to spawn window
    let create_win = move |el: &tao::event_loop::EventLoopWindowTarget<()>| -> Result<(Window, WebView)> {
        let win_icon = tao::window::Icon::from_rgba(icon_rgba.clone(), 64, 64).ok();
        let win = WindowBuilder::new()
            .with_title("联想超级互联")
            .with_window_icon(win_icon)
            .with_inner_size(LogicalSize::new(360.0, 640.0))
            .with_resizable(false)
            .with_visible(true)
            .build(el)?;
        win.set_visible(true);
        win.set_focus();

        let data_dir = std::path::PathBuf::from(r"D:\Temp\Web\temp\sc-webview-data");
        std::fs::create_dir_all(&data_dir).ok();
        let mut web_context = WebContext::new(Some(data_dir));
        let wv = WebViewBuilder::new_with_web_context(&mut web_context)
            .with_url("http://127.0.0.1:52021/")
            .with_drag_drop_handler(|event| {
                if let DragDropEvent::Drop { paths, .. } = event {
                    if !paths.is_empty() {
                        std::thread::spawn(move || {
                            let _ = crate::handle_send_files(paths, 52021);
                        });
                    }
                }
                true
            })
            .build(&win)?;

        Ok((win, wv))
    };

    // Open on startup
    match create_win(&event_loop) {
        Ok((w, wv)) => {
            window = Some(w);
            _webview = Some(wv);
        }
        Err(e) => {
            let _ = std::fs::write(
                r"D:\Temp\Web\temp\sc-target\release\gui_error.log",
                format!("create_win error: {e:?}"),
            );
        }
    }

    event_loop.run(move |event, event_loop_window_target, control_flow| {
        *control_flow = ControlFlow::WaitUntil(std::time::Instant::now() + std::time::Duration::from_millis(50));

        // Check single-instance show_window_requested signal
        if state.show_window_requested.swap(false, std::sync::atomic::Ordering::Relaxed) {
            if window.is_none() {
                if let Ok((w, wv)) = create_win(event_loop_window_target) {
                    window = Some(w);
                    _webview = Some(wv);
                }
            } else if let Some(w) = window.as_ref() {
                w.set_minimized(false);
                w.set_focus();
            }
        }

        // Check Tray Icon clicks
        if let Ok(tray_event) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::Click { .. } = tray_event {
                if window.is_none() {
                    if let Ok((w, wv)) = create_win(event_loop_window_target) {
                        window = Some(w);
                        _webview = Some(wv);
                    }
                } else if let Some(w) = window.as_ref() {
                    w.set_focus();
                }
            }
        }

        // Check Tray Menu clicks
        if let Ok(menu_event) = MenuEvent::receiver().try_recv() {
            if menu_event.id == open_id {
                if window.is_none() {
                    if let Ok((w, wv)) = create_win(event_loop_window_target) {
                        window = Some(w);
                        _webview = Some(wv);
                    }
                } else if let Some(w) = window.as_ref() {
                    w.set_focus();
                }
            } else if menu_event.id == quit_id {
                state.shutdown_tx.send(()).ok();
                *control_flow = ControlFlow::Exit;
            }
        }

        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                state.settings.lock().unwrap().reload().ok();
                let close_to_tray = state.settings.lock().unwrap().current.close_to_tray;
                if close_to_tray {
                    // True destruction of WebView2 and Window to drop memory footprint
                    _webview = None;
                    window = None;
                } else {
                    state.shutdown_tx.send(()).ok();
                    *control_flow = ControlFlow::Exit;
                }
            }
            _ => {}
        }
    });
}

fn generate_icon_rgba(size: u32) -> Vec<u8> {
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    let s = 128.0 / (size as f32);
    for y in 0..size {
        for x in 0..size {
            let fx = (x as f32 + 0.5) * s;
            let fy = (y as f32 + 0.5) * s;

            // Rounded rect check: [4, 4] to [124, 124] with radius 28
            let inside_bg = if fx < 4.0 || fx > 124.0 || fy < 4.0 || fy > 124.0 {
                false
            } else {
                let cx = if fx < 32.0 { 32.0 - fx } else if fx > 96.0 { fx - 96.0 } else { 0.0 };
                let cy = if fy < 32.0 { 32.0 - fy } else if fy > 96.0 { fy - 96.0 } else { 0.0 };
                (cx * cx + cy * cy) <= 28.0 * 28.0
            };

            if !inside_bg {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }

            // Linear gradient #62a0ea (98,160,234) -> #1a5fb4 (26,95,180)
            let t = ((fy - 4.0) / 120.0).clamp(0.0, 1.0);
            let mut r = (98.0 * (1.0 - t) + 26.0 * t) as u8;
            let mut g = (160.0 * (1.0 - t) + 95.0 * t) as u8;
            let mut b = (234.0 * (1.0 - t) + 180.0 * t) as u8;

            // PC monitor white frame [14..82, 30..78], stand [42..54, 78..88], base [32..64, 88..94]
            let in_pc_frame = (fx >= 14.0 && fx <= 82.0 && fy >= 30.0 && fy <= 78.0)
                || (fx >= 42.0 && fx <= 54.0 && fy >= 78.0 && fy <= 88.0)
                || (fx >= 32.0 && fx <= 64.0 && fy >= 88.0 && fy <= 94.0);
            let in_pc_screen = fx >= 20.0 && fx <= 76.0 && fy >= 36.0 && fy <= 72.0;

            // Link dots at (86, 60) and (92, 60) r=2.8
            let in_dots = ((fx - 86.0).powi(2) + (fy - 60.0).powi(2) <= 7.8)
                || ((fx - 92.0).powi(2) + (fy - 60.0).powi(2) <= 7.8);

            // Tablet/Phone frame [96..118, 38..82], screen [99..115, 43..74]
            let in_tab_frame = fx >= 96.0 && fx <= 118.0 && fy >= 38.0 && fy <= 82.0;
            let in_tab_screen = fx >= 99.0 && fx <= 115.0 && fy >= 43.0 && fy <= 74.0;

            if in_pc_screen || in_tab_screen {
                r = 28;
                g = 113;
                b = 216;
            } else if in_pc_frame || in_dots || in_tab_frame {
                r = 255;
                g = 255;
                b = 255;
            }

            rgba.extend_from_slice(&[r, g, b, 255]);
        }
    }
    rgba
}
