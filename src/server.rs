use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use axum::extract::{Multipart, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

use smartconnect_fex::client::{pull as fex_pull, Offer as FexOffer, DEFAULT_MAX_BYTES};
use smartconnect_fex::zip::read_all as fex_zip_read_all;

use crate::clipboard::ClipboardManager;
use crate::fex_stream::{serve_control_websocket, stream_download, DiskFile, StreamRegistry};
use crate::identity::Identity;
use crate::invite::{render_qr_png, Invite};
use crate::nfs::{download_nfs_file, list_directory, MountTarget};
use crate::pairing::PairingStore;
use crate::proto::{
    device_status_msg, Hello, WsMsg,
    SERVICE_CLIPBOARD, SERVICE_DEVICE_STATUS, SERVICE_FILE_EX, SERVICE_FILE_STATION,
    SERVICE_MANAGER,
};
use crate::settings::{Settings, SettingsStore};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TransferItem {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub status: String,
    #[serde(default)]
    pub path: String,
}

pub struct DaemonState {
    pub root_dir: PathBuf,
    pub identity: Arc<Identity>,
    pub pairing: Arc<Mutex<PairingStore>>,
    pub settings: Arc<Mutex<SettingsStore>>,
    pub clipboard: Arc<ClipboardManager>,
    pub fex_registry: Arc<StreamRegistry>,
    pub nfs_target: Arc<Mutex<Option<MountTarget>>>,
    pub connected: Arc<AtomicBool>,
    pub reconnecting: Arc<AtomicBool>,
    pub reconnect_nudge: Arc<tokio::sync::Notify>,
    pub connect_lock: Arc<tokio::sync::Mutex<()>>,
    pub tablet_mdns_addr: Arc<Mutex<Option<(String, SocketAddr)>>>,
    pub current_invite: Arc<Mutex<Option<Invite>>>,
    pub pending_files: Arc<Mutex<Vec<PathBuf>>>,
    pub show_window_requested: Arc<AtomicBool>,
    pub connected_device_name: Arc<Mutex<String>>,
    pub connected_device_id: Arc<Mutex<String>>,
    pub connected_ip: Arc<Mutex<String>>,
    pub ws_sender: Arc<tokio::sync::Mutex<Option<SplitSink<WebSocketStream<Prefixed<tokio_rustls::server::TlsStream<TcpStream>>>, Message>>>>,
    pub transfers: Arc<Mutex<Vec<TransferItem>>>,
    pub clipboard_history: Arc<Mutex<Vec<String>>>,
    pub shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl DaemonState {
    pub fn current_token(&self, ws_port: u16) -> String {
        let mut slot = self.current_invite.lock().unwrap();
        let fresh = matches!(
            slot.as_ref(),
            Some(inv) if inv.expires > std::time::Instant::now() + Duration::from_secs(60)
        );
        if !fresh {
            *slot = Some(Invite::new(ws_port, get_local_ips(), Duration::from_secs(3600)));
        }
        slot.as_ref().unwrap().token.clone()
    }
}

pub type SharedState = Arc<DaemonState>;

pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn run_daemon(state: SharedState, ws_port: u16, api_port: u16) -> Result<()> {
    let tls_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = run_tls_server(tls_state, ws_port).await {
            warn!("TLS server error: {:#}", e);
        }
    });

    let clip_state = state.clone();
    tokio::spawn(async move {
        run_clipboard_loop(clip_state).await;
    });

    // Start BLE peripheral advertisement (0x5246)
    crate::discovery::start_ble_peripheral_advert(&state);

    // Start pure Rust mDNS advertiser & browser (_readyformdns._tcp.local)
    let mdns_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::discovery::run_mdns_service(mdns_state, ws_port).await {
            warn!("mDNS service error: {:#}", e);
        }
    });

    // Start auto-reconnect loop (Wi-Fi /readyfor/mdns + BLE GATT 0x5246 wake)
    let reconn_state = state.clone();
    tokio::spawn(async move {
        crate::discovery::run_auto_reconnect_loop(reconn_state, ws_port).await;
    });

    let app = create_api_router(state.clone());
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), api_port)).await?;
    info!("Management API listening on http://127.0.0.1:{}", api_port);

    let mut shutdown_rx = state.shutdown_tx.subscribe();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_rx.recv().await.ok();
            info!("Management API shutting down");
        })
        .await?;

    Ok(())
}

async fn run_clipboard_loop(state: SharedState) {
    let mut interval = tokio::time::interval(Duration::from_millis(600));
    loop {
        interval.tick().await;
        let auto = state.settings.lock().unwrap().current.auto_clipboard;
        if !auto || !state.connected.load(Ordering::Relaxed) {
            continue;
        }

        if let Some(text) = state.clipboard.check_changed() {
            info!("Auto-clipboard: pushing {} chars to tablet", text.len());
            send_clipboard_to_tablet(&state, &text).await.ok();
        }
    }
}

pub async fn send_clipboard_to_tablet(state: &SharedState, text: &str) -> Result<()> {
    let mut guard = state.ws_sender.lock().await;
    if let Some(sink) = guard.as_mut() {
        let clip_id = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        let msg = WsMsg::outgoing(
            &state.identity.device_id,
            SERVICE_CLIPBOARD,
            json!({
                "msgId": 3,
                "data": {
                    "clipId": clip_id,
                    "text": text,
                    "time": clip_id,
                }
            }),
        );
        let s = serde_json::to_string(&msg)?;
        sink.send(Message::Text(s.into())).await?;
    }
    state.clipboard_history.lock().unwrap().push(format!("[Local -> Phone] {}", text));
    Ok(())
}

async fn run_tls_server(state: SharedState, port: u16) -> Result<()> {
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![state.identity.cert_der.clone()], state.identity.key_der.clone_key())?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)).await?;
    info!("Smart Connect TLS server listening on 0.0.0.0:{}", port);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("TLS accept error: {:#}", e);
                continue;
            }
        };

        let state = state.clone();
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(%peer, "TLS handshake failed: {:#}", e);
                    return;
                }
            };

            if let Err(e) = handle_tls_connection(state, tls_stream, peer).await {
                warn!(%peer, "Connection error: {:#}", e);
            }
        });
    }
}

async fn handle_tls_connection(
    state: SharedState,
    mut tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    peer: SocketAddr,
) -> Result<()> {
    let mut head_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    while !head_buf.windows(4).any(|w| w == b"\r\n\r\n") && head_buf.len() < 16384 {
        let n = tls_stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before HTTP head");
        }
        head_buf.extend_from_slice(&chunk[..n]);
    }

    let head = String::from_utf8_lossy(&head_buf).to_string();
    let first_line = head.lines().next().unwrap_or("").to_string();
    let target = first_line.split_whitespace().nth(1).unwrap_or("").to_string();

    if target.starts_with("/download") {
        stream_download(&state, tls_stream, &target).await.ok();
        return Ok(());
    }

    if target.starts_with("/websocket") {
        let prefixed = Prefixed::new(head_buf, tls_stream);
        let ws = tokio_tungstenite::accept_async(prefixed).await.context("fex WebSocket upgrade")?;
        serve_control_websocket(&state, ws).await.ok();
        return Ok(());
    }

    if target.starts_with("/readyfor/mdns") {
        let prefixed = Prefixed::new(head_buf, tls_stream);
        let ws = tokio_tungstenite::accept_async(prefixed).await.context("mDNS WebSocket upgrade")?;
        return handle_mdns_ws(state, ws, peer).await;
    }

    let prefixed = Prefixed::new(head_buf, tls_stream);
    let ws = tokio_tungstenite::accept_async(prefixed).await.context("Control WebSocket upgrade")?;
    info!(%peer, "Control WebSocket accepted for Smart Connect");

    handle_control_ws(state, ws, peer).await
}

async fn handle_mdns_ws(
    state: SharedState,
    mut ws: WebSocketStream<Prefixed<tokio_rustls::server::TlsStream<TcpStream>>>,
    peer: SocketAddr,
) -> Result<()> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    while let Some(msg) = ws.next().await {
        let frame = match msg? {
            Message::Binary(b) => b,
            Message::Close(_) => break,
            _ => continue,
        };
        if frame.len() < 45 || frame[16] != 1 {
            continue;
        }
        let iv = &frame[17..29];
        let ct = &frame[29..];
        let aad = &frame[..17];

        let mut matched_key = None;
        let keys: Vec<String> = {
            let p = state.pairing.lock().unwrap();
            p.first()
                .map(|(_, rec)| {
                    let mut v = vec![rec.key.clone()];
                    if let Some(pk) = &rec.phone_key {
                        v.push(pk.clone());
                    }
                    v
                })
                .unwrap_or_default()
        };

        for k in keys {
            if let Ok(kb) = B64.decode(&k) {
                if let Ok(cipher) = Aes256Gcm::new_from_slice(&kb) {
                    if let Ok(pt) = cipher.decrypt(Nonce::from_slice(iv), Payload { msg: ct, aad }) {
                        if let Ok(val) = serde_json::from_slice::<Value>(&pt) {
                            if val.get("cmd").and_then(Value::as_i64) == Some(0) {
                                matched_key = Some(k);
                                break;
                            }
                        }
                    }
                }
            }
        }

        if let Some(key_b64) = matched_key {
            if let Ok(out_frame) = crate::discovery::sealed_invite(&state, &key_b64, 52020) {
                ws.send(Message::Binary(out_frame.into())).await?;
                info!(%peer, "mdns: sent encrypted invite; tablet will dial /readyfor/ now");
            }
        }
    }
    Ok(())
}

async fn handle_control_ws(
    state: SharedState,
    ws: WebSocketStream<Prefixed<tokio_rustls::server::TlsStream<TcpStream>>>,
    peer: SocketAddr,
) -> Result<()> {
    let (mut sink, mut stream) = ws.split();

    // 1. Wait for tablet's first frame (Hello: serviceId 0, cmd 0)
    let first_text = match stream.next().await {
        Some(Ok(Message::Text(t))) => t.to_string(),
        other => bail!("expected text frame from tablet, got {:?}", other),
    };

    let hello_msg: WsMsg = serde_json::from_str(&first_text).context("parsing first Hello frame")?;
    if hello_msg.service_id != SERVICE_MANAGER {
        bail!("first frame serviceId {}, expected 0", hello_msg.service_id);
    }

    let hello_data = hello_msg.data.unwrap_or(Value::Null);
    let hello = Hello::parse(&hello_data);

    let stable_id = hello.real_device_id.unwrap_or(&hello_msg.device_id).to_string();
    let dev_name = hello.device_name.unwrap_or("联想小新平板Pro GT").to_string();

    info!(%peer, phone = %stable_id, name = %dev_name, "tablet Hello handshake received");

    let record = state.pairing.lock().unwrap().pair(&stable_id, Some(&dev_name), hello.real_device_id)?;
    state.pairing.lock().unwrap().update_ip(&stable_id, &peer.ip().to_string()).ok();

    *state.connected_device_name.lock().unwrap() = dev_name.clone();
    *state.connected_device_id.lock().unwrap() = stable_id.clone();
    *state.connected_ip.lock().unwrap() = peer.ip().to_string();

    // 2. Send full genuine Windows Verify Reply (cmd: 0)
    let id = &state.identity;
    let verify_reply = json!({
        "ver": 3,
        "cmd": 0,
        "token": "OK",
        "paired": 1,
        "connType": 1,
        "device": {
            "deviceId": id.device_id,
            "realDeviceId": id.real_device_id,
            "deviceName": id.device_name,
            "os": 6,
            "type": 4,
            "scType": 2,
            "verCode": crate::invite::VER_CODE,
            "verName": crate::invite::VER_NAME,
            "appVer": crate::invite::VER_NAME,
            "minVerCode": { "1": 7000000, "2": 700000000, "3": 7000000, "4": 7000000 },
            "sn": id.serial_number(),
            "Sku": "Windows PC",
            "sku": "Windows PC",
            "cap": 0,
            "caps": crate::proto::service_caps(),
            "serviceVersions": crate::proto::service_versions(),
            "key": record.key,
            "isPaired": true
        },
        "serviceVersions": crate::proto::service_versions()
    });
    sink.send(Message::Text(serde_json::to_string(&WsMsg::outgoing(&id.device_id, SERVICE_MANAGER, verify_reply))?.into())).await?;

    // 3. Send SERVICE_DEVICE_STATUS (serviceId 25)
    let status_data = device_status_msg(&id.device_name);
    sink.send(Message::Text(serde_json::to_string(&WsMsg::outgoing(&id.device_id, SERVICE_DEVICE_STATUS, status_data))?.into())).await?;

    // 4. Send File Station (serviceId 168) Handshake
    let handshake_inner = json!({
        "type": 0,
        "dt2type": 2,
        "nfs_dependency": 24,
        "fp": id.fp_hex(),
    }).to_string();
    let nfs_handshake = json!({
        "ver": "1.0",
        "cmd": 1001,
        "data": handshake_inner,
    });
    sink.send(Message::Text(serde_json::to_string(&WsMsg::outgoing(&id.device_id, SERVICE_FILE_STATION, nfs_handshake))?.into())).await?;

    {
        let mut guard = state.ws_sender.lock().await;
        *guard = Some(sink);
    }

    state.connected.store(true, Ordering::Relaxed);
    state.reconnecting.store(false, Ordering::Relaxed);
    info!(%peer, phone = %stable_id, "Connected and verified with tablet");

    // Flush any pending files queued via SendTo / drop while disconnected
    let flush_state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let queued: Vec<PathBuf> = {
            let mut g = flush_state.pending_files.lock().unwrap();
            std::mem::take(&mut *g)
        };
        if !queued.is_empty() {
            info!("Sending {} queued pending files to newly connected tablet", queued.len());
            let _ = send_files_to_tablet(&flush_state, &queued).await;
        }
    });

    let mut ping_interval = tokio::time::interval(Duration::from_secs(20));
    ping_interval.tick().await;
    let key_exchange_deadline = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(key_exchange_deadline);
    let mut key_exchanged = false;

    loop {
        tokio::select! {
            _ = &mut key_exchange_deadline, if !key_exchanged => {
                key_exchanged = true;
                let id = &state.identity;
                let ex_reply = json!({
                    "ver": 3,
                    "cmd": 1,
                    "paired": 1,
                    "device": {
                        "deviceId": id.real_device_id,
                        "realDeviceId": id.real_device_id,
                        "deviceName": id.device_name,
                        "key": record.key,
                        "sn": id.serial_number(),
                        "cap": 0,
                        "os": 6,
                        "type": 4,
                        "i3": 1,
                        "verCode": crate::invite::VER_CODE,
                        "verName": crate::invite::VER_NAME,
                    }
                });
                let mut guard = state.ws_sender.lock().await;
                if let Some(sink) = guard.as_mut() {
                    if let Ok(s) = serde_json::to_string(&WsMsg::outgoing(&id.device_id, SERVICE_MANAGER, ex_reply)) {
                        sink.send(Message::Text(s.into())).await.ok();
                    }
                }
            }
            _ = ping_interval.tick() => {
                let mut guard = state.ws_sender.lock().await;
                if let Some(s) = guard.as_mut() {
                    if let Err(e) = s.send(Message::Ping(vec![].into())).await {
                        warn!("Ping failed: {:#}", e);
                        break;
                    }
                }
            }
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if text.contains("\"cmd\":1") && text.contains("\"serviceId\":0") {
                            key_exchanged = true;
                        }
                        handle_incoming_frame(&state, &text, peer, &record.key).await.ok();
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!(%peer, "WebSocket closed by peer");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    state.connected.store(false, Ordering::Relaxed);
    {
        let mut guard = state.ws_sender.lock().await;
        *guard = None;
    }
    info!(%peer, "Disconnected from tablet");
    state.reconnect_nudge.notify_one();
    Ok(())
}

async fn handle_incoming_frame(state: &SharedState, text: &str, peer: SocketAddr, pairing_key: &str) -> Result<()> {
    let val: Value = serde_json::from_str(text)?;
    let service_id = val.get("serviceId").and_then(Value::as_i64).unwrap_or(-1);
    let src_service_id = val.get("srcServiceId").and_then(Value::as_i64).unwrap_or(service_id);
    let data = val.get("data").cloned().unwrap_or(val.clone());

    if src_service_id == SERVICE_MANAGER {
        let cmd = data.get("cmd").and_then(Value::as_i64).unwrap_or(0);
        if cmd == 1 {
            // key exchange from phone
            if let Some(phone_key) = data.pointer("/device/key").and_then(Value::as_str) {
                let dev_id = state.connected_device_id.lock().unwrap().clone();
                state.pairing.lock().unwrap().save_phone_key(&dev_id, phone_key).ok();
            }
            // Reply with our key exchange
            let id = &state.identity;
            let ex_reply = json!({
                "ver": 3,
                "cmd": 1,
                "paired": 1,
                "device": {
                    "deviceId": id.real_device_id,
                    "realDeviceId": id.real_device_id,
                    "deviceName": id.device_name,
                    "key": pairing_key,
                    "sn": id.serial_number(),
                    "cap": 0,
                    "os": 6,
                    "type": 4,
                    "i3": 1,
                    "verCode": crate::invite::VER_CODE,
                    "verName": crate::invite::VER_NAME,
                }
            });
            let mut guard = state.ws_sender.lock().await;
            if let Some(sink) = guard.as_mut() {
                sink.send(Message::Text(serde_json::to_string(&WsMsg::outgoing(&id.device_id, SERVICE_MANAGER, ex_reply))?.into())).await?;
            }
        }
    } else if src_service_id == SERVICE_CLIPBOARD {
        let msg_id = data.get("msgId").and_then(Value::as_i64).unwrap_or(0);
        if msg_id == 1 {
            // CLIP_NEGO -> reply with CLIP_CONFIRM
            let mut guard = state.ws_sender.lock().await;
            if let Some(sink) = guard.as_mut() {
                let confirm = json!({
                    "msgId": 2,
                    "data": { "version": 1 }
                });
                sink.send(Message::Text(serde_json::to_string(&WsMsg::outgoing(&state.identity.device_id, SERVICE_CLIPBOARD, confirm))?.into())).await?;
            }
        } else if msg_id == 3 {
            // CLIP_UPDATE_NOTIFY
            if let Some(t) = data.pointer("/data/text").and_then(Value::as_str) {
                info!("Received clipboard text from tablet: {} chars", t.len());
                state.clipboard.set_text(t).ok();
                state.clipboard_history.lock().unwrap().push(t.to_string());
            } else if let Some(clip_id) = data.pointer("/data/clipId").and_then(Value::as_i64) {
                // Image clip -> PULL it
                let mut guard = state.ws_sender.lock().await;
                if let Some(sink) = guard.as_mut() {
                    let pull = json!({
                        "msgId": 4,
                        "data": { "clipId": clip_id }
                    });
                    sink.send(Message::Text(serde_json::to_string(&WsMsg::outgoing(&state.identity.device_id, SERVICE_CLIPBOARD, pull))?.into())).await?;
                }
            }
        }
    } else if src_service_id == SERVICE_FILE_STATION {
        let cmd = data.get("cmd").and_then(Value::as_i64).unwrap_or(0);
        if cmd == 1001 {
            if let Some(inner_str) = data.get("data").and_then(Value::as_str) {
                if let Ok(hs) = serde_json::from_str::<Value>(inner_str) {
                    if hs.get("type").and_then(Value::as_i64) == Some(1) {
                        let nfs_port = hs.get("nfsport").and_then(json_u16).unwrap_or(0);
                        let mount_port = hs.get("port").and_then(json_u16).unwrap_or(0);
                        let ip = hs.get("ip").and_then(Value::as_str).unwrap_or(&peer.ip().to_string()).to_string();
                        let fp = hs.get("fp").and_then(Value::as_str).unwrap_or("").to_string();
                        let path = hs.get("path").and_then(Value::as_str).filter(|p| !p.is_empty()).unwrap_or("/sdcard").to_string();

                        info!("File Station (NFSv3) target acquired: {}:{} (mount: {}) at {}", ip, nfs_port, mount_port, path);
                        let mut guard = state.nfs_target.lock().unwrap();
                        *guard = Some(MountTarget {
                            ip,
                            mount_port,
                            nfs_port,
                            fingerprint: fp,
                            path,
                        });
                    }
                }
            }
        }
    } else if src_service_id == SERVICE_FILE_EX {
        let cmd = data.get("cmd").and_then(Value::as_i64).unwrap_or(0);
        if cmd == 1 {
            info!("Incoming FEX file offer from tablet: {:?}", data);
            let state = state.clone();
            tokio::spawn(async move {
                handle_incoming_fex_offer(state, data, peer.ip()).await.ok();
            });
        }
    } else if (src_service_id == 1 && data.get("cmd").and_then(Value::as_i64) == Some(31))
        || (src_service_id == 16 && data.get("cmd").and_then(Value::as_i64) == Some(14))
    {
        let mut reply_data = data.clone();
        if let Value::Object(ref mut m) = reply_data {
            m.insert("reply".into(), json!(1));
        }
        let ack = WsMsg {
            device_id: state.identity.device_id.clone(),
            src_service_id,
            service_id: src_service_id,
            msg_id: val.get("msgId").and_then(Value::as_u64).unwrap_or(0),
            data: Some(reply_data),
            ver: None,
            sender_id: None,
        };
        let mut guard = state.ws_sender.lock().await;
        if let Some(sink) = guard.as_mut() {
            sink.send(Message::Text(serde_json::to_string(&ack)?.into())).await.ok();
        }
    }

    Ok(())
}

fn json_u16(v: &Value) -> Option<u16> {
    v.as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .filter(|&p| p != 0)
}

async fn handle_incoming_fex_offer(state: SharedState, data: Value, default_ip: IpAddr) -> Result<()> {
    let task_id = data.get("taskId").and_then(Value::as_str).unwrap_or("").to_string();
    let port = data.get("port").and_then(json_u16).unwrap_or(0);
    let fp = data.get("fingerprint").and_then(Value::as_str).unwrap_or("").to_string();
    let token = data.get("token").and_then(Value::as_str).unwrap_or("").to_string();

    if port == 0 || task_id.is_empty() {
        return Ok(());
    }

    let download_dir = state.settings.lock().unwrap().current.download_dir.clone();
    std::fs::create_dir_all(&download_dir)?;

    let offer = FexOffer {
        host: default_ip,
        port,
        fingerprint: fp,
        token,
    };

    info!("Pulling FEX transfer {} from tablet {}:{}", task_id, default_ip, port);
    let pulled = fex_pull(&offer, DEFAULT_MAX_BYTES).await.context("pulling FEX offer")?;
    let entries = fex_zip_read_all(&pulled.archive).context("unzipping FEX archive")?;

    for entry in entries {
        let file_name = Path::new(&entry.name).file_name().unwrap_or_default().to_string_lossy().to_string();
        let dest = Path::new(&download_dir).join(&file_name);
        tokio::fs::write(&dest, &entry.data).await?;

        let transfer_id = format!("dl_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
        state.transfers.lock().unwrap().insert(0, TransferItem {
            id: transfer_id,
            name: file_name.clone(),
            size: entry.data.len() as u64,
            status: "已下载".to_string(),
            path: dest.to_string_lossy().to_string(),
        });
        info!("Successfully saved tablet file to {:?}", dest);
    }

    Ok(())
}

fn create_api_router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(handle_index))
        .route("/style.css", get(handle_css))
        .route("/app.js", get(handle_js))
        .route("/api/status", get(api_status))
        .route("/api/pair", get(api_pair))
        .route("/api/pair-qr.png", get(api_pair_qr))
        .route("/api/reconnect", get(api_reconnect).post(api_reconnect))
        .route("/api/settings", get(api_get_settings).post(api_post_settings))
        .route("/api/pick-download-dir", post(api_pick_download_dir))
        .route("/api/clipboard", post(api_post_clipboard))
        .route("/api/read-pc-clipboard", get(api_read_pc_clipboard).post(api_read_pc_clipboard))
        .route("/api/clipboard/read-pc", get(api_read_pc_clipboard).post(api_read_pc_clipboard))
        .route("/api/pick-and-send", post(api_pick_and_send))
        .route("/api/drop-send", post(api_drop_send))
        .route("/api/upload-and-send", post(api_upload_and_send))
        .route("/api/transfers", get(api_get_transfers))
        .route("/api/transfers/clear", post(api_clear_transfers))
        .route("/api/open-file", post(api_open_file))
        .route("/api/reveal-file", post(api_reveal_file))
        .route("/api/nfs/list", get(api_nfs_list))
        .route("/api/nfs/download", post(api_nfs_download))
        .route("/api/show-window", get(api_show_window).post(api_show_window))
        .route("/api/shutdown", get(api_shutdown))
        .with_state(state)
}

const EMBEDDED_INDEX_HTML: &str = include_str!("../ui/index.html");
const EMBEDDED_STYLE_CSS: &str = include_str!("../ui/style.css");
const EMBEDDED_APP_JS: &str = include_str!("../ui/app.js");

fn resolve_ui_file(state: &SharedState, filename: &str) -> PathBuf {
    let src_ui = PathBuf::from(r"D:\Temp\Turbo\mta-share\smartconnect-win\ui").join(filename);
    if src_ui.exists() {
        return src_ui;
    }
    state.root_dir.join("ui").join(filename)
}

async fn handle_index(State(state): State<SharedState>) -> Response {
    let p = resolve_ui_file(&state, "index.html");
    let body = tokio::fs::read_to_string(&p)
        .await
        .unwrap_or_else(|_| EMBEDDED_INDEX_HTML.to_string());
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
        ],
        body,
    )
        .into_response()
}

async fn handle_css(State(state): State<SharedState>) -> Response {
    let p = resolve_ui_file(&state, "style.css");
    let body = tokio::fs::read_to_string(&p)
        .await
        .unwrap_or_else(|_| EMBEDDED_STYLE_CSS.to_string());
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
        ],
        body,
    )
        .into_response()
}

async fn handle_js(State(state): State<SharedState>) -> Response {
    let p = resolve_ui_file(&state, "app.js");
    let body = tokio::fs::read_to_string(&p)
        .await
        .unwrap_or_else(|_| EMBEDDED_APP_JS.to_string());
    (
        [
            (header::CONTENT_TYPE, "application/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
        ],
        body,
    )
        .into_response()
}

async fn api_status(State(state): State<SharedState>) -> Json<Value> {
    let is_conn = state.connected.load(Ordering::Relaxed);
    let is_reconn = state.reconnecting.load(Ordering::Relaxed);
    let has_paired = !state.pairing.lock().unwrap().is_empty();
    let dev_name = state.connected_device_name.lock().unwrap().clone();
    let dev_id = state.connected_device_id.lock().unwrap().clone();
    let ip = state.connected_ip.lock().unwrap().clone();
    let auto_clip = state.settings.lock().unwrap().current.auto_clipboard;
    let clip_hist = state.clipboard_history.lock().unwrap().clone();
    let trans_hist = state.transfers.lock().unwrap().clone();

    let default_name = state.pairing.lock().unwrap().first().and_then(|(_, p)| p.device_name.clone()).unwrap_or_else(|| "联想小新平板Pro GT".to_string());
    let display_name = if is_conn && !dev_name.is_empty() { dev_name } else { default_name };

    Json(json!({
        "connected": is_conn,
        "reconnecting": is_reconn,
        "has_paired": has_paired,
        "peer_name": display_name,
        "device_name": display_name,
        "device_id": dev_id,
        "ip": ip,
        "auto_clipboard": auto_clip,
        "clipboard_history": clip_hist,
        "transfer_history": trans_hist,
    }))
}

async fn api_reconnect(State(state): State<SharedState>) -> Json<Value> {
    if state.connected.load(Ordering::Relaxed) {
        return Json(json!({ "status": "ok", "connected": true, "message": "已连接平板" }));
    }
    state.reconnect_nudge.notify_one();
    let st = state.clone();
    tokio::spawn(async move {
        let _ = crate::discovery::connect_now(&st, 52020).await;
    });
    Json(json!({
        "status": "ok",
        "connected": false,
        "message": "正在通过局域网与蓝牙自动唤醒平板..."
    }))
}

async fn api_pair(State(state): State<SharedState>) -> Json<Value> {
    let ips = get_local_ips();
    let inv = Invite::new(52020, ips, Duration::from_secs(3600));
    let payload = inv.qr_payload(&state.identity);
    *state.current_invite.lock().unwrap() = Some(inv);
    let qr_path = state.root_dir.join("pair_qr.png");
    render_qr_png(&payload, &qr_path).ok();
    Json(json!({ "status": "ok", "payload": payload }))
}

pub fn get_local_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("10.22.51.228:80").is_ok() {
            if let Ok(addr) = s.local_addr() {
                ips.push(addr.ip());
            }
        }
    }
    if ips.is_empty() {
        ips.push(IpAddr::V4(Ipv4Addr::new(10, 35, 209, 152)));
    }
    ips
}

async fn api_pair_qr(State(state): State<SharedState>) -> Response {
    let qr_path = state.root_dir.join("pair_qr.png");
    if let Ok(b) = tokio::fs::read(&qr_path).await {
        ([(header::CONTENT_TYPE, "image/png")], b).into_response()
    } else {
        (StatusCode::NOT_FOUND, "QR not found").into_response()
    }
}

async fn api_get_settings(State(state): State<SharedState>) -> Json<Settings> {
    let s = state.settings.lock().unwrap().current.clone();
    Json(s)
}

async fn api_post_settings(State(state): State<SharedState>, Json(s): Json<Settings>) -> Json<Value> {
    state.settings.lock().unwrap().save(s).ok();
    Json(json!({ "status": "ok" }))
}

async fn api_pick_download_dir(State(state): State<SharedState>) -> Json<Value> {
    let cur_dir = state.settings.lock().unwrap().current.download_dir.clone();
    let mut dialog = rfd::AsyncFileDialog::new().set_title("选择接收文件保存目录");
    if Path::new(&cur_dir).exists() {
        dialog = dialog.set_directory(&cur_dir);
    }
    if let Some(folder) = dialog.pick_folder().await {
        let new_dir = folder.path().to_string_lossy().to_string();
        let mut guard = state.settings.lock().unwrap();
        let mut s = guard.current.clone();
        s.download_dir = new_dir.clone();
        guard.save(s).ok();
        return Json(json!({ "status": "ok", "download_dir": new_dir }));
    }
    Json(json!({ "status": "cancelled" }))
}

async fn api_post_clipboard(State(state): State<SharedState>, Json(body): Json<Value>) -> Json<Value> {
    let text = body.get("text").and_then(Value::as_str).unwrap_or("");
    if !text.is_empty() {
        send_clipboard_to_tablet(&state, text).await.ok();
    }
    Json(json!({ "status": "ok" }))
}

async fn api_read_pc_clipboard(State(state): State<SharedState>) -> Json<Value> {
    let text = state.clipboard.get_text().unwrap_or_default();
    Json(json!({ "text": text }))
}

async fn api_pick_and_send(State(state): State<SharedState>) -> Json<Value> {
    let dialog = rfd::AsyncFileDialog::new().set_title("选择要发送到平板的文件");
    if let Some(handles) = dialog.pick_files().await {
        let paths: Vec<PathBuf> = handles.into_iter().map(|h| h.path().to_path_buf()).collect();
        if !paths.is_empty() {
            let names: Vec<String> = paths
                .iter()
                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .collect();
            send_files_to_tablet(&state, &paths).await.ok();
            return Json(json!({ "status": "ok", "files": names }));
        }
    }
    Json(json!({ "status": "cancelled" }))
}

async fn api_drop_send(State(state): State<SharedState>, Json(body): Json<Value>) -> Json<Value> {
    state.show_window_requested.store(true, Ordering::Relaxed);
    if let Some(files) = body.get("files").and_then(Value::as_array) {
        let paths: Vec<PathBuf> = files
            .iter()
            .filter_map(|f| f.as_str().map(PathBuf::from))
            .collect();
        if !paths.is_empty() {
            send_files_to_tablet(&state, &paths).await.ok();
        }
    }
    Json(json!({ "status": "ok" }))
}

async fn api_upload_and_send(State(state): State<SharedState>, mut multipart: Multipart) -> Response {
    let mut sent = Vec::new();
    let mut paths = Vec::new();
    let mut last_path = String::new();
    let temp_dir = state.root_dir.join("temp_uploads");
    std::fs::create_dir_all(&temp_dir).ok();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.file_name().unwrap_or("upload.dat").to_string();
        if let Ok(bytes) = field.bytes().await {
            let dest = temp_dir.join(&name);
            if tokio::fs::write(&dest, &bytes).await.is_ok() {
                last_path = dest.to_string_lossy().to_string();
                paths.push(dest);
                sent.push(name);
            }
        }
    }
    if !paths.is_empty() {
        send_files_to_tablet(&state, &paths).await.ok();
    }
    Json(json!({ "status": "ok", "success": true, "path": last_path, "sent": sent })).into_response()
}

pub async fn send_files_to_tablet(state: &SharedState, file_paths: &[PathBuf]) -> Result<()> {
    let mut disk_files = Vec::new();
    for p in file_paths {
        if let Ok(meta) = std::fs::metadata(p) {
            if meta.is_file() {
                let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                disk_files.push(DiskFile {
                    path: p.clone(),
                    name,
                    size: meta.len(),
                });
            }
        }
    }
    if disk_files.is_empty() {
        bail!("no valid files to send");
    }

    let total_size: u64 = disk_files.iter().map(|f| f.size).sum();
    let display_name = if disk_files.len() == 1 {
        disk_files[0].name.clone()
    } else {
        format!("{} 等 {} 个文件", disk_files[0].name, disk_files.len())
    };
    let first_path_str = disk_files[0].path.to_string_lossy().to_string();

    if !state.connected.load(Ordering::Relaxed) {
        {
            let mut q = state.pending_files.lock().unwrap();
            for f in &disk_files {
                if !q.iter().any(|p| p == &f.path) {
                    q.push(f.path.clone());
                }
            }
        }
        {
            let mut tr = state.transfers.lock().unwrap();
            tr.retain(|t| t.path != first_path_str);
            tr.insert(
                0,
                TransferItem {
                    id: format!("q_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis()),
                    name: display_name.clone(),
                    size: total_size,
                    status: "等待连接后自动发送...".to_string(),
                    path: first_path_str,
                },
            );
        }
        state.reconnect_nudge.notify_one();
        info!("Tablet not yet connected; queued {} for auto-send and nudged reconnect", display_name);
        return Ok(());
    }

    let offer = state.fex_registry.offer_files(
        disk_files,
        &state.identity.device_id,
        &state.identity.device_name,
    );

    {
        let mut tr = state.transfers.lock().unwrap();
        tr.retain(|t| t.path != first_path_str);
        tr.insert(
            0,
            TransferItem {
                id: offer.task_id.clone(),
                name: display_name.clone(),
                size: total_size,
                status: "等待平板接收...".to_string(),
                path: first_path_str,
            },
        );
    }

    let mut guard = state.ws_sender.lock().await;
    if let Some(sink) = guard.as_mut() {
        let fex_msg = json!({
            "ver": "1.0",
            "cmd": 1,
            "serviceId": 2,
            "requestId": offer.task_id,
            "taskId": offer.task_id,
            "port": 52020,
            "fingerprint": state.identity.fp_hex(),
            "token": offer.token,
            "fexId": 0,
            "autoDownload": true,
        });
        sink.send(Message::Text(serde_json::to_string(&WsMsg::outgoing(&state.identity.device_id, SERVICE_FILE_EX, fex_msg))?.into())).await?;
        info!("Sent streaming FEX offer {} ({} bytes) to tablet", display_name, total_size);
    }
    Ok(())
}

async fn api_get_transfers(State(state): State<SharedState>) -> Json<Vec<TransferItem>> {
    let list = state.transfers.lock().unwrap().clone();
    Json(list)
}

async fn api_clear_transfers(State(state): State<SharedState>) -> Json<Value> {
    state.transfers.lock().unwrap().clear();
    Json(json!({ "status": "ok" }))
}

async fn api_open_file(Json(body): Json<Value>) -> Json<Value> {
    if let Some(p) = body.get("path").and_then(Value::as_str) {
        open::that(p).ok();
    }
    Json(json!({ "status": "ok" }))
}

async fn api_reveal_file(Json(body): Json<Value>) -> Json<Value> {
    if let Some(p) = body.get("path").and_then(Value::as_str) {
        let arg = format!("/select,\"{}\"", p);
        std::process::Command::new("explorer").arg(arg).spawn().ok();
    }
    Json(json!({ "status": "ok" }))
}

#[derive(Deserialize)]
struct NfsListQuery {
    path: Option<String>,
}

async fn api_nfs_list(State(state): State<SharedState>, Query(q): Query<NfsListQuery>) -> Response {
    let rel_path = q.path.unwrap_or_else(|| "/sdcard".to_string());
    let target = state.nfs_target.lock().unwrap().clone();

    let target = match target {
        Some(t) => t,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "平板无线存储服务（NFS）尚未就绪或未完成握手" })),
            ).into_response();
        }
    };

    match list_directory(&state.identity, &target, &rel_path).await {
        Ok(entries) => Json(json!({ "entries": entries })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("获取目录失败: {:#}", e) })),
        ).into_response(),
    }
}

async fn api_nfs_download(State(state): State<SharedState>, Json(body): Json<Value>) -> Response {
    let remote_path = body.get("path").and_then(Value::as_str).unwrap_or("");
    if remote_path.is_empty() {
        return (StatusCode::BAD_REQUEST, "path required").into_response();
    }

    let target = state.nfs_target.lock().unwrap().clone();
    let target = match target {
        Some(t) => t,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "平板无线存储服务（NFS）尚未就绪" })),
            ).into_response();
        }
    };

    let file_name = remote_path.split('/').last().unwrap_or("file");
    let download_dir = state.settings.lock().unwrap().current.download_dir.clone();
    std::fs::create_dir_all(&download_dir).ok();
    let dest_path = Path::new(&download_dir).join(file_name);

    match download_nfs_file(&state.identity, &target, remote_path, &dest_path).await {
        Ok(sz) => {
            Json(json!({
                "status": "ok",
                "dest_path": dest_path.to_string_lossy(),
                "size": sz
            })).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("下载失败: {:#}", e) }))).into_response()
        }
    }
}

async fn api_show_window(State(state): State<SharedState>) -> Json<Value> {
    state.show_window_requested.store(true, Ordering::Relaxed);
    Json(json!({ "status": "ok" }))
}

async fn api_shutdown(State(state): State<SharedState>) -> Json<Value> {
    info!("Shutdown requested via API");
    state.shutdown_tx.send(()).ok();
    Json(json!({ "status": "shutting_down" }))
}
