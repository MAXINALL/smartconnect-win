use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::SinkExt;
use rand::RngCore;
use serde_json::{json, Value};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout};
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{self, ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info};

use crate::identity::{self, Identity};
use crate::invite::{VER_CODE, VER_NAME};
use crate::server::{get_local_ips, SharedState};

pub const MDNS_PATH: &str = "/readyfor/mdns";
const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const TYPE_ENCRYPTED: u8 = 1;
const HEADER_LEN: usize = 17;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub fn seal(key_b64: &str, sender_nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    ensure!(sender_nonce.len() == 16, "nonce id must be 16 bytes");
    let mut iv = [0u8; IV_LEN];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let mut frame = Vec::with_capacity(HEADER_LEN + IV_LEN + plaintext.len() + TAG_LEN);
    frame.extend_from_slice(sender_nonce);
    frame.push(TYPE_ENCRYPTED);
    let key = B64.decode(key_b64).context("per-pair key is not base64")?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("invalid AES-256 key length"))?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext, aad: &frame[..HEADER_LEN] })
        .map_err(|_| anyhow!("AES-GCM encrypt failed"))?;
    frame.extend_from_slice(&iv);
    frame.extend_from_slice(&ct);
    Ok(frame)
}

pub fn open(key_b64: &str, frame: &[u8]) -> Result<(Vec<u8>, u8, Vec<u8>)> {
    ensure!(frame.len() >= HEADER_LEN + IV_LEN + TAG_LEN, "discovery frame too short");
    let (nonce, kind) = (frame[..16].to_vec(), frame[16]);
    ensure!(kind == TYPE_ENCRYPTED, "unexpected discovery frame type {kind}");
    let iv = &frame[HEADER_LEN..HEADER_LEN + IV_LEN];
    let key = B64.decode(key_b64).context("per-pair key is not base64")?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("invalid AES-256 key length"))?;
    let pt = cipher
        .decrypt(Nonce::from_slice(iv), Payload { msg: &frame[HEADER_LEN + IV_LEN..], aad: &frame[..HEADER_LEN] })
        .map_err(|_| anyhow!("AES-GCM decrypt failed"))?;
    Ok((nonce, kind, pt))
}

pub fn invite_json(id: &Identity, token: &str, ips: &[IpAddr], ws_port: u16) -> Value {
    let ips_str: Vec<String> = ips.iter().map(ToString::to_string).collect();
    json!({
        "ver": 2,
        "cmd": 1,
        "deviceId": id.device_id,
        "deviceName": id.device_name,
        "fp": id.fp_base64(),
        "token": token,
        "policies": [{ "wifi": ips_str }],
        "wsPort": ws_port,
        "appVer": VER_NAME,
        "verCode": VER_CODE,
        "os": 6,
        "scType": 2,
        "type": 4,
    })
}

pub fn sealed_invite(state: &SharedState, key_b64: &str, ws_port: u16) -> Result<Vec<u8>> {
    let ips = get_local_ips();
    let token = state.current_token(ws_port);
    let invite = invite_json(&state.identity, &token, &ips, ws_port);
    let nonce = B64.decode(&state.identity.device_id)?;
    seal(key_b64, &nonce, invite.to_string().as_bytes())
}

pub async fn push_invite(addr: SocketAddr, our_nonce_b64: &str, key: &str, invite: &str) -> Result<()> {
    let frame = seal(key, &B64.decode(our_nonce_b64)?, invite.as_bytes())?;
    let tcp = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;
    let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::IpAddress(addr.ip().into()), tcp)
        .await?;
    let url = format!("wss://{addr}{MDNS_PATH}");
    let (mut ws, _) = timeout(Duration::from_secs(4), tokio_tungstenite::client_async(url, tls)).await??;
    ws.send(Message::Binary(frame.into())).await?;
    info!(%addr, "mdns: pushed encrypted cmd:1 invite to tablet");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let _ = ws.close(None).await;
    Ok(())
}

pub async fn dial_tablet(state: &SharedState, phone_id: &str, addr: SocketAddr, ws_port: u16) -> Result<()> {
    let keys: Vec<String> = {
        let p = state.pairing.lock().unwrap();
        let rec = p.get(phone_id).context("tablet not paired")?;
        let mut v = vec![rec.key.clone()];
        if let Some(pk) = &rec.phone_key {
            v.push(pk.clone());
        }
        v
    };
    let ips = get_local_ips();
    let token = state.current_token(ws_port);
    let invite = invite_json(&state.identity, &token, &ips, ws_port).to_string();

    let mut last_err = None;
    for k in keys {
        match push_invite(addr, &state.identity.device_id, &k, &invite).await {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no key available")))
}

/// Start Windows BLE Peripheral advertisement for 0x5246 so the tablet can also spot our PC over BLE.
pub fn start_ble_peripheral_advert(state: &SharedState) {
    use windows::Devices::Bluetooth::Advertisement::{
        BluetoothLEAdvertisement, BluetoothLEAdvertisementDataSection, BluetoothLEAdvertisementPublisher,
    };
    use windows::Storage::Streams::DataWriter;

    let Ok(raw_id) = B64.decode(state.identity.device_id.as_bytes()) else { return };
    if raw_id.len() != 16 {
        return;
    }

    let run = (|| -> Result<BluetoothLEAdvertisementPublisher> {
        let adv = BluetoothLEAdvertisement::new()?;
        let writer = DataWriter::new()?;
        // 0x16 (Service Data - 16-bit UUID): [0x46, 0x52] (0x5246 LE) + [0x10, 0x04, 0x00, 0x00] + 16B deviceId
        let mut payload = Vec::with_capacity(22);
        payload.extend_from_slice(&[0x46, 0x52, 0x10, 0x04, 0x00, 0x00]);
        payload.extend_from_slice(&raw_id);
        writer.WriteBytes(&payload)?;
        let buffer = writer.DetachBuffer()?;
        let section = BluetoothLEAdvertisementDataSection::Create(0x16, &buffer)?;
        adv.DataSections()?.Append(&section)?;
        let publisher = BluetoothLEAdvertisementPublisher::Create(&adv)?;
        publisher.Start()?;
        Ok(publisher)
    })();

    match run {
        Ok(pub_handle) => {
            info!("BLE peripheral advertising 0x5246 active");
            // Keep publisher alive in a background thread
            std::thread::spawn(move || {
                let _keep = pub_handle;
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            });
        }
        Err(e) => {
            debug!("BLE peripheral advertisement not started: {e:#}");
        }
    }
}

/// Wake a backgrounded tablet over Bluetooth LE GATT (service 0x5246 -> write sealed invite to char 0x0722).
pub async fn ble_wake_paired_tablet(state: &SharedState, ws_port: u16) -> Result<String> {
    let state_clone = state.clone();
    tokio::task::spawn_blocking(move || ble_wake_blocking(&state_clone, ws_port))
        .await
        .context("BLE wake task panicked")?
}

fn ble_wake_blocking(state: &SharedState, ws_port: u16) -> Result<String> {
    use windows::core::GUID;
    use windows::Devices::Bluetooth::Advertisement::{
        BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher, BluetoothLEScanningMode,
    };
    use windows::Devices::Bluetooth::GenericAttributeProfile::{
        GattCharacteristic, GattClientCharacteristicConfigurationDescriptorValue, GattCommunicationStatus, GattSession,
    };
    use windows::Devices::Bluetooth::{BluetoothCacheMode, BluetoothLEDevice};
    use windows::Foundation::TypedEventHandler;
    use windows::Storage::Streams::{DataReader, DataWriter};

    let paired_list: Vec<(String, String)> = {
        let p = state.pairing.lock().unwrap();
        p.iter()
            .map(|(real_id, rec)| (real_id.clone(), rec.key.clone()))
            .collect()
    };
    if paired_list.is_empty() {
        bail!("no paired tablet in paired.json");
    }

    let found: Arc<Mutex<Option<(u64, String, String)>>> = Arc::new(Mutex::new(None));
    let found_cb = found.clone();

    let watcher = BluetoothLEAdvertisementWatcher::new().context("creating BLE watcher")?;
    watcher.SetScanningMode(BluetoothLEScanningMode::Active).ok();

    let handler = TypedEventHandler::<BluetoothLEAdvertisementWatcher, BluetoothLEAdvertisementReceivedEventArgs>::new(
        move |_sender, args| {
            let Some(args) = args.as_ref() else { return Ok(()) };
            if found_cb.lock().unwrap().is_some() {
                return Ok(());
            }
            let Ok(bt_addr) = args.BluetoothAddress() else { return Ok(()) };
            let Ok(adv) = args.Advertisement() else { return Ok(()) };
            let Ok(sections) = adv.DataSections() else { return Ok(()) };
            let count = sections.Size().unwrap_or(0);
            for i in 0..count {
                let Ok(sec) = sections.GetAt(i) else { continue };
                let Ok(buf) = sec.Data() else { continue };
                let len = buf.Length().unwrap_or(0) as usize;
                if len < 16 {
                    continue;
                }
                let Ok(reader) = DataReader::FromBuffer(&buf) else { continue };
                let mut bytes = vec![0u8; len];
                if reader.ReadBytes(&mut bytes).is_err() {
                    continue;
                }
                let nonce = &bytes[len - 16..];
                for (real_id, key) in &paired_list {
                    if identity::is_nonce_of(nonce, real_id) {
                        *found_cb.lock().unwrap() = Some((bt_addr, real_id.clone(), key.clone()));
                        return Ok(());
                    }
                }
            }
            Ok(())
        },
    );

    let token = watcher.Received(&handler)?;
    watcher.Start().context("starting BLE scan (is Bluetooth turned on?)")?;
    info!("ble: scanning for paired tablet 0x5246 advert...");

    let start = std::time::Instant::now();
    let mut target = None;
    while start.elapsed() < Duration::from_secs(12) {
        if state.connected.load(Ordering::Relaxed) {
            let _ = watcher.Stop();
            let _ = watcher.RemoveReceived(token);
            return Ok("already connected".into());
        }
        if let Some(t) = found.lock().unwrap().clone() {
            target = Some(t);
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    let _ = watcher.Stop();
    let _ = watcher.RemoveReceived(token);

    let Some((bt_addr, real_id, key)) = target else {
        bail!("未在蓝牙广播中发现已配对平板（请确认电脑与平板蓝牙已开启）");
    };

    info!(bt_addr = format!("0x{:x}", bt_addr), phone = %real_id, "ble: found paired tablet; connecting GATT 0x5246");
    let frame = sealed_invite(state, &key, ws_port)?;

    let svc_uuid = GUID::from_u128(0x00005246_0000_1000_8000_00805f9b34fb);
    let chr_invite_uuid = GUID::from_u128(0x00000722_0000_1000_8000_00805f9b34fb);
    let chr_notify_uuid = GUID::from_u128(0x00000726_0000_1000_8000_00805f9b34fb);

    let mut dev = BluetoothLEDevice::FromBluetoothAddressAsync(bt_addr)?.get()?;
    // If Windows holds a stale OS-level LE bond on this rotating address, unpair it first so L2CAP doesn't drop on SMP Encryption Request
    if let Ok(di) = dev.DeviceInformation() {
        if let Ok(pairing) = di.Pairing() {
            if pairing.IsPaired().unwrap_or(false) {
                info!(bt_addr = format!("0x{:x}", bt_addr), "ble: clearing stale OS LE bond before GATT wake");
                let _ = pairing.UnpairAsync().and_then(|op| op.get());
                let _ = dev.Close();
                std::thread::sleep(Duration::from_millis(400));
                dev = BluetoothLEDevice::FromBluetoothAddressAsync(bt_addr)?.get()?;
            }
        }
    }
    let gatt_session = dev
        .BluetoothDeviceId()
        .ok()
        .and_then(|id| GattSession::FromDeviceIdAsync(&id).ok())
        .and_then(|op| op.get().ok());
    if let Some(sess) = &gatt_session {
        let _ = sess.SetMaintainConnection(true);
    }

    let mut target_svc = None;
    let mut last_status = GattCommunicationStatus::Unreachable;
    let mut last_count = 0;

    for try_idx in 0..3 {
        let mode = if try_idx == 0 {
            BluetoothCacheMode::Uncached
        } else {
            BluetoothCacheMode::Cached
        };
        if let Ok(op) = dev.GetGattServicesWithCacheModeAsync(mode) {
            if let Ok(svcs_res) = op.get() {
                last_status = svcs_res.Status().unwrap_or(GattCommunicationStatus::Unreachable);
                if let Ok(svcs) = svcs_res.Services() {
                    last_count = svcs.Size().unwrap_or(0);
                    info!(try_idx, ?last_status, count = last_count, "ble: enumerated GATT services");
                    for i in 0..last_count {
                        if let Ok(s) = svcs.GetAt(i) {
                            if let Ok(u) = s.Uuid() {
                                let u_str = format!("{u:?}").to_ascii_lowercase();
                                if u == svc_uuid || u_str.contains("00005246") {
                                    target_svc = Some(s);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        if target_svc.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(600));
    }

    let Some(service) = target_svc else {
        if let Some(sess) = &gatt_session {
            let _ = sess.SetMaintainConnection(false);
            let _ = sess.Close();
        }
        let _ = dev.Close();
        bail!("tablet has no 0x5246 GATT service (status={:?}, count={})", last_status, last_count);
    };

    let mut invite_chr: Option<GattCharacteristic> = None;
    let mut notify_chr: Option<GattCharacteristic> = None;
    for c_try in 0..3 {
        let mode = if c_try == 0 {
            BluetoothCacheMode::Cached
        } else {
            BluetoothCacheMode::Uncached
        };
        if let Ok(op) = service.GetCharacteristicsWithCacheModeAsync(mode) {
            if let Ok(chrs_res) = op.get() {
                if let Ok(chrs) = chrs_res.Characteristics() {
                    let count = chrs.Size().unwrap_or(0);
                    info!(c_try, count, "ble: enumerated 0x5246 characteristics");
                    for i in 0..count {
                        if let Ok(c) = chrs.GetAt(i) {
                            if let Ok(u) = c.Uuid() {
                                let u_str = format!("{u:?}").to_ascii_lowercase();
                                if u == chr_invite_uuid || u_str.contains("00000722") {
                                    invite_chr = Some(c);
                                } else if u == chr_notify_uuid || u_str.contains("00000726") {
                                    notify_chr = Some(c);
                                }
                            }
                        }
                    }
                }
            }
        }
        if invite_chr.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(400));
    }

    let Some(invite_chr) = invite_chr else {
        if let Some(sess) = &gatt_session {
            let _ = sess.SetMaintainConnection(false);
            let _ = sess.Close();
        }
        let _ = service.Close();
        let _ = dev.Close();
        bail!("characteristic 0x0722 missing on tablet");
    };

    // Subscribe CCCD before writing (0x0722 = Indicate, 0x0726 = Notify)
    let _ = invite_chr
        .WriteClientCharacteristicConfigurationDescriptorAsync(
            GattClientCharacteristicConfigurationDescriptorValue::Indicate,
        )
        .and_then(|op| op.get());
    if let Some(nc) = &notify_chr {
        let _ = nc
            .WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue::Notify,
            )
            .and_then(|op| op.get());
    }

    let writer = DataWriter::new()?;
    writer.WriteBytes(&frame)?;
    let ibuf = writer.DetachBuffer()?;
    let write_res = invite_chr.WriteValueWithResultAsync(&ibuf)?.get()?;
    let status = write_res.Status()?;
    info!(?status, bytes = frame.len(), "ble: wrote sealed invite to 0x0722");

    if status != GattCommunicationStatus::Success {
        if let Some(sess) = &gatt_session {
            let _ = sess.SetMaintainConnection(false);
            let _ = sess.Close();
        }
        let _ = service.Close();
        let _ = dev.Close();
        bail!("GATT write to 0x0722 failed with status {:?}", status);
    }

    // Wait up to 8 seconds for tablet to dial our TLS WebSocket
    let wait_start = std::time::Instant::now();
    while wait_start.elapsed() < Duration::from_secs(8) && !state.connected.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
    }

    if let Some(sess) = &gatt_session {
        let _ = sess.SetMaintainConnection(false);
        let _ = sess.Close();
    }
    let _ = service.Close();
    let _ = dev.Close();

    if state.connected.load(Ordering::Relaxed) {
        Ok("已通过蓝牙唤醒并重连平板".into())
    } else {
        Ok("已通过蓝牙发送唤醒邀请，正在等待平板连接...".into())
    }
}

/// Pure Rust UDP 5353 mDNS advertiser & browser for `_readyformdns._tcp.local.`
pub async fn run_mdns_service(state: SharedState, ws_port: u16) -> Result<()> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT)))?;

    let _ = sock.join_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED);
    for ip in get_local_ips() {
        if let IpAddr::V4(v4) = ip {
            let _ = sock.join_multicast_v4(&MDNS_ADDR, &v4);
            let _ = sock.set_multicast_if_v4(&v4);
        }
    }

    let udp = Arc::new(UdpSocket::from_std(sock.into())?);
    let mcast_dest = SocketAddr::V4(SocketAddrV4::new(MDNS_ADDR, MDNS_PORT));

    // Send initial query + announce
    let query_pkt = build_mdns_ptr_query("_readyformdns._tcp.local");
    let _ = udp.send_to(&query_pkt, mcast_dest).await;
    if let Some(ann) = build_mdns_announce(&state.identity, ws_port) {
        let _ = udp.send_to(&ann, mcast_dest).await;
    }

    let udp_periodic = udp.clone();
    let state_periodic = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(12));
        loop {
            interval.tick().await;
            if !state_periodic.connected.load(Ordering::Relaxed) {
                let q = build_mdns_ptr_query("_readyformdns._tcp.local");
                let _ = udp_periodic.send_to(&q, mcast_dest).await;
                if let Some(ann) = build_mdns_announce(&state_periodic.identity, ws_port) {
                    let _ = udp_periodic.send_to(&ann, mcast_dest).await;
                }
            }
        }
    });

    let mut buf = [0u8; 4096];
    loop {
        let (n, peer) = match udp.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let pkt = &buf[..n];
        if pkt.len() < 12 {
            continue;
        }

        // Check if this packet mentions _readyformdns
        if !contains_subslice(pkt, b"_readyformdns") {
            continue;
        }

        let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
        let is_response = (flags & 0x8000) != 0;

        if !is_response {
            // Someone (the tablet!) queried _readyformdns._tcp.local -> immediately unicast & multicast our announce
            if let Some(ann) = build_mdns_announce(&state.identity, ws_port) {
                let _ = udp.send_to(&ann, peer).await;
                let _ = udp.send_to(&ann, mcast_dest).await;
            }
            continue;
        }

        // It's an mDNS response containing _readyformdns! Parse SRV port and TXT deviceId
        if let Some((srv_port, txt_dev_id)) = parse_mdns_readyfor_response(pkt) {
            if srv_port == ws_port && get_local_ips().contains(&peer.ip()) {
                continue; // Ignore our own reflection
            }

            let matched_phone = {
                let p = state.pairing.lock().unwrap();
                if let Some(dev_b64) = &txt_dev_id {
                    if let Ok(nonce) = B64.decode(dev_b64) {
                        p.iter()
                            .find(|(real_id, _)| identity::is_nonce_of(&nonce, real_id))
                            .map(|(real_id, _)| real_id.clone())
                    } else {
                        None
                    }
                } else {
                    // Match by known IP or first paired device
                    p.iter()
                        .find(|(_, rec)| rec.last_ip.as_deref() == Some(&peer.ip().to_string()))
                        .or_else(|| p.first())
                        .map(|(real_id, _)| real_id.clone())
                }
            };

            if let Some(phone_id) = matched_phone {
                let addr = SocketAddr::new(peer.ip(), srv_port);
                state
                    .pairing
                    .lock()
                    .unwrap()
                    .update_mdns_endpoint(&phone_id, &peer.ip().to_string(), srv_port)
                    .ok();
                *state.tablet_mdns_addr.lock().unwrap() = Some((phone_id.clone(), addr));

                if !state.connected.load(Ordering::Relaxed) {
                    info!(%addr, %phone_id, "mdns: spotted paired tablet advert; dialing back now");
                    let st = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = dial_tablet(&st, &phone_id, addr, ws_port).await {
                            debug!(%addr, "mdns dial-back error: {e:#}");
                        }
                    });
                }
            }
        }
    }
}

/// Immediate reconnect attempt (Wi-Fi `/readyfor/mdns` first, then BLE GATT 0x5246 wake).
pub async fn connect_now(state: &SharedState, ws_port: u16) -> (bool, String) {
    let _guard = state.connect_lock.lock().await;
    if state.connected.load(Ordering::Relaxed) {
        return (true, "已连接".into());
    }

    let paired_info = {
        let p = state.pairing.lock().unwrap();
        p.first().map(|(id, rec)| (id.clone(), rec.clone()))
    };
    let Some((phone_id, rec)) = paired_info else {
        return (false, "尚无已配对平板，请先扫码配对一次".into());
    };

    state.reconnecting.store(true, Ordering::Relaxed);

    // 1. Send active mDNS query first in case the tablet app is open in foreground
    if let Ok(udp) = UdpSocket::bind("0.0.0.0:0").await {
        let q = build_mdns_ptr_query("_readyformdns._tcp.local");
        let mcast = SocketAddr::V4(SocketAddrV4::new(MDNS_ADDR, MDNS_PORT));
        let _ = udp.send_to(&q, mcast).await;
        if let Some(ip_str) = &rec.last_ip {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let _ = udp.send_to(&q, SocketAddr::new(ip, MDNS_PORT)).await;
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(350)).await;
    if state.connected.load(Ordering::Relaxed) {
        state.reconnecting.store(false, Ordering::Relaxed);
        return (true, "已通过局域网重连平板".into());
    }

    // 2. Try known /readyfor/mdns endpoint if we have one
    let mut candidate_addrs = Vec::new();
    if let Some((_, addr)) = *state.tablet_mdns_addr.lock().unwrap() {
        candidate_addrs.push(addr);
    }
    if let (Some(ip_str), Some(port)) = (&rec.last_ip, rec.last_mdns_port) {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            let a = SocketAddr::new(ip, port);
            if !candidate_addrs.contains(&a) {
                candidate_addrs.push(a);
            }
        }
    }

    for addr in candidate_addrs {
        if dial_tablet(state, &phone_id, addr, ws_port).await.is_ok() {
            let until = Instant::now() + Duration::from_secs(3);
            while Instant::now() < until && !state.connected.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            if state.connected.load(Ordering::Relaxed) {
                state.reconnecting.store(false, Ordering::Relaxed);
                return (true, "已通过 Wi-Fi 自动重连平板".into());
            }
        }
    }

    // 3. Wake over Bluetooth LE GATT (0x5246 -> 0x0722) when tablet app is in background
    match ble_wake_paired_tablet(state, ws_port).await {
        Ok(msg) => {
            state.reconnecting.store(false, Ordering::Relaxed);
            (state.connected.load(Ordering::Relaxed), msg)
        }
        Err(e) => {
            state.reconnecting.store(false, Ordering::Relaxed);
            (false, format!("{e}"))
        }
    }
}

/// Background auto-reconnect loop (runs on startup and whenever connection drops).
pub async fn run_auto_reconnect_loop(state: SharedState, ws_port: u16) {
    const BACKOFF_S: [u64; 6] = [1, 4, 10, 20, 45, 120];
    let mut attempt = 0usize;

    loop {
        if state.connected.load(Ordering::Relaxed) || state.pairing.lock().unwrap().is_empty() {
            attempt = 0;
            state.reconnect_nudge.notified().await;
            continue;
        }

        let wait_secs = BACKOFF_S[attempt.min(BACKOFF_S.len() - 1)];
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(wait_secs)) => {}
            _ = state.reconnect_nudge.notified() => {
                attempt = 0;
            }
        }

        if state.connected.load(Ordering::Relaxed) || state.pairing.lock().unwrap().is_empty() {
            continue;
        }

        let (ok, msg) = connect_now(&state, ws_port).await;
        info!(attempt, ok, "auto-reconnect: {msg}");
        if ok || state.connected.load(Ordering::Relaxed) {
            attempt = 0;
        } else {
            attempt += 1;
        }
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

fn encode_dns_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let b = label.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0);
}

fn build_mdns_ptr_query(service: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    encode_dns_name(&mut pkt, service);
    pkt.extend_from_slice(&12u16.to_be_bytes()); // PTR
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
    pkt
}

fn build_mdns_announce(id: &Identity, port: u16) -> Option<Vec<u8>> {
    let ip = get_local_ips().into_iter().find_map(|i| match i {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    })?;

    let svc_type = "_readyformdns._tcp.local";
    let instance = format!("{}._readyformdns._tcp.local", id.device_name);
    let host = format!("{}.local", id.device_name);
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let txt_items = [
        format!("deviceId={}", id.device_id),
        format!("deviceName={}", id.device_name),
        "appType=1".to_string(),
        "type=4".to_string(),
        "os=6".to_string(),
        "cap=0".to_string(),
        format!("timestamp={ts}"),
        format!("fp={}", id.fp_hex()),
    ];

    let mut pkt = Vec::with_capacity(512);
    // Header: QR=1, AA=1 (0x8400), ANCOUNT=4
    pkt.extend_from_slice(&[0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);

    // 1. PTR record
    encode_dns_name(&mut pkt, svc_type);
    pkt.extend_from_slice(&12u16.to_be_bytes()); // PTR
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
    pkt.extend_from_slice(&120u32.to_be_bytes()); // TTL
    let mut ptr_rdata = Vec::new();
    encode_dns_name(&mut ptr_rdata, &instance);
    pkt.extend_from_slice(&(ptr_rdata.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&ptr_rdata);

    // 2. SRV record
    encode_dns_name(&mut pkt, &instance);
    pkt.extend_from_slice(&33u16.to_be_bytes()); // SRV
    pkt.extend_from_slice(&0x8001u16.to_be_bytes()); // IN + cache flush
    pkt.extend_from_slice(&120u32.to_be_bytes());
    let mut srv_rdata = Vec::new();
    srv_rdata.extend_from_slice(&0u16.to_be_bytes()); // priority
    srv_rdata.extend_from_slice(&0u16.to_be_bytes()); // weight
    srv_rdata.extend_from_slice(&port.to_be_bytes());
    encode_dns_name(&mut srv_rdata, &host);
    pkt.extend_from_slice(&(srv_rdata.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&srv_rdata);

    // 3. TXT record
    encode_dns_name(&mut pkt, &instance);
    pkt.extend_from_slice(&16u16.to_be_bytes()); // TXT
    pkt.extend_from_slice(&0x8001u16.to_be_bytes());
    pkt.extend_from_slice(&120u32.to_be_bytes());
    let mut txt_rdata = Vec::new();
    for item in &txt_items {
        let b = item.as_bytes();
        if b.len() <= 255 {
            txt_rdata.push(b.len() as u8);
            txt_rdata.extend_from_slice(b);
        }
    }
    pkt.extend_from_slice(&(txt_rdata.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&txt_rdata);

    // 4. A record
    encode_dns_name(&mut pkt, &host);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // A
    pkt.extend_from_slice(&0x8001u16.to_be_bytes());
    pkt.extend_from_slice(&120u32.to_be_bytes());
    pkt.extend_from_slice(&4u16.to_be_bytes());
    pkt.extend_from_slice(&ip.octets());

    Some(pkt)
}

fn skip_dns_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        if pos >= pkt.len() || jumps > 32 {
            return None;
        }
        let len = pkt[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            return if pos + 1 < pkt.len() { Some(pos + 2) } else { None };
        }
        pos += 1 + (len as usize);
        jumps += 1;
    }
}

fn parse_mdns_readyfor_response(pkt: &[u8]) -> Option<(u16, Option<String>)> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let nscount = u16::from_be_bytes([pkt[8], pkt[9]]) as usize;
    let arcount = u16::from_be_bytes([pkt[10], pkt[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(pkt, pos)?;
        pos += 4;
        if pos > pkt.len() {
            return None;
        }
    }

    let total_rr = ancount + nscount + arcount;
    let mut srv_port: Option<u16> = None;
    let mut device_id: Option<String> = None;

    for _ in 0..total_rr {
        if pos >= pkt.len() {
            break;
        }
        pos = skip_dns_name(pkt, pos)?;
        if pos + 10 > pkt.len() {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let rdlen = u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > pkt.len() {
            break;
        }
        let rdata = &pkt[pos..pos + rdlen];
        if rtype == 33 && rdlen >= 6 {
            // SRV: priority(2), weight(2), port(2), target(...)
            let p = u16::from_be_bytes([rdata[4], rdata[5]]);
            if p != 0 {
                srv_port = Some(p);
            }
        } else if rtype == 16 {
            // TXT
            let mut tpos = 0;
            while tpos < rdata.len() {
                let tlen = rdata[tpos] as usize;
                tpos += 1;
                if tpos + tlen > rdata.len() {
                    break;
                }
                if let Ok(s) = std::str::from_utf8(&rdata[tpos..tpos + tlen]) {
                    if let Some(id) = s.strip_prefix("deviceId=") {
                        device_id = Some(id.to_string());
                    }
                }
                tpos += tlen;
            }
        }
        pos += rdlen;
    }

    srv_port.map(|p| (p, device_id))
}

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
