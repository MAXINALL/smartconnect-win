use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, warn};

use crate::server::SharedState;

const OFFER_TTL: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(3600);

const EOCD_SIG: u32 = 0x0605_4b50;
const CDH_SIG: u32 = 0x0201_4b50;
const LFH_SIG: u32 = 0x0403_4b50;
const DD_SIG: u32 = 0x0807_4b50;
const FLAG_STREAM_UTF8: u16 = (1 << 11) | (1 << 3); // UTF-8 + Data Descriptor (bit 3)
const METHOD_STORE: u16 = 0;
const DOS_DATE: u16 = (1 << 5) | 1;

const CRC32_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    crc = !crc;
    for &b in data {
        crc = CRC32_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

fn fresh_id(len: usize) -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let digest = sha2::Sha256::digest(format!("{t}-{n}-{}", std::process::id()));
    hex::encode(digest)[..len].to_owned()
}

#[derive(Debug, Clone)]
pub struct DiskFile {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    pub id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub file_name: String,
    pub file_count: u64,
    pub mime_type: String,
    pub total_size: u64,
    #[serde(rename = "file")]
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub name: String,
    pub mime_type: String,
    pub size: u64,
    pub dir: bool,
    pub index: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatusFrame {
    pub task_id: String,
    #[serde(rename = "type")]
    pub kind: i64,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug)]
pub struct StreamOffer {
    pub task_id: String,
    pub token: String,
    pub files: Vec<DiskFile>,
    pub total_zip_size: u64,
    pub request: SendRequest,
    created: Instant,
    claimed: Mutex<bool>,
    pub finished: AtomicBool,
}

#[derive(Debug, Default)]
pub struct StreamRegistry {
    offers: Mutex<Vec<Arc<StreamOffer>>>,
}

impl StreamRegistry {
    /// Creates a streaming ZIP offer from one or more files on disk in O(1) time and memory
    /// without reading file contents upfront.
    pub fn offer_files(&self, files: Vec<DiskFile>, sender_id: &str, sender_name: &str) -> Arc<StreamOffer> {
        let task_id = fresh_id(32);
        let token = fresh_id(16);

        // Compute exact byte size of the streaming Stored ZIP:
        // Each entry: Local Header (30 + name_len) + raw file bytes + Data Descriptor (16) + Central Header (46 + name_len)
        // Plus EOCD (22 bytes)
        let mut total_zip_size: u64 = 22;
        for f in &files {
            let nlen = f.name.len() as u64;
            total_zip_size += 30 + nlen + f.size + 16 + 46 + nlen;
        }

        let entries: Vec<FileEntry> = files
            .iter()
            .enumerate()
            .map(|(i, f)| FileEntry {
                name: f.name.clone(),
                mime_type: "application/octet-stream".to_string(),
                size: f.size,
                dir: false,
                index: i as i64,
            })
            .collect();

        let request = SendRequest {
            id: task_id.clone(),
            sender_id: sender_id.to_owned(),
            sender_name: sender_name.to_owned(),
            file_name: files.first().map(|f| f.name.clone()).unwrap_or_default(),
            file_count: files.len() as u64,
            mime_type: if files.len() == 1 {
                "application/octet-stream".to_owned()
            } else {
                "*/*".to_owned()
            },
            total_size: total_zip_size,
            files: entries,
        };

        let offer = Arc::new(StreamOffer {
            task_id,
            token,
            files,
            total_zip_size,
            request,
            created: Instant::now(),
            claimed: Mutex::new(false),
            finished: AtomicBool::new(false),
        });

        let mut guard = self.offers.lock().unwrap();
        guard.retain(|o| o.created.elapsed() < OFFER_TTL);
        guard.push(offer.clone());
        offer
    }

    fn claim_newest(&self) -> Option<Arc<StreamOffer>> {
        let guard = self.offers.lock().unwrap();
        guard
            .iter()
            .rev()
            .filter(|o| o.created.elapsed() < OFFER_TTL)
            .find(|o| {
                let mut claimed = o.claimed.lock().unwrap();
                !std::mem::replace(&mut *claimed, true)
            })
            .cloned()
    }

    pub fn find(&self, task_id: &str) -> Option<Arc<StreamOffer>> {
        self.offers.lock().unwrap().iter().find(|o| o.task_id == task_id).cloned()
    }

    pub fn remove(&self, task_id: &str) {
        self.offers.lock().unwrap().retain(|o| o.task_id != task_id);
    }
}

fn update_transfer_status(state: &SharedState, task_id: &str, new_status: &str) {
    let mut tr = state.transfers.lock().unwrap();
    if let Some(item) = tr.iter_mut().find(|i| i.id == task_id) {
        item.status = new_status.to_string();
    }
}

/// Streams `GET /download?taskId=...` directly from disk in 64 KB chunks with O(1) memory.
pub async fn stream_download<S>(state: &SharedState, mut stream: S, target: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let task_id = target
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or_default()
        .split('&')
        .find_map(|kv| kv.strip_prefix("taskId="))
        .unwrap_or_default();

    let Some(offer) = state.fex_registry.find(task_id) else {
        let body = format!("download -> taskId {task_id} does not exist!");
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.shutdown().await.ok();
        return Ok(());
    };

    info!(task = %offer.task_id, total_bytes = offer.total_zip_size, "fex_stream: streaming offer from disk");

    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\nAccept-Ranges: none\r\nConnection: close\r\n\r\n",
        offer.total_zip_size
    );
    stream.write_all(header.as_bytes()).await?;

    let mut central_dir = Vec::new();
    let mut offset: u64 = 0;
    let mut total_sent: u64 = 0;
    let total_raw: u64 = offer.files.iter().map(|f| f.size).sum::<u64>().max(1);
    let mut buf = vec![0u8; 64 * 1024];
    let mut last_pct_update = Instant::now();

    for f in &offer.files {
        let name_bytes = f.name.as_bytes();
        let name_len = name_bytes.len() as u16;
        let local_offset = offset as u32;

        // 1. Write 30-byte Local File Header + filename (flags = 0x0808, crc/sizes = 0)
        let mut lfh = Vec::with_capacity(30 + name_bytes.len());
        lfh.extend_from_slice(&LFH_SIG.to_le_bytes());
        lfh.extend_from_slice(&20u16.to_le_bytes());
        lfh.extend_from_slice(&FLAG_STREAM_UTF8.to_le_bytes());
        lfh.extend_from_slice(&METHOD_STORE.to_le_bytes());
        lfh.extend_from_slice(&0u16.to_le_bytes()); // time
        lfh.extend_from_slice(&DOS_DATE.to_le_bytes()); // date
        lfh.extend_from_slice(&[0u8; 12]); // crc32, csize, usize in Data Descriptor
        lfh.extend_from_slice(&name_len.to_le_bytes());
        lfh.extend_from_slice(&0u16.to_le_bytes()); // extra len
        lfh.extend_from_slice(name_bytes);

        stream.write_all(&lfh).await?;
        offset += lfh.len() as u64;

        // 2. Stream file bytes from disk in 64 KB chunks while computing CRC32
        let mut file = tokio::fs::File::open(&f.path)
            .await
            .with_context(|| format!("opening {:?}", f.path))?;
        let mut crc = 0u32;
        let mut remaining = f.size;

        while remaining > 0 {
            if offer.finished.load(Ordering::SeqCst) {
                bail!("transfer already finished or cancelled");
            }
            let to_read = (remaining as usize).min(buf.len());
            let n = file.read(&mut buf[..to_read]).await?;
            if n == 0 {
                break;
            }
            crc = crc32_update(crc, &buf[..n]);
            if let Err(e) = stream.write_all(&buf[..n]).await {
                if total_sent > 512 * 1024 && !offer.finished.load(Ordering::SeqCst) {
                    update_transfer_status(state, &offer.task_id, "发送失败 / 已取消");
                }
                return Err(e.into());
            }
            remaining -= n as u64;
            offset += n as u64;
            total_sent += n as u64;

            if last_pct_update.elapsed() >= Duration::from_millis(250) && !offer.finished.load(Ordering::SeqCst) {
                let pct = ((total_sent as f64 / total_raw as f64) * 100.0).clamp(1.0, 99.0);
                update_transfer_status(state, &offer.task_id, &format!("发送中 {:.0}%", pct));
                last_pct_update = Instant::now();
            }
        }
        // Pad with zeros if file shrank on disk while streaming
        while remaining > 0 {
            let pad = (remaining as usize).min(buf.len());
            buf[..pad].fill(0);
            crc = crc32_update(crc, &buf[..pad]);
            stream.write_all(&buf[..pad]).await?;
            remaining -= pad as u64;
            offset += pad as u64;
        }

        // 3. Write 16-byte Data Descriptor
        let size_u32 = f.size as u32;
        let mut dd = [0u8; 16];
        dd[0..4].copy_from_slice(&DD_SIG.to_le_bytes());
        dd[4..8].copy_from_slice(&crc.to_le_bytes());
        dd[8..12].copy_from_slice(&size_u32.to_le_bytes());
        dd[12..16].copy_from_slice(&size_u32.to_le_bytes());
        stream.write_all(&dd).await?;
        offset += 16;

        // 4. Append Central Directory Header for this file
        central_dir.extend_from_slice(&CDH_SIG.to_le_bytes());
        central_dir.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central_dir.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central_dir.extend_from_slice(&FLAG_STREAM_UTF8.to_le_bytes());
        central_dir.extend_from_slice(&METHOD_STORE.to_le_bytes());
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // time
        central_dir.extend_from_slice(&DOS_DATE.to_le_bytes()); // date
        central_dir.extend_from_slice(&crc.to_le_bytes());
        central_dir.extend_from_slice(&size_u32.to_le_bytes());
        central_dir.extend_from_slice(&size_u32.to_le_bytes());
        central_dir.extend_from_slice(&name_len.to_le_bytes());
        central_dir.extend_from_slice(&[0u8; 12]); // extra, comment, disk, int/ext attr
        central_dir.extend_from_slice(&local_offset.to_le_bytes());
        central_dir.extend_from_slice(name_bytes);
    }

    // 5. Write Central Directory + 22-byte EOCD
    let cd_offset = offset as u32;
    let cd_size = central_dir.len() as u32;
    let count = offer.files.len() as u16;

    central_dir.extend_from_slice(&EOCD_SIG.to_le_bytes());
    central_dir.extend_from_slice(&[0u8; 4]);
    central_dir.extend_from_slice(&count.to_le_bytes());
    central_dir.extend_from_slice(&count.to_le_bytes());
    central_dir.extend_from_slice(&cd_size.to_le_bytes());
    central_dir.extend_from_slice(&cd_offset.to_le_bytes());
    central_dir.extend_from_slice(&0u16.to_le_bytes());

    stream.write_all(&central_dir).await?;
    stream.flush().await?;
    stream.shutdown().await.ok();

    if !offer.finished.load(Ordering::SeqCst) {
        update_transfer_status(state, &offer.task_id, "发送中 99%");
    }
    Ok(())
}

/// Runs the FEX control WebSocket (`/websocket`) and updates the transfer status in `SharedState`
/// based on the tablet's real status report (or cancellation/disconnect).
pub async fn serve_control_websocket<S>(state: &SharedState, mut ws: WebSocketStream<S>) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(offer) = state.fex_registry.claim_newest() else {
        let _ = ws.close(None).await;
        bail!("fex WebSocket arrived with no active offer");
    };

    let task_id = offer.task_id.clone();
    if !offer.finished.load(Ordering::SeqCst) {
        update_transfer_status(state, &task_id, "平板已连接，准备发送...");
    }

    let res = run_exchange(state, &mut ws, &offer).await;
    offer.finished.store(true, Ordering::SeqCst);
    let _ = ws.close(None).await;
    state.fex_registry.remove(&task_id);

    match &res {
        Ok(true) => {
            info!(task = %task_id, "fex_stream: tablet confirmed transfer complete");
            update_transfer_status(state, &task_id, "已发送");
        }
        Ok(false) => {
            warn!(task = %task_id, "fex_stream: tablet reported transfer cancelled/failed");
            update_transfer_status(state, &task_id, "发送失败 / 平板已取消");
        }
        Err(e) => {
            warn!(task = %task_id, "fex_stream: transfer interrupted: {e:#}");
            update_transfer_status(state, &task_id, "发送失败 / 已中断");
        }
    }

    res
}

async fn run_exchange<S>(state: &SharedState, ws: &mut WebSocketStream<S>, offer: &StreamOffer) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ver_json = r#"{"version":1}"#;
    ws.send(Message::text(format!("action:Server1001:versionNegotiation?{ver_json}"))).await?;
    tokio::time::timeout(STEP_TIMEOUT, wait_ack(ws, "Server1001", ver_json))
        .await
        .context("versionNegotiation ack timeout")??;

    let req_json = serde_json::to_string(&offer.request)?;
    ws.send(Message::text(format!("action:Server1002:sendRequest?{req_json}"))).await?;
    tokio::time::timeout(STEP_TIMEOUT, wait_ack(ws, "Server1002", ver_json))
        .await
        .context("sendRequest ack timeout")??;

    info!(task = %offer.task_id, bytes = offer.total_zip_size, "fex_stream: tablet accepted offer");
    if !offer.finished.load(Ordering::SeqCst) {
        update_transfer_status(state, &offer.task_id, "正在发送...");
    }

    tokio::time::timeout(TRANSFER_TIMEOUT, async {
        loop {
            let text = next_text_frame(ws).await?;
            debug!("fex_stream <- {}", text);
            if let Some(rest) = text.strip_prefix("action:") {
                let (id, name_and_payload) = rest.split_once(':').unwrap_or(("", ""));
                let (name, payload) = name_and_payload
                    .split_once('?')
                    .map(|(n, p)| (n, Some(p)))
                    .unwrap_or((name_and_payload, None));

                if name == "status" {
                    ws.send(Message::text(format!("ack:{id}:status"))).await?;
                    if let Some(p) = payload {
                        if let Ok(st) = serde_json::from_str::<StatusFrame>(p) {
                            if st.kind == 0 {
                                // STATUS_STARTED
                                continue;
                            }
                            return Ok(st.kind == 1);
                        }
                    }
                } else if name == "versionNegotiation" {
                    ws.send(Message::text(format!("ack:{id}:versionNegotiation?{ver_json}"))).await?;
                }
            }
        }
    })
    .await
    .context("transfer status timeout")?
}

async fn wait_ack<S>(ws: &mut WebSocketStream<S>, expected_id: &str, ver_json: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ack_prefix = format!("ack:{expected_id}:");
    loop {
        let text = next_text_frame(ws).await?;
        if text.starts_with(&ack_prefix) {
            return Ok(());
        }
        if let Some(rest) = text.strip_prefix("action:") {
            if let Some((id, name_rest)) = rest.split_once(':') {
                if name_rest.starts_with("versionNegotiation") {
                    ws.send(Message::text(format!("ack:{id}:versionNegotiation?{ver_json}"))).await?;
                }
            }
        }
    }
}

async fn next_text_frame<S>(ws: &mut WebSocketStream<S>) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => return Ok(t.to_string()),
            Some(Ok(Message::Close(_))) | None => bail!("tablet closed fex WebSocket"),
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(e).context("reading fex WebSocket"),
        }
    }
}
