//! The **sending** side of fex: offers files to the phone, as the phone's own Go library does when
//! it sends (see [`crate::client`] for the receiving side and `docs/protocol/file-exchange.md` §3).
//!
//! The sender is the server. It zips the files, then the phone (the receiver) connects:
//!
//! ```text
//! phone                                   PC (this module, on a TLS listener it is handed)
//!   GET /websocket (upgrade)         ->
//!                                    <-   action:Server1001:versionNegotiation?{"version":1}
//!   ack:Server1001:versionNegotiation ->
//!                                    <-   action:Server1002:sendRequest?{id, file[], totalSize…}
//!   ack:Server1002:sendRequest        ->
//!   GET /download?taskId=<id>&token=… (second connection)  -> 200 application/zip
//!   action:<id>:status?{"taskId":<id>,"type":1,"reason":""} ->
//!                                    <-   ack:<id>:status
//! ```
//!
//! This module only knows the protocol: the caller owns the listener and TLS (the daemon serves these
//! routes on its existing port) and routes `/websocket` to [`serve_websocket`] and `/download` to
//! [`download_response`]. A [`Registry`] holds the offered transfers until they finish or expire.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info};

use crate::frame::{self, FileEntry, Frame, Kind, Name, SendRequest, Status, VersionNegotiation};
use crate::zip;

/// A transfer nobody picked up within this long is dropped.
const OFFER_TTL: Duration = Duration::from_secs(120);
/// How long each step of the WebSocket exchange may take.
const STEP_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the receiver may take between accepting and reporting the outcome.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);

/// One file to send.
#[derive(Debug, Clone)]
pub struct OutFile {
    pub name: String,
    pub mime_type: String,
    pub data: Vec<u8>,
}

/// An offered transfer: its id, the zip it serves and the `sendRequest` that describes it.
#[derive(Debug)]
pub struct Transfer {
    pub task_id: String,
    pub token: String,
    pub zip: Vec<u8>,
    pub request: SendRequest,
    created: Instant,
    /// Set once a WebSocket has taken this transfer (one receiver per offer).
    claimed: Mutex<bool>,
}

/// The transfers on offer.
#[derive(Debug, Default)]
pub struct Registry {
    offers: Mutex<Vec<Arc<Transfer>>>,
}

/// A fresh hex id from the clock and a counter (task ids and tokens only need to be unique).
fn fresh_id(len: usize) -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let digest = sha2::Sha256::digest(format!("{t}-{n}-{}", std::process::id()));
    hex::encode(digest)[..len].to_owned()
}

impl Registry {
    /// Zips `files` and offers them. The phone learns about it from the caller (for the clipboard,
    /// a service 2 message carrying our port and certificate fingerprint).
    pub fn offer(&self, files: &[OutFile], sender_id: &str, sender_name: &str) -> Arc<Transfer> {
        let entries: Vec<(&str, &[u8])> = files.iter().map(|f| (f.name.as_str(), f.data.as_slice())).collect();
        let zip = zip::write_stored(&entries);
        let task_id = fresh_id(32);
        let request = SendRequest {
            id: task_id.clone(),
            sender_id: sender_id.to_owned(),
            sender_name: sender_name.to_owned(),
            file_name: files.first().map(|f| f.name.clone()).unwrap_or_default(),
            file_count: files.len() as u64,
            mime_type: if files.len() == 1 { files[0].mime_type.clone() } else { "*/*".to_owned() },
            // As on the phone: the size of the zip, not the sum of the files.
            total_size: zip.len() as u64,
            files: files
                .iter()
                .enumerate()
                .map(|(i, f)| FileEntry {
                    name: f.name.clone(),
                    mime_type: f.mime_type.clone(),
                    size: f.data.len() as u64,
                    dir: false,
                    index: i as i64,
                })
                .collect(),
        };
        let t = Arc::new(Transfer { task_id, token: fresh_id(16), zip, request, created: Instant::now(), claimed: Mutex::new(false) });
        let mut offers = self.offers.lock().unwrap();
        offers.retain(|o| o.created.elapsed() < OFFER_TTL);
        offers.push(t.clone());
        t
    }

    /// The newest unclaimed offer, claimed for a new `/websocket` (which carries no task id).
    fn claim_newest(&self) -> Option<Arc<Transfer>> {
        let offers = self.offers.lock().unwrap();
        offers.iter().rev().filter(|o| o.created.elapsed() < OFFER_TTL).find(|o| {
            let mut claimed = o.claimed.lock().unwrap();
            !std::mem::replace(&mut *claimed, true)
        }).cloned()
    }

    fn find(&self, task_id: &str) -> Option<Arc<Transfer>> {
        self.offers.lock().unwrap().iter().find(|o| o.task_id == task_id).cloned()
    }

    fn remove(&self, task_id: &str) {
        self.offers.lock().unwrap().retain(|o| o.task_id != task_id);
    }

    /// Whether any offer is waiting (callers only route fex paths while one is).
    pub fn has_offers(&self) -> bool {
        self.offers.lock().unwrap().iter().any(|o| o.created.elapsed() < OFFER_TTL)
    }
}

/// Runs the control WebSocket for the newest offer: version negotiation, the `sendRequest`, then
/// the receiver's `status`. Returns whether the receiver reported success.
pub async fn serve_websocket<S>(mut ws: WebSocketStream<S>, registry: &Registry) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(t) = registry.claim_newest() else {
        let _ = ws.close(None).await;
        bail!("a fex WebSocket arrived with nothing on offer");
    };
    let result = run_exchange(&mut ws, &t).await;
    let _ = ws.close(None).await;
    registry.remove(&t.task_id);
    result
}

async fn run_exchange<S>(ws: &mut WebSocketStream<S>, t: &Transfer) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = serde_json::to_string(&VersionNegotiation { version: frame::VERSION })?;
    send(ws, &Frame::action("Server1001", Name::VersionNegotiation, Some(version.clone()))).await?;
    tokio::time::timeout(STEP_TIMEOUT, wait_ack(ws, "Server1001", &version)).await.context("no versionNegotiation ack")??;
    let request = serde_json::to_string(&t.request)?;
    send(ws, &Frame::action("Server1002", Name::SendRequest, Some(request))).await?;
    tokio::time::timeout(STEP_TIMEOUT, wait_ack(ws, "Server1002", &version)).await.context("no sendRequest ack")??;
    info!(task = %t.task_id, bytes = t.zip.len(), "fex: the phone accepted our offer");
    // The receiver downloads on its own connection, then reports the outcome here.
    tokio::time::timeout(TRANSFER_TIMEOUT, async {
        loop {
            let f = next_frame(ws).await?;
            match (f.kind, f.name) {
                (Kind::Action, Name::Status) => {
                    send(ws, &Frame::ack(&f.id, Name::Status, None)).await?;
                    let status: Status = f.json()?;
                    if status.kind == frame::STATUS_STARTED {
                        continue; // progress, not the outcome
                    }
                    return Ok(status.kind == frame::STATUS_COMPLETE);
                }
                (Kind::Action, Name::VersionNegotiation) => {
                    send(ws, &Frame::ack(&f.id, Name::VersionNegotiation, Some(version.clone()))).await?;
                }
                _ => {}
            }
        }
    })
    .await
    .context("the phone never reported the transfer's outcome")?
}

async fn send<S: AsyncRead + AsyncWrite + Unpin>(ws: &mut WebSocketStream<S>, f: &Frame) -> Result<()> {
    debug!(kind = ?f.kind, name = ?f.name, id = %f.id, "fex: ->");
    ws.send(Message::text(f.to_string())).await.context("writing the fex WebSocket")
}

async fn next_frame<S: AsyncRead + AsyncWrite + Unpin>(ws: &mut WebSocketStream<S>) -> Result<Frame> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => match Frame::parse(&t) {
                Ok(f) => {
                    debug!(kind = ?f.kind, name = ?f.name, id = %f.id, "fex: <-");
                    return Ok(f);
                }
                Err(e) => debug!("fex: ignoring frame: {e:#}"),
            },
            Some(Ok(Message::Close(_))) | None => bail!("the phone closed the fex WebSocket"),
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(e).context("reading the fex WebSocket"),
        }
    }
}

/// Waits for the ack of our action `id`, answering a receiver's own version negotiation meanwhile.
async fn wait_ack<S: AsyncRead + AsyncWrite + Unpin>(ws: &mut WebSocketStream<S>, id: &str, version: &str) -> Result<()> {
    loop {
        let f = next_frame(ws).await?;
        match f.kind {
            Kind::Ack if f.id == id => return Ok(()),
            Kind::Action if f.name == Name::VersionNegotiation => {
                send(ws, &Frame::ack(&f.id, Name::VersionNegotiation, Some(version.to_owned()))).await?;
            }
            _ => {}
        }
    }
}

/// The HTTP/1.1 response for a `GET /download?taskId=…` request `target`: the transfer's zip, or
/// (like the phone's server) `200 text/plain` naming an unknown task.
pub fn download_response(registry: &Registry, target: &str) -> Vec<u8> {
    let task = target
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or_default()
        .split('&')
        .find_map(|kv| kv.strip_prefix("taskId="))
        .unwrap_or_default();
    match registry.find(task) {
        Some(t) => {
            info!(task = %t.task_id, bytes = t.zip.len(), "fex: the phone is downloading our offer");
            let mut out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\nAccept-Ranges: none\r\nConnection: close\r\n\r\n",
                t.zip.len()
            )
            .into_bytes();
            out.extend_from_slice(&t.zip);
            out
        }
        None => {
            let body = format!("download -> taskId {task} does not exist!");
            format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                .into_bytes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::ClientIds;

    fn png() -> OutFile {
        OutFile { name: "clipboard.png".into(), mime_type: "image/png".into(), data: b"\x89PNG\r\n\x1a\nfake".to_vec() }
    }

    #[test]
    fn an_offer_describes_its_zip() {
        let r = Registry::default();
        let t = r.offer(&[png()], "pc-id", "Linux PC");
        assert_eq!(t.request.file_count, 1);
        assert_eq!(t.request.total_size, t.zip.len() as u64, "totalSize is the zip's size");
        assert_eq!(t.request.files[0].size, 12);
        assert_eq!(t.request.mime_type, "image/png");
        let back = zip::read_all(&t.zip).unwrap();
        assert_eq!(back[0].name, "clipboard.png");
        assert!(r.has_offers());
    }

    #[test]
    fn download_serves_the_zip_by_task_id() {
        let r = Registry::default();
        let t = r.offer(&[png()], "", "");
        let resp = download_response(&r, &format!("/download?taskId={}&token={}", t.task_id, t.token));
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\n"));
        assert!(resp.ends_with(&t.zip));
        let missing = download_response(&r, "/download?taskId=nope");
        assert!(String::from_utf8_lossy(&missing).ends_with("taskId nope does not exist!"));
    }

    /// The whole exchange against our own client code's frame handling, over an in-memory pipe.
    #[tokio::test]
    async fn websocket_exchange_reports_success() {
        let r = Arc::new(Registry::default());
        let t = r.offer(&[png()], "pc", "Linux PC");
        let (a, b) = tokio::io::duplex(64 * 1024);
        let server = {
            let r = r.clone();
            tokio::spawn(async move {
                let ws = tokio_tungstenite::accept_async(a).await.unwrap();
                serve_websocket(ws, &r).await
            })
        };
        let (mut ws, _) = tokio_tungstenite::client_async("ws://pc/websocket", b).await.unwrap();
        // version negotiation
        let f = Frame::parse(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!((f.kind, f.name, f.id.as_str()), (Kind::Action, Name::VersionNegotiation, "Server1001"));
        ws.send(Message::text(Frame::ack(&f.id, Name::VersionNegotiation, Some("{\"version\":1}".into())).to_string())).await.unwrap();
        // the offer
        let f = Frame::parse(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        let req: SendRequest = f.json().unwrap();
        assert_eq!(req.id, t.task_id);
        ws.send(Message::text(Frame::ack(&f.id, Name::SendRequest, Some("{}".into())).to_string())).await.unwrap();
        // done
        let id = ClientIds::default().next_id();
        let status = Status { task_id: t.task_id.clone(), kind: frame::STATUS_COMPLETE, reason: String::new() };
        ws.send(Message::text(Frame::action(&id, Name::Status, Some(serde_json::to_string(&status).unwrap())).to_string())).await.unwrap();
        let ack = Frame::parse(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!((ack.kind, ack.name, ack.id), (Kind::Ack, Name::Status, id));
        assert!(server.await.unwrap().unwrap());
        assert!(!r.has_offers(), "a finished offer is removed");
    }
}
