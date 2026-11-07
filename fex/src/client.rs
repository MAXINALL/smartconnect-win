//! Pulls one offered transfer from the phone's fex server.
//!
//! ```text
//! client                                   phone (fex server, TLS, pinned)
//!   GET /websocket (upgrade)          ->
//!                                     <-   action:Server<n>:versionNegotiation?{"version":1}
//!   ack:Server<n>:versionNegotiation?{"version":1}  ->
//!                                     <-   action:Server<n+1>:sendRequest?{id, file[], totalSize…}
//!   ack:Server<n+1>:sendRequest?{}    ->
//!   GET /download?taskId=<id>&token=<token>   (second TLS connection)  -> 200 application/zip
//!   action:Client1001:status?{"taskId":<id>,"type":1,"reason":""}  ->
//!                                     <-   ack:Client1001:status
//! ```
//!
//! If the download fails after the offer was accepted, the status goes out as type 2 (failed)
//! instead.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use tokio_rustls::rustls::ClientConfig;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::frame::{self, ClientIds, Frame, Kind, Name, SendRequest, Status, VersionNegotiation};
use crate::{http, tls};

/// How long to wait for the server's `sendRequest` after connecting.
const OFFER_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the `/download` may take end to end.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait for the `status` ack (missing it is not an error: the files are here).
const ACK_TIMEOUT: Duration = Duration::from_secs(5);
/// Default cap on the downloaded archive.
pub const DEFAULT_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Where an offer's server is: the phone's address plus the advertised `port`, `fingerprint` and
/// `token` (the token is sent along on `/download` as the PC does; the phone does not check it
/// there).
#[derive(Debug, Clone)]
pub struct Offer {
    pub host: IpAddr,
    pub port: u16,
    pub fingerprint: String,
    pub token: String,
}

/// A completed pull: the server's description of the transfer and the zip it served.
#[derive(Debug)]
pub struct Pulled {
    pub request: SendRequest,
    pub archive: Vec<u8>,
}

/// Runs the whole exchange for `offer` and returns the archive. The phone is told the transfer
/// completed only after the archive arrived in full.
pub async fn pull(offer: &Offer, max_bytes: usize) -> Result<Pulled> {
    let config = tls::client_config(&offer.fingerprint)?;
    let addr = SocketAddr::new(offer.host, offer.port);
    let host = addr.to_string();

    let stream = tls::connect(addr, config.clone()).await?;
    let (mut ws, _) = tokio_tungstenite::client_async(format!("wss://{host}/websocket"), stream)
        .await
        .context("WebSocket upgrade on /websocket")?;

    // versionNegotiation, then sendRequest; ack each.
    let request = tokio::time::timeout(OFFER_TIMEOUT, async {
        loop {
            let text = match ws.next().await {
                Some(Ok(Message::Text(t))) => t,
                Some(Ok(Message::Close(_))) | None => bail!("fex server closed the WebSocket before offering files"),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e).context("reading the fex WebSocket"),
            };
            let f = match Frame::parse(&text) {
                Ok(f) => f,
                Err(e) => {
                    warn!("fex: ignoring frame: {e:#}");
                    continue;
                }
            };
            debug!(kind = ?f.kind, name = ?f.name, id = %f.id, "fex: <-");
            if f.kind != Kind::Action {
                continue;
            }
            match f.name {
                Name::VersionNegotiation => {
                    if let Ok(v) = f.json::<VersionNegotiation>() {
                        if v.version != frame::VERSION {
                            warn!(offered = v.version, "fex: server offers another protocol version; answering with ours");
                        }
                    }
                    let body = serde_json::to_string(&VersionNegotiation { version: frame::VERSION })?;
                    ws.send(Message::text(Frame::ack(&f.id, Name::VersionNegotiation, Some(body)).to_string())).await?;
                }
                Name::SendRequest => {
                    let req: SendRequest = f.json()?;
                    ws.send(Message::text(Frame::ack(&f.id, Name::SendRequest, Some("{}".into())).to_string())).await?;
                    return Ok(req);
                }
                _ => {}
            }
        }
    })
    .await
    .context("timed out waiting for the phone's sendRequest")??;
    info!(files = request.file_count, bytes = request.total_size, "fex: phone offers a transfer");

    // The download runs on its own connection while the WebSocket stays open; keep reading the
    // WebSocket meanwhile so pings are answered.
    let result: Result<Vec<u8>> = async {
        if request.total_size as usize > max_bytes {
            bail!("the offered transfer ({} bytes) is over the {max_bytes}-byte limit", request.total_size);
        }
        let download = download(addr, config, &host, &request.id, &offer.token, max_bytes);
        tokio::pin!(download);
        let archive = loop {
            tokio::select! {
                r = &mut download => break r?,
                m = ws.next() => match m {
                    Some(Ok(Message::Close(_))) | None => bail!("fex server closed the WebSocket during the download"),
                    Some(Err(e)) => return Err(e).context("fex WebSocket during the download"),
                    Some(Ok(_)) => {}
                },
            }
        };
        if request.total_size > 0 && archive.len() as u64 != request.total_size {
            bail!("downloaded {} bytes but the phone announced {}", archive.len(), request.total_size);
        }
        Ok(archive)
    }
    .await;

    // Report the outcome: type 1 fires the phone's onComplete, type 2 its onFailure (so it can
    // drop the transfer now instead of at its own timeout).
    let (kind, reason) = match &result {
        Ok(_) => (frame::STATUS_COMPLETE, String::new()),
        Err(_) => (frame::STATUS_FAILED, "download failed".to_owned()),
    };
    let status = Status { task_id: request.id.clone(), kind, reason };
    if !report(&mut ws, &status).await && result.is_ok() {
        warn!("fex: the phone did not acknowledge the completion status");
    }
    let _ = ws.close(None).await;
    Ok(Pulled { request, archive: result? })
}

/// Sends a `status` action and waits briefly for its ack; returns whether it came.
async fn report<S>(ws: &mut S, status: &Status) -> bool
where
    S: futures_util::Sink<Message> + futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let id = ClientIds::default().next_id();
    let Ok(body) = serde_json::to_string(status) else { return false };
    if ws.send(Message::text(Frame::action(&id, Name::Status, Some(body)).to_string())).await.is_err() {
        return false;
    }
    tokio::time::timeout(ACK_TIMEOUT, async {
        while let Some(Ok(m)) = ws.next().await {
            if let Message::Text(t) = m {
                if Frame::parse(&t).is_ok_and(|f| f.kind == Kind::Ack && f.name == Name::Status && f.id == id) {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false)
}

async fn download(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    host: &str,
    task_id: &str,
    token: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let mut target = format!("/download?taskId={}", http::encode_query_value(task_id));
    if !token.is_empty() {
        target.push_str(&format!("&token={}", http::encode_query_value(token)));
    }
    tokio::time::timeout(DOWNLOAD_TIMEOUT, async {
        let mut stream = tls::connect(addr, config).await?;
        let resp = http::get(&mut stream, host, &target, max_bytes).await?;
        if resp.status != 200 {
            // The server answers an unknown task with 200 text/plain, so also check the type below.
            bail!("/download answered HTTP {}", resp.status);
        }
        if !resp.body.starts_with(b"PK") {
            let preview = String::from_utf8_lossy(&resp.body[..resp.body.len().min(80)]).into_owned();
            bail!("/download did not return a zip ({:?})", preview.replace(task_id, "<task>"));
        }
        Ok(resp.body)
    })
    .await
    .context("/download timed out")?
}
