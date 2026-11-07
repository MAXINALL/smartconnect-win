//! End-to-end tests against a mock fex server that behaves like the phone's (as observed): TLS with
//! a throwaway self-signed certificate, `/websocket` speaking the action/ack frames, `/download`
//! serving a streaming-mode zip. All ids, tokens and names are placeholders.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;

use crate::client::{self, Offer};
use crate::icons::{self, AppListAdvert};
use crate::tls;
use crate::zip::tests::build_zip;

const TASK: &str = "TASKplaceholder01";
const TOKEN: &str = "tok+en/placeholder=";

struct Mock {
    addr: SocketAddr,
    fingerprint: String,
    events: Arc<Mutex<Vec<String>>>,
}

async fn start_mock(archive: Vec<u8>, files_json: String) -> Mock {
    let total = archive.len();
    start_mock_announcing(archive, files_json, total).await
}

/// Like [`start_mock`], but `sendRequest` announces `total` bytes.
async fn start_mock_announcing(archive: Vec<u8>, files_json: String, total: usize) -> Mock {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["Lenovo".to_owned()]).unwrap().self_signed(&key).unwrap();
    let der: CertificateDer<'static> = cert.der().clone();
    let fingerprint = tls::fingerprint(der.as_ref());
    let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], PrivatePkcs8KeyDer::from(key.serialize_der()).into())
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (acceptor, ev, archive, files_json) = (acceptor.clone(), ev.clone(), archive.clone(), files_json.clone());
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else { return };
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let head = String::from_utf8(head).unwrap();
                let target = head.split_whitespace().nth(1).unwrap().to_owned();
                if target == "/websocket" {
                    let key = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ").or_else(|| l.strip_prefix("sec-websocket-key: ")))
                        .unwrap();
                    let resp = format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                        derive_accept_key(key.trim().as_bytes())
                    );
                    s.write_all(resp.as_bytes()).await.unwrap();
                    let mut ws = WebSocketStream::from_raw_socket(s, Role::Server, None).await;
                    ws.send(Message::text(r#"action:Server1001:versionNegotiation?{"version":1}"#)).await.unwrap();
                    let mut sent_request = false;
                    while let Some(Ok(m)) = ws.next().await {
                        let Message::Text(t) = m else { continue };
                        ev.lock().unwrap().push(format!("ws {t}"));
                        if t.starts_with("ack:Server1001:versionNegotiation") && !sent_request {
                            sent_request = true;
                            let req = format!(
                                r#"action:Server1002:sendRequest?{{"id":"{TASK}","senderId":"<device-id>","senderName":"","fileName":"x","fileCount":2,"mimeType":"*/*","totalSize":{total},"file":{files_json}}}"#
                            );
                            ws.send(Message::text(req)).await.unwrap();
                        } else if let Some(rest) = t.strip_prefix("action:") {
                            let id = rest.split(':').next().unwrap();
                            ws.send(Message::text(format!("ack:{id}:status"))).await.unwrap();
                        }
                    }
                } else {
                    ev.lock().unwrap().push(format!("http {target}"));
                    let body = if target.starts_with(&format!("/download?taskId={TASK}")) {
                        archive
                    } else {
                        b"download -> taskId x does not exist!".to_vec()
                    };
                    let ctype = if body.starts_with(b"PK") { "application/zip" } else { "text/plain; charset=utf-8" };
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n", body.len());
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.write_all(&body).await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });
    Mock { addr, fingerprint, events }
}

fn png(tag: u8) -> Vec<u8> {
    [&b"\x89PNG\r\n\x1a\n"[..], &[tag; 40]].concat()
}

const FILES: &str = r#"[{"name":"a.b_a.b.Main.png","mimeType":"image/png","size":48,"dir":false,"index":0},{"name":"10_c.d_c.d.Main.png","mimeType":"image/png","size":48,"dir":false,"index":0}]"#;

#[tokio::test]
async fn pulls_a_transfer_and_reports_completion() {
    let (a, c) = (png(1), png(2));
    let archive = build_zip(&[("a.b_a.b.Main.png", &a), ("10_c.d_c.d.Main.png", &c)], false);
    let mock = start_mock(archive.clone(), FILES.into()).await;
    let offer = Offer { host: mock.addr.ip(), port: mock.addr.port(), fingerprint: mock.fingerprint.to_uppercase(), token: TOKEN.into() };
    let pulled = client::pull(&offer, client::DEFAULT_MAX_BYTES).await.unwrap();
    assert_eq!(pulled.request.id, TASK);
    assert_eq!(pulled.request.files.len(), 2);
    assert_eq!(pulled.archive, archive);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let events = mock.events.lock().unwrap().clone();
    assert_eq!(
        events,
        [
            r#"ws ack:Server1001:versionNegotiation?{"version":1}"#.to_owned(),
            "ws ack:Server1002:sendRequest?{}".to_owned(),
            format!("http /download?taskId={TASK}&token=tok%2Ben%2Fplaceholder%3D"),
            format!(r#"ws action:Client1001:status?{{"taskId":"{TASK}","type":1,"reason":""}}"#),
        ]
    );
}

#[tokio::test]
async fn reports_a_failed_download_to_the_phone() {
    let archive = build_zip(&[("a.b_a.b.Main.png", &png(1))], false);
    let announced = archive.len() + 7;
    let mock = start_mock_announcing(archive, FILES.into(), announced).await;
    let offer = Offer { host: mock.addr.ip(), port: mock.addr.port(), fingerprint: mock.fingerprint.clone(), token: String::new() };
    let err = client::pull(&offer, client::DEFAULT_MAX_BYTES).await.unwrap_err();
    assert!(format!("{err:#}").contains("announced"), "{err:#}");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let events = mock.events.lock().unwrap().clone();
    assert_eq!(events[2], format!("http /download?taskId={TASK}"));
    assert_eq!(events[3], format!(r#"ws action:Client1001:status?{{"taskId":"{TASK}","type":2,"reason":"download failed"}}"#));
}

#[tokio::test]
async fn refuses_a_server_with_another_certificate() {
    let mock = start_mock(build_zip(&[("a.png", &png(1))], false), FILES.into()).await;
    let wrong = tls::fingerprint(b"some other certificate");
    let offer = Offer { host: mock.addr.ip(), port: mock.addr.port(), fingerprint: wrong, token: String::new() };
    let err = client::pull(&offer, client::DEFAULT_MAX_BYTES).await.unwrap_err();
    assert!(format!("{err:#}").contains("TLS handshake"), "{err:#}");
    assert!(mock.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn fetches_icons_into_the_cache_layout() {
    let (a, c) = (png(1), png(2));
    let archive = build_zip(&[("a.b_a.b.Main.png", &a), ("10_c.d_c.d.Main.png", &c), ("../escape.png", &a)], true);
    let mock = start_mock(archive, FILES.into()).await;
    let data = serde_json::json!({"ver":"1","cmd":1,"port":mock.addr.port(),"fingerprint":mock.fingerprint,"token":TOKEN,
        "appLimit":5,"autoDownload":false,
        "apps":[{"pkg":"a.b","name":"A","userId":0,"cmp":"a.b.Main","iconName":"a.b_a.b.Main.png"},
                {"pkg":"c.d","name":"C","userId":10,"cmp":"c.d.Main","iconName":"10_c.d_c.d.Main.png"},
                {"pkg":"e.f","name":"E","userId":0,"cmp":"e.f.Main","iconName":"e.f_e.f.Main.png"}],"wpApps":[]});
    let advert = AppListAdvert::from_data(&data).unwrap();
    let dir = std::env::temp_dir().join(format!("smartconnect-fex-mock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let r = icons::fetch(IpAddr::V4(Ipv4Addr::LOCALHOST), &advert, &dir).await.unwrap();
    assert_eq!((r.icons, r.written, r.skipped), (2, 2, 1));
    assert_eq!(r.missing, ["e.f_e.f.Main.png"]);
    assert_eq!(std::fs::read(dir.join("10_c.d_c.d.Main.png")).unwrap(), c);
    assert!(!dir.parent().unwrap().join("escape.png").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
