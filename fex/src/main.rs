//! `smartconnect-fex`: pull files the phone offers over its fex file-transfer server.
//!
//! * `fetch-app-icons [--out DIR] [--phone IP]`: asks the phone (through smartconnectd's control
//!   socket) to resend its app list (service 17 `cmd 2`), then pulls the icon transfer the list
//!   advertises and writes the PNGs to the app-icon cache. The daemon does the same on every
//!   connection by itself; this is the manual/testing path.
//! * `pull --host IP --port N --fingerprint HEX [--token T] --out DIR`: pulls any offer whose
//!   coordinates you already have and unpacks it into DIR.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use smartconnect_fex::icons::{self, AppListAdvert, FetchLock};
use smartconnect_fex::{client, zip};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Parser)]
#[command(name = "smartconnect-fex", version, about = "Pull files the phone offers over Smart Connect's fex transfer server")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Ask the phone for its app list and download the app icons it offers.
    FetchAppIcons {
        /// Where to write the PNGs (default: $XDG_CACHE_HOME/smartconnect-linux/app-icons).
        #[arg(long)]
        out: Option<PathBuf>,
        /// The phone's IP address (default: `phoneAddress` from the daemon's status).
        #[arg(long)]
        phone: Option<IpAddr>,
        /// Seconds to wait for the phone's app list.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Pull one offer by its coordinates and unpack it.
    Pull {
        #[arg(long)]
        host: IpAddr,
        #[arg(long)]
        port: u16,
        /// Lowercase hex SHA-256 of the server certificate, as advertised.
        #[arg(long)]
        fingerprint: String,
        #[arg(long, default_value = "")]
        token: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "smartconnect_fex=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match Cli::parse().cmd {
        Cmd::FetchAppIcons { out, phone, timeout } => {
            fetch_app_icons(out.unwrap_or_else(icons::default_cache_dir), phone, Duration::from_secs(timeout)).await
        }
        Cmd::Pull { host, port, fingerprint, token, out } => {
            let offer = client::Offer { host, port, fingerprint, token };
            let pulled = client::pull(&offer, client::DEFAULT_MAX_BYTES).await?;
            let entries = zip::read_all(&pulled.archive)?;
            let n = unpack(&entries, &out)?;
            println!("pulled task with {} file(s), {} bytes; wrote {n} file(s) to {}", entries.len(), pulled.archive.len(), out.display());
            Ok(())
        }
    }
}

fn control_socket() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("smartconnectd.sock")
}

async fn control_request(line: &str) -> Result<Value> {
    let mut s = UnixStream::connect(control_socket()).await.context("connecting to smartconnectd's control socket (is the daemon running?)")?;
    s.write_all(format!("{line}\n").as_bytes()).await?;
    let mut lines = BufReader::new(s).lines();
    let reply = lines.next_line().await?.context("smartconnectd closed the control socket")?;
    Ok(serde_json::from_str(&reply)?)
}

async fn fetch_app_icons(out: PathBuf, phone: Option<IpAddr>, timeout: Duration) -> Result<()> {
    let status = control_request("status").await?;
    if status.get("connected").and_then(Value::as_bool) != Some(true) {
        bail!("the phone is not connected to smartconnectd");
    }
    let host = match phone {
        Some(ip) => ip,
        None => status
            .get("phoneAddress")
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok())
            .context("the daemon's status has no phoneAddress; pass --phone <ip>")?,
    };

    // Hold the lock from before the request, so the daemon leaves this offer to us.
    let deadline = Instant::now() + timeout;
    let _lock = loop {
        if let Some(l) = FetchLock::try_acquire()? {
            break l;
        }
        if Instant::now() > deadline {
            bail!("another icon fetch is still running (lock {})", FetchLock::path().display());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    let mut watch = UnixStream::connect(control_socket()).await?;
    watch
        .write_all(format!("{}\n", json!({"cmd":"watch","services":[icons::SERVICE_APP_LIST]})).as_bytes())
        .await?;
    let mut lines = BufReader::new(watch).lines();
    lines.next_line().await?; // {"ok":true,"message":"watching"}
    let sent = control_request(
        &json!({"cmd":"send","service":icons::SERVICE_APP_LIST,"data":{"ver":"1","cmd":icons::CMD_REQUEST_APP_LIST}}).to_string(),
    )
    .await?;
    if sent.get("ok").and_then(Value::as_bool) != Some(true) {
        bail!("asking the phone for its app list failed: {sent}");
    }
    eprintln!("asked the phone for its app list; waiting for the icon offer…");
    let advert = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), async {
        while let Some(line) = lines.next_line().await? {
            let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
            if v.get("service").and_then(Value::as_i64) != Some(icons::SERVICE_APP_LIST) {
                continue;
            }
            if let Some(a) = v.get("data").and_then(AppListAdvert::from_data) {
                return Ok(a);
            }
        }
        bail!("smartconnectd closed the watch stream")
    })
    .await
    .context("the phone did not send its app list in time")??;
    eprintln!("app list: {} apps (+{} work profile); pulling icons from {host}:{}", advert.apps.len(), advert.wp_apps.len(), advert.port);

    let report = icons::fetch(host, &advert, &out).await?;
    println!(
        "fetched {} icons into {} ({} written, {} unchanged, {} skipped)",
        report.icons,
        out.display(),
        report.written,
        report.unchanged,
        report.skipped
    );
    if !report.missing.is_empty() {
        let missing: BTreeSet<_> = report.missing.iter().take(5).collect();
        println!("{} listed icon(s) were not in the transfer, e.g. {missing:?}", report.missing.len());
    }
    Ok(())
}

/// Writes every entry with a plain, non-hidden file name into `dir`.
fn unpack(entries: &[zip::Entry], dir: &Path) -> Result<usize> {
    std::fs::create_dir_all(dir)?;
    let mut n = 0;
    for e in entries {
        let name = e.name.as_str();
        if name.is_empty() || name.starts_with('.') || name.contains(['/', '\\', '\0']) {
            eprintln!("skipping entry with an unsafe name: {name:?}");
            continue;
        }
        icons::write_if_changed(dir, name, &e.data)?;
        n += 1;
    }
    Ok(n)
}
