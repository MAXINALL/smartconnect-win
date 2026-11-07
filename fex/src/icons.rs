//! App icons for the Apps page: the service 17 `cmd 1` app list advertises a fex transfer of one
//! PNG per app, named exactly as the list's `iconName`.
//!
//! Files land in `$XDG_CACHE_HOME/smartconnect-linux/app-icons/` (default
//! `~/.cache/smartconnect-linux/app-icons/`), one per `iconName` (`<pkg>_<cmp>.png`, prefixed
//! `<userId>_` for a non-zero user). Each is written atomically (temp file + rename) and only when
//! its bytes changed, so readers never see a half-written icon and unchanged icons keep their
//! mtime. Old icons are never deleted.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::client::{self, Offer};
use crate::zip;

/// Control-WS service id of the app list.
pub const SERVICE_APP_LIST: i64 = 17;
/// `cmd` of the phone's app list (with the icon offer).
pub const CMD_APP_LIST: i64 = 1;
/// `cmd` the PC sends to make the phone send the list (and offer the icons) again.
pub const CMD_REQUEST_APP_LIST: i64 = 2;

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// One app of the list.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct App {
    #[serde(default)]
    pub pkg: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub user_id: i64,
    #[serde(default)]
    pub cmp: String,
    #[serde(default)]
    pub icon_name: String,
}

/// Service 17 `cmd 1`: the app list plus the coordinates of the icon transfer.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppListAdvert {
    pub port: u16,
    pub fingerprint: String,
    #[serde(default)]
    pub token: String,
    /// Always `false` in the adverts seen so far; the Windows PC fetches the icons regardless.
    #[serde(default)]
    pub auto_download: bool,
    #[serde(default)]
    pub app_limit: i64,
    #[serde(default)]
    pub apps: Vec<App>,
    #[serde(default)]
    pub wp_apps: Vec<App>,
}

impl AppListAdvert {
    /// The advert in a service 17 frame's `data`, if it is a `cmd 1` that offers icons.
    pub fn from_data(data: &Value) -> Option<AppListAdvert> {
        if data.get("cmd").and_then(Value::as_i64) != Some(CMD_APP_LIST) {
            return None;
        }
        let advert: AppListAdvert = serde_json::from_value(data.clone()).ok()?;
        (advert.port != 0 && !advert.fingerprint.is_empty()).then_some(advert)
    }

    /// The `iconName`s the list refers to.
    pub fn icon_names(&self) -> BTreeSet<String> {
        self.apps.iter().chain(&self.wp_apps).map(|a| a.icon_name.clone()).filter(|n| !n.is_empty()).collect()
    }

    pub fn offer(&self, host: IpAddr) -> Offer {
        Offer { host, port: self.port, fingerprint: self.fingerprint.clone(), token: self.token.clone() }
    }
}

/// `$XDG_CACHE_HOME/smartconnect-linux/app-icons`, else `~/.cache/smartconnect-linux/app-icons`.
pub fn default_cache_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("smartconnect-linux").join("app-icons")
}

/// A name we will write: a plain file name (no directories, not hidden) ending in `.png`.
pub fn is_safe_icon_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && !name.contains(['/', '\\', '\0'])
        && name.to_ascii_lowercase().ends_with(".png")
}

/// Writes `data` to `dir/name` unless the file already holds exactly that; returns whether it
/// wrote. The new content goes to a hidden temp file in `dir` and is renamed over the target.
pub fn write_if_changed(dir: &Path, name: &str, data: &[u8]) -> Result<bool> {
    let path = dir.join(name);
    if std::fs::read(&path).is_ok_and(|old| old == data) {
        return Ok(false);
    }
    let tmp = dir.join(format!(".{name}.{}.part", std::process::id()));
    let result = (|| {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &path)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("writing {}", path.display()));
    }
    Ok(true)
}

/// What [`store`] did with an archive.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// PNGs in the archive that we kept (written + unchanged).
    pub icons: usize,
    pub written: usize,
    pub unchanged: usize,
    /// Entries skipped: unsafe name, not a PNG, or not a `.png` name.
    pub skipped: usize,
    /// `iconName`s of the list that the archive did not contain.
    pub missing: Vec<String>,
}

/// Writes the icon entries of an archive into `dir` (created if needed).
pub fn store(entries: &[zip::Entry], expected: &BTreeSet<String>, dir: &Path) -> Result<Report> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut report = Report::default();
    let mut seen = BTreeSet::new();
    for e in entries {
        if !is_safe_icon_name(&e.name) || !e.data.starts_with(PNG_MAGIC) {
            report.skipped += 1;
            continue;
        }
        if write_if_changed(dir, &e.name, &e.data)? {
            report.written += 1;
        } else {
            report.unchanged += 1;
        }
        report.icons += 1;
        seen.insert(e.name.as_str());
    }
    report.missing = expected.iter().filter(|n| !seen.contains(n.as_str())).cloned().collect();
    Ok(report)
}

/// Pulls the icon transfer an app-list advert offers and stores the icons in `dir`.
pub async fn fetch(host: IpAddr, advert: &AppListAdvert, dir: &Path) -> Result<Report> {
    let pulled = client::pull(&advert.offer(host), client::DEFAULT_MAX_BYTES).await?;
    let expected = advert.icon_names();
    let dir = dir.to_owned();
    tokio::task::spawn_blocking(move || {
        let entries = zip::read_all(&pulled.archive)?;
        store(&entries, &expected, &dir)
    })
    .await
    .context("icon writer task")?
}

/// An exclusive, non-blocking lock so only one process pulls an icon offer at a time: the CLI holds
/// it from before it asks the phone for the list until it is done, so the daemon's automatic fetch
/// leaves that offer alone. Released on drop (or process exit).
#[derive(Debug)]
pub struct FetchLock {
    _file: File,
}

impl FetchLock {
    pub fn path() -> PathBuf {
        let base = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        base.join("smartconnectd").join("app-icons.lock")
    }

    /// `Ok(None)` if someone else holds it.
    pub fn try_acquire() -> Result<Option<FetchLock>> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = File::options().create(true).truncate(false).write(true).open(&path)?;
        // SAFETY: flock on a descriptor we own.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(FetchLock { _file: file }));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(None)
        } else {
            bail!("locking {}: {err}", path.display())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("smartconnect-fex-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn parses_the_advert() {
        let data = json!({"ver":"1","cmd":1,"port":50000,"fingerprint":"<fingerprint>","token":"<token>",
            "appLimit":5,"autoDownload":false,
            "apps":[{"pkg":"a.b","name":"A","userId":0,"cmp":"a.b.Main","iconName":"a.b_a.b.Main.png"},
                    {"pkg":"c.d","name":"C","userId":10,"cmp":"c.d.Main","iconName":"10_c.d_c.d.Main.png"}],
            "wpApps":[]});
        let a = AppListAdvert::from_data(&data).unwrap();
        assert_eq!((a.port, a.app_limit, a.auto_download), (50000, 5, false));
        assert_eq!(a.apps[1].user_id, 10);
        assert_eq!(a.icon_names().into_iter().collect::<Vec<_>>(), ["10_c.d_c.d.Main.png", "a.b_a.b.Main.png"]);
        assert!(AppListAdvert::from_data(&json!({"cmd":10,"port":1,"fingerprint":"x"})).is_none());
        assert!(AppListAdvert::from_data(&json!({"cmd":1,"apps":[]})).is_none());
    }

    #[test]
    fn icon_name_safety() {
        assert!(is_safe_icon_name("com.google.android.youtube_com.google.android.youtube.app.honeycomb.Shell$HomeActivity.png"));
        assert!(is_safe_icon_name("10_c.d_c.d.Main.PNG"));
        for bad in ["", "../x.png", "a/b.png", ".hidden.png", "x.txt", "a\\b.png"] {
            assert!(!is_safe_icon_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn stores_atomically_and_skips_unchanged() {
        let dir = scratch("store");
        let png = |b: u8| [PNG_MAGIC, &[b]].concat();
        let entries = vec![
            zip::Entry { name: "a.b_a.b.Main.png".into(), data: png(1) },
            zip::Entry { name: "../evil.png".into(), data: png(2) },
            zip::Entry { name: "notes.png".into(), data: b"not a png".to_vec() },
        ];
        let expected: BTreeSet<String> = ["a.b_a.b.Main.png".to_owned(), "gone.png".to_owned()].into();
        let r = store(&entries, &expected, &dir).unwrap();
        assert_eq!((r.icons, r.written, r.unchanged, r.skipped), (1, 1, 0, 2));
        assert_eq!(r.missing, ["gone.png"]);
        assert_eq!(std::fs::read(dir.join("a.b_a.b.Main.png")).unwrap(), png(1));

        let r = store(&entries[..1], &expected, &dir).unwrap();
        assert_eq!((r.written, r.unchanged), (0, 1));
        let r = store(&[zip::Entry { name: "a.b_a.b.Main.png".into(), data: png(3) }], &expected, &dir).unwrap();
        assert_eq!(r.written, 1);
        assert_eq!(std::fs::read(dir.join("a.b_a.b.Main.png")).unwrap(), png(3));
        // Only the icon is left: no temp files, nothing outside the directory.
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["a.b_a.b.Main.png"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_dir_follows_xdg_layout() {
        assert!(default_cache_dir().ends_with("smartconnect-linux/app-icons"));
    }
}
