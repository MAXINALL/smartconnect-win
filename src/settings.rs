use std::fs;
use std::path::{Path, PathBuf};
use anyhow::Result;
use serde::{Deserialize, Serialize};

const SETTINGS_FILE: &str = "settings.json";

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Settings {
    pub close_to_tray: bool,
    pub auto_clipboard: bool,
    pub context_menu: bool,
    pub download_dir: String,
}

impl Default for Settings {
    fn default() -> Self {
        let download_dir = dirs_downloads().unwrap_or_else(|| "C:\\Users\\Default\\Downloads".to_string());
        Self {
            close_to_tray: true,
            auto_clipboard: true,
            context_menu: false,
            download_dir,
        }
    }
}

pub fn dirs_downloads() -> Option<String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(folders) = hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") {
        if let Ok(val) = folders.get_value::<String, _>("{374DE290-123F-4565-9164-39C4925E467B}") {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                if let Ok(userprofile) = std::env::var("USERPROFILE") {
                    return Some(trimmed.replace("%USERPROFILE%", &userprofile));
                }
                return Some(trimmed.to_string());
            }
        }
    }
    if let Ok(folders) = hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders") {
        if let Ok(val) = folders.get_value::<String, _>("{374DE290-123F-4565-9164-39C4925E467B}") {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        Some(format!("{}\\Downloads", userprofile))
    } else {
        None
    }
}

pub struct SettingsStore {
    path: PathBuf,
    pub current: Settings,
}

impl SettingsStore {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(SETTINGS_FILE);
        let current = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?).unwrap_or_default()
        } else {
            let def = Settings::default();
            fs::write(&path, serde_json::to_vec_pretty(&def)?)?;
            def
        };
        Ok(Self { path, current })
    }

    pub fn save(&mut self, s: Settings) -> Result<()> {
        let old_menu = self.current.context_menu;
        self.current = s;
        fs::write(&self.path, serde_json::to_vec_pretty(&self.current)?)?;
        if old_menu != self.current.context_menu {
            sync_context_menu(self.current.context_menu).ok();
        }
        Ok(())
    }

    pub fn reload(&mut self) -> Result<()> {
        if self.path.exists() {
            if let Ok(s) = serde_json::from_slice::<Settings>(&fs::read(&self.path)?) {
                self.current = s;
            }
        }
        Ok(())
    }
}

pub fn sync_context_menu(enable: bool) -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let shell_path = r"Software\Classes\*\shell";

    if enable {
        let (shell_key, _) = hkcu.create_subkey(shell_path)?;
        let (item_key, _) = shell_key.create_subkey("SmartConnectSend")?;
        item_key.set_value("", &"发送到联想小新平板")?;
        
        let exe = std::env::current_exe()?;
        let exe_str = exe.to_string_lossy();
        let cmd = format!("\"{}\" --send \"%1\"", exe_str);
        let (cmd_key, _) = item_key.create_subkey("command")?;
        cmd_key.set_value("", &cmd)?;
    } else {
        if let Ok(shell_key) = hkcu.open_subkey_with_flags(shell_path, KEY_WRITE) {
            shell_key.delete_subkey_all("SmartConnectSend").ok();
        }
    }
    Ok(())
}
