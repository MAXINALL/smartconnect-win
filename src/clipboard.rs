use std::sync::Mutex;
use anyhow::Result;
use arboard::Clipboard;

pub struct ClipboardManager {
    clipboard: Mutex<Option<Clipboard>>,
    last_text: Mutex<String>,
}

impl ClipboardManager {
    pub fn new() -> Self {
        let cb = Clipboard::new().ok();
        Self {
            clipboard: Mutex::new(cb),
            last_text: Mutex::new(String::new()),
        }
    }

    pub fn get_text(&self) -> Result<String> {
        let mut guard = self.clipboard.lock().unwrap();
        if guard.is_none() {
            *guard = Clipboard::new().ok();
        }
        if let Some(cb) = guard.as_mut() {
            let t = cb.get_text().unwrap_or_default();
            Ok(t)
        } else {
            Ok(String::new())
        }
    }

    pub fn set_text(&self, text: &str) -> Result<()> {
        let mut guard = self.clipboard.lock().unwrap();
        if guard.is_none() {
            *guard = Clipboard::new().ok();
        }
        if let Some(cb) = guard.as_mut() {
            cb.set_text(text.to_string())?;
        }
        if let Ok(mut last) = self.last_text.lock() {
            *last = text.to_string();
        }
        Ok(())
    }

    pub fn check_changed(&self) -> Option<String> {
        if let Ok(curr) = self.get_text() {
            if curr.is_empty() {
                return None;
            }
            if let Ok(mut last) = self.last_text.lock() {
                if *last != curr {
                    *last = curr.clone();
                    return Some(curr);
                }
            }
        }
        None
    }
}
