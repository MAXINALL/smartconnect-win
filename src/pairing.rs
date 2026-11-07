use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::Result;
use serde::{Deserialize, Serialize};

const PAIRED_FILE: &str = "paired.json";

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PairedPhone {
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub real_device_id: Option<String>,
    pub key: String,
    #[serde(default)]
    pub phone_key: Option<String>,
    #[serde(default)]
    pub last_ip: Option<String>,
    #[serde(default)]
    pub last_mdns_port: Option<u16>,
}

pub struct PairingStore {
    path: PathBuf,
    phones: BTreeMap<String, PairedPhone>,
}

impl PairingStore {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(PAIRED_FILE);
        let phones = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?)?
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, phones })
    }

    pub fn is_empty(&self) -> bool {
        self.phones.is_empty()
    }

    pub fn first(&self) -> Option<(&String, &PairedPhone)> {
        self.phones.iter().next()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &PairedPhone)> {
        self.phones.iter()
    }

    pub fn get(&self, key: &str) -> Option<&PairedPhone> {
        self.phones.get(key)
    }

    pub fn save(&self) -> Result<()> {
        fs::write(&self.path, serde_json::to_vec_pretty(&self.phones)?)?;
        Ok(())
    }

    pub fn pair(&mut self, key: &str, device_name: Option<&str>, real_device_id: Option<&str>) -> Result<PairedPhone> {
        let entry = self.phones.entry(key.to_owned()).or_insert_with(|| PairedPhone {
            device_name: None,
            real_device_id: None,
            key: gen_key(),
            phone_key: None,
            last_ip: None,
            last_mdns_port: None,
        });
        if let Some(dn) = device_name {
            entry.device_name = Some(dn.to_owned());
        }
        if let Some(rd) = real_device_id {
            entry.real_device_id = Some(rd.to_owned());
        }
        let record = entry.clone();
        self.save()?;
        Ok(record)
    }

    pub fn save_phone_key(&mut self, key: &str, phone_key: &str) -> Result<()> {
        if let Some(entry) = self.phones.get_mut(key) {
            entry.phone_key = Some(phone_key.to_owned());
            self.save()?;
        }
        Ok(())
    }

    pub fn update_ip(&mut self, key: &str, ip: &str) -> Result<()> {
        if let Some(entry) = self.phones.get_mut(key) {
            entry.last_ip = Some(ip.to_owned());
            self.save()?;
        }
        Ok(())
    }

    pub fn update_mdns_endpoint(&mut self, key: &str, ip: &str, port: u16) -> Result<()> {
        if let Some(entry) = self.phones.get_mut(key) {
            entry.last_ip = Some(ip.to_owned());
            entry.last_mdns_port = Some(port);
            self.save()?;
        }
        Ok(())
    }
}

pub fn gen_key() -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}
