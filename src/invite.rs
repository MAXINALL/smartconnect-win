use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};
use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use qrcode::{EcLevel, QrCode};
use rand::{Rng, RngCore};
use serde_json::json;

use crate::identity::Identity;
use crate::proto::SERVICE_DEVICE_PAIRED;

pub const QR_PREFIX: &str = "motorolardpconnection";
pub const VER_CODE: u64 = 903013000;
pub const VER_NAME: &str = "09.0.3.013.000";
const OS_WINDOWS: i64 = 6;
const TYPE_PC: i64 = 4;

pub struct Invite {
    pub token: String,
    pub expires: Instant,
    pub ws_port: u16,
    pub ips: Vec<IpAddr>,
}

impl Invite {
    pub fn new(ws_port: u16, ips: Vec<IpAddr>, ttl: Duration) -> Self {
        Self {
            token: gen_token(),
            expires: Instant::now() + ttl,
            ws_port,
            ips,
        }
    }

    pub fn is_valid(&self, token: &str) -> bool {
        Instant::now() < self.expires && self.token == token
    }

    pub fn qr_payload(&self, id: &Identity) -> String {
        let ips: Vec<String> = self.ips.iter().map(ToString::to_string).collect();
        let ws_data = json!({
            "cmd": 1,
            "ver": 2,
            "appVer": VER_NAME,
            "i3": 1,
            "deviceId": id.device_id,
            "realDeviceId": id.real_device_id,
            "deviceName": id.device_name,
            "serviceId": SERVICE_DEVICE_PAIRED,
            "token": self.token,
            "fp": id.fp_base64(),
            "wsPort": self.ws_port,
            "policies": [{ "wifi": ips }],
            "os": OS_WINDOWS,
            "type": TYPE_PC,
            "verCode": VER_CODE,
            "verName": VER_NAME,
            "bleAddress": "",
            "device": {
                "deviceId": id.device_id,
                "realDeviceId": id.real_device_id,
                "deviceName": id.device_name,
                "os": OS_WINDOWS,
                "type": TYPE_PC,
                "verCode": VER_CODE,
                "verName": VER_NAME,
                "bleAddress": ""
            }
        });
        let host_info = json!({ "wsData": ws_data, "version": "3.0.0" });
        format!("{QR_PREFIX}{host_info}")
    }
}

pub fn gen_token() -> String {
    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut rng = rand::thread_rng();
    B64.encode(bytes)
        .chars()
        .map(|c| match c {
            '=' | '+' | '/' => ALNUM[rng.gen_range(0..ALNUM.len())] as char,
            c => c,
        })
        .collect()
}

pub fn render_qr_png(payload: &str, path: &Path) -> Result<Vec<u8>> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)?;
    let image = code.render::<image::Luma<u8>>().min_dimensions(320, 320).build();
    let mut buf = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut buf);
    image.write_with_encoder(encoder)?;
    std::fs::write(path, &buf)?;
    Ok(buf)
}
