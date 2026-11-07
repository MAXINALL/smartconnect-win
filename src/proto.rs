use std::sync::atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const SERVICE_MANAGER: i64 = 0;
pub const SERVICE_FILE_EX: i64 = 2;
pub const SERVICE_CLIPBOARD: i64 = 9;
pub const SERVICE_DEVICE_PAIRED: i64 = 19;
pub const SERVICE_DEVICE_STATUS: i64 = 25;
pub const SERVICE_FILE_STATION: i64 = 168;

static NEXT_MSG_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WsMsg {
    #[serde(rename = "deviceId", default, skip_serializing_if = "String::is_empty")]
    pub device_id: String,
    #[serde(rename = "srcServiceId", default)]
    pub src_service_id: i64,
    #[serde(rename = "serviceId", default)]
    pub service_id: i64,
    #[serde(rename = "msgId", default, skip_serializing_if = "is_zero")]
    pub msg_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ver: Option<Value>,
    #[serde(rename = "senderId", default, skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<i64>,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

impl WsMsg {
    pub fn outgoing(device_id: &str, service_id: i64, data: Value) -> Self {
        Self {
            device_id: device_id.to_owned(),
            src_service_id: service_id,
            service_id,
            msg_id: NEXT_MSG_ID.fetch_add(1, Ordering::Relaxed),
            data: Some(data),
            ver: None,
            sender_id: None,
        }
    }
}

pub fn service_versions() -> Value {
    json!({
        "0": 3,
        "1": 10,
        "2": 3,
        "3": 3,
        "9": 4,
        "13": 1,
        "15": 16,
        "22": 2,
        "25": 1,
        "26": 1,
        "168": 2
    })
}

pub fn service_caps() -> Value {
    json!({
        "1": 2,
        "2": 2,
        "9": 3,
        "15": 3,
        "25": 1,
        "26": 2,
        "168": 2
    })
}

pub fn device_status_msg(device_name: &str) -> Value {
    let cap = json!({
        "1": 1,
        "2": 1,
        "3": 1,
        "9": 1,
        "13": 1,
        "15": 1,
        "22": 1,
        "25": 1,
        "26": 1,
        "168": 1
    });
    json!({
        "ver": "1",
        "cmd": 1,
        "cap": cap,
        "battery": 100,
        "deviceName": device_name,
        "realDeviceName": device_name,
        "model": "Windows PC"
    })
}

pub struct Hello<'a> {
    pub token: Option<&'a str>,
    pub cmd: Option<i64>,
    pub paired: Option<i64>,
    pub device_name: Option<&'a str>,
    pub real_device_id: Option<&'a str>,
}

impl<'a> Hello<'a> {
    pub fn parse(data: &'a Value) -> Self {
        let device = data.get("device");
        Self {
            token: data.get("token").and_then(Value::as_str),
            cmd: data.get("cmd").and_then(Value::as_i64),
            paired: data.get("paired").and_then(Value::as_i64),
            device_name: device.and_then(|d| d.get("deviceName")).and_then(Value::as_str),
            real_device_id: device.and_then(|d| d.get("realDeviceId")).and_then(Value::as_str),
        }
    }
}
