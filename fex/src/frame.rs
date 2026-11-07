//! The fex WebSocket control frames.
//!
//! Every frame is one WebSocket **text** message of the form
//!
//! ```text
//! <kind>:<id>:<name>[?<json object>]
//! ```
//!
//! * `kind` is `action` (a request) or `ack` (the reply to the action with the same `id`);
//! * `id` is a token without whitespace or `:`; the server numbers its actions `Server1001`,
//!   `Server1002`, … and accepts client ids of the form `Client<n>`;
//! * `name` is one of `versionNegotiation`, `sendRequest`, `status`, `message`;
//! * the JSON payload is optional (an ack of `status` carries none).
//!
//! See `docs/protocol/file-exchange.md` §3 for the sequence.

use std::fmt;

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The protocol version this client speaks (the phone offers 1).
pub const VERSION: u32 = 1;

/// `status` type 0: accepted / in progress (the phone fires `onProgress` with 0 bytes done).
pub const STATUS_STARTED: i64 = 0;
/// `status` type 1: the receiver has the files (the phone fires `onComplete`).
pub const STATUS_COMPLETE: i64 = 1;
/// `status` type 2: the receiver failed (the phone fires `onFailure` with code 2 and the `reason`;
/// 3 behaves the same way).
pub const STATUS_FAILED: i64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Action,
    Ack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Name {
    VersionNegotiation,
    SendRequest,
    Status,
    Message,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Action => "action",
            Kind::Ack => "ack",
        }
    }
}

impl Name {
    fn as_str(self) -> &'static str {
        match self {
            Name::VersionNegotiation => "versionNegotiation",
            Name::SendRequest => "sendRequest",
            Name::Status => "status",
            Name::Message => "message",
        }
    }

    fn parse(s: &str) -> Option<Name> {
        Some(match s {
            "versionNegotiation" => Name::VersionNegotiation,
            "sendRequest" => Name::SendRequest,
            "status" => Name::Status,
            "message" => Name::Message,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub id: String,
    pub name: Name,
    /// The JSON object after `?`, verbatim.
    pub payload: Option<String>,
}

impl Frame {
    pub fn action(id: impl Into<String>, name: Name, payload: Option<String>) -> Frame {
        Frame { kind: Kind::Action, id: id.into(), name, payload }
    }

    pub fn ack(id: impl Into<String>, name: Name, payload: Option<String>) -> Frame {
        Frame { kind: Kind::Ack, id: id.into(), name, payload }
    }

    /// Parses one text message. Trailing data that isn't a JSON object is ignored, as the phone's
    /// own parser does.
    pub fn parse(text: &str) -> Result<Frame> {
        let (kind, rest) = text.split_once(':').context("fex frame without ':'")?;
        let kind = match kind {
            "action" => Kind::Action,
            "ack" => Kind::Ack,
            other => bail!("unknown fex frame kind {other:?}"),
        };
        let (id, rest) = rest.split_once(':').context("fex frame without a name")?;
        if id.is_empty() || id.chars().any(char::is_whitespace) {
            bail!("bad fex frame id {id:?}");
        }
        let (name, payload) = match rest.split_once('?') {
            Some((n, p)) => (n, Some(p)),
            None => (rest, None),
        };
        let name = Name::parse(name).with_context(|| format!("unknown fex frame name {name:?}"))?;
        let payload = payload.filter(|p| p.starts_with('{') && p.ends_with('}')).map(str::to_owned);
        Ok(Frame { kind, id: id.to_owned(), name, payload })
    }

    /// Decodes the JSON payload.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        let p = self.payload.as_deref().with_context(|| format!("{} frame without a payload", self.name.as_str()))?;
        serde_json::from_str(p).with_context(|| format!("decoding the {} payload", self.name.as_str()))
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.kind.as_str(), self.id, self.name.as_str())?;
        if let Some(p) = &self.payload {
            write!(f, "?{p}")?;
        }
        Ok(())
    }
}

/// `versionNegotiation` payload, in both directions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionNegotiation {
    pub version: u32,
}

/// `sendRequest` payload: the transfer the phone offers. `id` is the task id for `/download`;
/// `total_size` is the size of the zip that `/download` returns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    pub id: String,
    #[serde(default)]
    pub sender_id: String,
    #[serde(default)]
    pub sender_name: String,
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub file_count: u64,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub total_size: u64,
    #[serde(default, rename = "file")]
    pub files: Vec<FileEntry>,
}

/// One file of a [`SendRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub name: String,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub dir: bool,
    #[serde(default)]
    pub index: i64,
}

/// `status` payload, client → server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub task_id: String,
    #[serde(rename = "type")]
    pub kind: i64,
    #[serde(default)]
    pub reason: String,
}

/// Hands out `Client1001`, `Client1002`, … for the client's own actions.
#[derive(Debug)]
pub struct ClientIds(u32);

impl Default for ClientIds {
    fn default() -> Self {
        ClientIds(1000)
    }
}

impl ClientIds {
    pub fn next_id(&mut self) -> String {
        self.0 += 1;
        format!("Client{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shapes as seen on the wire; ids, names and sizes are placeholders.
    const VN: &str = r#"action:Server1001:versionNegotiation?{"version":1}"#;
    const SR: &str = r#"action:Server1002:sendRequest?{"id":"TASK0000000001","senderId":"<device-id>","senderName":"","fileName":"a.b_a.b.Main.png","fileCount":2,"mimeType":"*/*","totalSize":420,"file":[{"name":"a.b_a.b.Main.png","mimeType":"image/png","size":100,"dir":false,"index":0},{"name":"10_c.d_c.d.Main.png","mimeType":"image/png","size":120,"dir":false,"index":0}]}"#;

    #[test]
    fn parses_version_negotiation() {
        let f = Frame::parse(VN).unwrap();
        assert_eq!(f.kind, Kind::Action);
        assert_eq!(f.id, "Server1001");
        assert_eq!(f.name, Name::VersionNegotiation);
        assert_eq!(f.json::<VersionNegotiation>().unwrap(), VersionNegotiation { version: 1 });
        assert_eq!(f.to_string(), VN);
    }

    #[test]
    fn parses_send_request() {
        let f = Frame::parse(SR).unwrap();
        assert_eq!((f.kind, f.name, f.id.as_str()), (Kind::Action, Name::SendRequest, "Server1002"));
        let r: SendRequest = f.json().unwrap();
        assert_eq!(r.id, "TASK0000000001");
        assert_eq!(r.file_count, 2);
        assert_eq!(r.total_size, 420);
        assert_eq!(r.files[1].name, "10_c.d_c.d.Main.png");
        assert_eq!(f.to_string(), SR);
    }

    #[test]
    fn encodes_client_frames_exactly() {
        // The acks and the completion status this client sends (known-answer strings).
        let ack = Frame::ack("Server1001", Name::VersionNegotiation, Some(r#"{"version":1}"#.into()));
        assert_eq!(ack.to_string(), r#"ack:Server1001:versionNegotiation?{"version":1}"#);
        assert_eq!(Frame::ack("Server1002", Name::SendRequest, Some("{}".into())).to_string(), "ack:Server1002:sendRequest?{}");
        let st = Status { task_id: "TASK0000000001".into(), kind: STATUS_COMPLETE, reason: String::new() };
        let mut ids = ClientIds::default();
        let f = Frame::action(ids.next_id(), Name::Status, Some(serde_json::to_string(&st).unwrap()));
        assert_eq!(f.to_string(), r#"action:Client1001:status?{"taskId":"TASK0000000001","type":1,"reason":""}"#);
        assert_eq!(ids.next_id(), "Client1002");
    }

    #[test]
    fn parses_bare_ack() {
        let f = Frame::parse("ack:Client1001:status").unwrap();
        assert_eq!((f.kind, f.name, f.id.as_str(), f.payload), (Kind::Ack, Name::Status, "Client1001", None));
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["", "hello", "action:Server1:bogus", "nope:Server1:status", "action::status", "action:a b:status"] {
            assert!(Frame::parse(bad).is_err(), "{bad:?} parsed");
        }
        // A non-object payload is dropped, not an error.
        assert_eq!(Frame::parse("ack:X1:status?oops").unwrap().payload, None);
    }
}
