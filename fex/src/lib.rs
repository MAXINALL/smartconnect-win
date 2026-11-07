//! Client for the phone's **fex** file-transfer server.
//!
//! When Smart Connect on the phone "sends" files to the PC it does not push them: its Go
//! file-transfer library zips them, starts a short-lived HTTPS server on a random port and
//! advertises `port` + certificate `fingerprint` (+ a `token`) over the control WebSocket. The PC
//! then pulls:
//!
//! 1. TLS to `phone:port`, the server certificate pinned by `SHA-256(DER)` ([`tls`]).
//! 2. WebSocket `GET /websocket`; the server sends `versionNegotiation`, then `sendRequest` (the
//!    task id and file list), each acknowledged by the client ([`frame`]).
//! 3. Plain HTTPS `GET /download?taskId=<id>` returns the whole transfer as one zip ([`http`],
//!    [`zip`]).
//! 4. The client reports `status` type 1 (complete) on the WebSocket, which the phone acks.
//!
//! [`client::pull`] runs that sequence for any offer. [`icons`] uses it for the service 17 app list
//! (app icons for the Apps page) and for clipboard images from the phone (service 2
//! `FileExSendData`). [`server`] is the sending side, for clipboard images to the phone. Wire details:
//! `docs/protocol/file-exchange.md` §3.

pub mod client;
pub mod frame;
pub mod http;
#[cfg(unix)]
pub mod icons;
pub mod server;
pub mod tls;
pub mod zip;

#[cfg(test)]
mod mock_tests;
