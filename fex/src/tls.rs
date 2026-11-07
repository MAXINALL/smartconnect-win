//! TLS to the phone's fex server, pinned by certificate fingerprint.
//!
//! The server presents a fresh self-signed certificate per transfer (RSA-2048, subject
//! `CN=Lenovo`); the offer carries `fingerprint` = lowercase hex `SHA-256(certificate DER)`. Nothing
//! chains to a CA and there is no hostname, so the verifier checks the pin only and then checks the
//! handshake signature against that pinned certificate. No client certificate is sent.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{self, ClientConfig, DigitallySignedStruct, SignatureScheme};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Lowercase hex `SHA-256(der)`, the form the phone advertises.
pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Normalises an advertised fingerprint: hex digits only (separators dropped), lowercase. `None`
/// unless it is exactly 32 bytes.
pub fn normalize_fingerprint(fp: &str) -> Option<String> {
    let hex: String = fp.chars().filter(|c| !matches!(c, ':' | ' ' | '-')).collect::<String>().to_ascii_lowercase();
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hex)
}

#[derive(Debug)]
struct PinnedVerifier {
    expected: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if fingerprint(end_entity.as_ref()) == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("fex server certificate does not match the advertised fingerprint".into()))
        }
    }

    // The pin fixes the certificate; these prove the server holds its private key.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A rustls client config that accepts only the certificate whose fingerprint is `fp`. ALPN offers
/// `http/1.1` only: the server also speaks h2, which a WebSocket upgrade can't use.
pub fn client_config(fp: &str) -> Result<Arc<ClientConfig>> {
    let Some(expected) = normalize_fingerprint(fp) else {
        bail!("the advertised fingerprint is not a SHA-256 hex digest");
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("selecting TLS versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { expected, provider }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Opens a pinned TLS connection to `addr`.
pub async fn connect(addr: SocketAddr, config: Arc<ClientConfig>) -> Result<TlsStream<TcpStream>> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .with_context(|| format!("connecting to {addr}: timed out"))?
        .with_context(|| format!("connecting to {addr}"))?;
    let _ = tcp.set_nodelay(true);
    let name = ServerName::IpAddress(addr.ip().into());
    tokio::time::timeout(CONNECT_TIMEOUT, TlsConnector::from(config).connect(name, tcp))
        .await
        .context("TLS handshake timed out")?
        .context("TLS handshake with the fex server")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_known_answers() {
        // SHA-256 test vectors (FIPS 180-2): "" and "abc".
        assert_eq!(fingerprint(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(fingerprint(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn normalizes_fingerprints() {
        let lower = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(normalize_fingerprint(&lower.to_uppercase()).as_deref(), Some(lower));
        let colons: Vec<String> = lower.as_bytes().chunks(2).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
        assert_eq!(normalize_fingerprint(&colons.join(":")).as_deref(), Some(lower));
        assert_eq!(normalize_fingerprint("abc"), None);
        assert_eq!(normalize_fingerprint(&"zz".repeat(32)), None);
        assert!(client_config("not-a-fingerprint").is_err());
    }
}
