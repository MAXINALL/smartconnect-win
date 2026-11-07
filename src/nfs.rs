use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use anyhow::{Context, Result, bail};
use nfs3_client::net::Connector;
use nfs3_client::tokio::TokioIo;
use nfs3_client::{Nfs3Connection, Nfs3ConnectionBuilder};
use nfs3_types::nfs3::{
    diropargs3, filename3, ftype3, Nfs3Option, Nfs3Result, LOOKUP3args, READ3args,
    READDIRPLUS3args,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;

use crate::identity::Identity;

pub type NfsConn = Nfs3Connection<TokioIo<tokio_rustls::client::TlsStream<TcpStream>>>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NfsEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MountTarget {
    pub ip: String,
    pub mount_port: u16,
    pub nfs_port: u16,
    pub fingerprint: String,
    pub path: String,
}

#[derive(Debug)]
struct FingerprintVerifier {
    expected: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = hex::encode(Sha256::digest(end_entity.as_ref()));
        if got.eq_ignore_ascii_case(&self.expected) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "fingerprint mismatch: got {}, expected {}",
                got, self.expected
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_signature(cert, message, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_signature(cert, message, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub(crate) fn verify_signature(
    cert: &CertificateDer<'_>,
    message: &[u8],
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    use ring::signature;
    let bad = |m: &str| rustls::Error::General(m.to_string());
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|_| bad("could not parse phone certificate"))?;
    let key = parsed.public_key().subject_public_key.data.as_ref();
    let alg: &dyn signature::VerificationAlgorithm = match dss.scheme {
        SignatureScheme::RSA_PKCS1_SHA256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512 => &signature::RSA_PKCS1_2048_8192_SHA512,
        SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_2048_8192_SHA256,
        SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_2048_8192_SHA384,
        SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_2048_8192_SHA512,
        SignatureScheme::ECDSA_NISTP256_SHA256 => &signature::ECDSA_P256_SHA256_ASN1,
        SignatureScheme::ECDSA_NISTP384_SHA384 => &signature::ECDSA_P384_SHA384_ASN1,
        SignatureScheme::ED25519 => &signature::ED25519,
        other => return Err(bad(&format!("unsupported scheme {other:?}"))),
    };
    signature::UnparsedPublicKey::new(alg, key)
        .verify(message, dss.signature())
        .map(|()| HandshakeSignatureValid::assertion())
        .map_err(|_| bad("phone handshake signature failed"))
}

pub fn client_config(id: &Identity, phone_fingerprint: &str) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(FingerprintVerifier {
        expected: phone_fingerprint.to_string(),
        provider: provider.clone(),
    });
    let cert_chain = vec![id.cert_der.clone()];
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(cert_chain, id.key_der.clone_key())
        .context("installing client cert")?;
    Ok(Arc::new(config))
}

pub struct TlsNfsConnector {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl TlsNfsConnector {
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self {
            config,
            server_name: ServerName::try_from("smartconnect-phone").expect("static name"),
        }
    }

    async fn tls(&self, stream: TcpStream) -> std::io::Result<TokioIo<tokio_rustls::client::TlsStream<TcpStream>>> {
        let connector = TlsConnector::from(self.config.clone());
        let tls = connector.connect(self.server_name.clone(), stream).await?;
        Ok(TokioIo::new(tls))
    }
}

impl Connector for TlsNfsConnector {
    type Connection = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;

    async fn connect(&self, addr: SocketAddr) -> std::io::Result<Self::Connection> {
        let stream = TcpStream::connect(addr).await?;
        self.tls(stream).await
    }

    async fn connect_with_port(&self, addr: SocketAddr, local_port: u16) -> std::io::Result<Self::Connection> {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), local_port))?;
        let stream = socket.connect(addr).await?;
        self.tls(stream).await
    }
}

pub async fn connect_nfs(id: &Identity, t: &MountTarget) -> Result<NfsConn> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = client_config(id, &t.fingerprint)?;
    let connector = TlsNfsConnector::new(config);
    Nfs3ConnectionBuilder::new(connector, &t.ip, &t.path)
        .mount_port(t.mount_port)
        .nfs3_port(t.nfs_port)
        .connect_from_privileged_port(false)
        .mount()
        .await
        .context("mounting tablet NFS export over TLS")
}

pub async fn list_directory(id: &Identity, target: &MountTarget, rel_path: &str) -> Result<Vec<NfsEntry>> {
    let mut conn = connect_nfs(id, target).await?;
    let mut dir_fh = conn.root_nfs_fh3();

    let clean = rel_path.trim_start_matches("/sdcard").trim_start_matches('/');
    for part in clean.split('/') {
        if !part.is_empty() {
            let args = LOOKUP3args {
                what: diropargs3 {
                    dir: dir_fh,
                    name: filename3::from(part.as_bytes().to_vec()),
                },
            };
            match conn.lookup(&args).await.context("LOOKUP dir part")? {
                Nfs3Result::Ok(ok) => {
                    dir_fh = ok.object;
                }
                Nfs3Result::Err((c, _)) => {
                    bail!("lookup error for {}: {:?}", part, c);
                }
            }
        }
    }

    let args = READDIRPLUS3args {
        dir: dir_fh,
        cookie: 0,
        cookieverf: Default::default(),
        dircount: 8192,
        maxcount: 32768,
    };

    let mut out = Vec::new();
    match conn.readdirplus(&args).await.context("READDIRPLUS")? {
        Nfs3Result::Ok(ok) => {
            for entry in ok.reply.entries.into_inner() {
                let name = String::from_utf8_lossy(entry.name.0.as_ref()).to_string();
                if name != "." && name != ".." {
                    let is_dir = match &entry.name_attributes {
                        Nfs3Option::Some(attr) => attr.type_ == ftype3::NF3DIR,
                        Nfs3Option::None => false,
                    };
                    let size = match &entry.name_attributes {
                        Nfs3Option::Some(attr) => attr.size,
                        Nfs3Option::None => 0,
                    };
                    out.push(NfsEntry { name, is_dir, size });
                }
            }
        }
        Nfs3Result::Err((c, _)) => {
            bail!("readdirplus error: {:?}", c);
        }
    }

    conn.unmount().await.ok();
    Ok(out)
}

pub async fn download_nfs_file(
    id: &Identity,
    target: &MountTarget,
    remote_path: &str,
    local_path: &Path,
) -> Result<u64> {
    let mut conn = connect_nfs(id, target).await?;
    let mut curr_fh = conn.root_nfs_fh3();

    let clean = remote_path.trim_start_matches("/sdcard").trim_start_matches('/');
    let parts: Vec<&str> = clean.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        bail!("empty file path");
    }

    for part in parts {
        let args = LOOKUP3args {
            what: diropargs3 {
                dir: curr_fh,
                name: filename3::from(part.as_bytes().to_vec()),
            },
        };
        match conn.lookup(&args).await.context("LOOKUP file")? {
            Nfs3Result::Ok(ok) => {
                curr_fh = ok.object;
            }
            Nfs3Result::Err((c, _)) => {
                bail!("lookup error for {}: {:?}", part, c);
            }
        }
    }

    let mut file = tokio::fs::File::create(local_path).await?;
    let mut offset = 0u64;
    let chunk_size = 65536u32;
    let mut total_bytes = 0u64;

    loop {
        let args = READ3args {
            file: curr_fh.clone(),
            offset,
            count: chunk_size,
        };
        match conn.read(&args).await.context("READ chunk")? {
            Nfs3Result::Ok(ok) => {
                let data = ok.data.as_ref();
                if data.is_empty() {
                    break;
                }
                file.write_all(data).await?;
                total_bytes += data.len() as u64;
                offset += data.len() as u64;
                if ok.eof {
                    break;
                }
            }
            Nfs3Result::Err((c, _)) => {
                bail!("read error at offset {}: {:?}", offset, c);
            }
        }
    }

    file.flush().await?;
    conn.unmount().await.ok();
    Ok(total_bytes)
}
