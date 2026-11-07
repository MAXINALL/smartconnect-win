use std::fs;
use std::path::Path;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use rsa::pkcs8::EncodePrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

const IDENTITY_FILE: &str = "identity.json";
const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StoredIdentity {
    pub device_id: String,
    pub real_device_id: String,
    pub device_name: String,
}

pub struct Identity {
    pub device_id: String,
    pub real_device_id: String,
    pub device_name: String,
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub fingerprint: [u8; 32],
}

impl Identity {
    pub fn load_or_create(dir: &Path, name_override: Option<String>) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let id_path = dir.join(IDENTITY_FILE);
        let mut stored: StoredIdentity = if id_path.exists() {
            serde_json::from_slice(&fs::read(&id_path)?).context("parsing identity.json")?
        } else {
            StoredIdentity {
                device_id: random_id(),
                real_device_id: random_id(),
                device_name: default_device_name(),
            }
        };

        if let Some(name) = name_override {
            stored.device_name = name;
        }
        fs::write(&id_path, serde_json::to_vec_pretty(&stored)?)?;

        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        let (cert_pem, key_pem) = if cert_path.exists() && key_path.exists() {
            (fs::read(&cert_path)?, fs::read(&key_path)?)
        } else {
            tracing::info!("generating RSA-2048 self-signed certificate");
            let (c, k) = generate_cert(&stored.device_name)?;
            fs::write(&cert_path, &c)?;
            fs::write(&key_path, &k)?;
            (c.into_bytes(), k.into_bytes())
        };

        let cert_der = CertificateDer::from_pem_slice(&cert_pem).context("parsing cert.pem")?;
        let key_der = PrivateKeyDer::from_pem_slice(&key_pem).context("parsing key.pem")?;
        let fingerprint: [u8; 32] = Sha256::digest(cert_der.as_ref()).into();

        Ok(Self {
            device_id: nonce_id(&stored.real_device_id),
            real_device_id: stored.real_device_id,
            device_name: stored.device_name,
            cert_der,
            key_der,
            cert_pem,
            key_pem,
            fingerprint,
        })
    }

    pub fn fp_base64(&self) -> String {
        B64.encode(self.fingerprint)
    }

    pub fn fp_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }

    pub fn serial_number(&self) -> String {
        let h = hex::encode(&Sha256::digest(self.real_device_id.as_bytes())[..16]);
        format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
    }
}

pub fn nonce_id(real_id_b64: &str) -> String {
    let mut salt = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    B64.encode(salted(real_id_b64, &salt))
}

pub fn is_nonce_of(nonce: &[u8], real_id_b64: &str) -> bool {
    nonce.len() == 16 && salted(real_id_b64, &nonce[..8])[..] == nonce[..]
}

fn salted(real_id_b64: &str, salt: &[u8]) -> Vec<u8> {
    let real = B64.decode(real_id_b64).unwrap_or_else(|_| real_id_b64.as_bytes().to_vec());
    let mut h = Sha256::new();
    h.update(&real);
    h.update(salt);
    [salt, &h.finalize()[..8]].concat()
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}

fn default_device_name() -> String {
    "MAXINALL".to_string()
}

fn generate_cert(device_name: &str) -> Result<(String, String)> {
    let rsa_key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)?;
    let pkcs8 = rsa_key.to_pkcs8_der()?;
    let pkcs8 = rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_RSA_SHA256)?;

    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::OrganizationName, "smartconnect-win");
    dn.push(rcgen::DnType::CommonName, device_name);
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2045, 1, 1);
    let mut serial = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut serial);
    serial[0] &= 0x7f;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));

    let cert = params.self_signed(&key_pair)?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}
