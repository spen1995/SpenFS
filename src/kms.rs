use anyhow::Context;
use std::path::Path;
use std::fs;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::os::unix::fs::OpenOptionsExt;

// KeyStore trait defines an abstraction for signing and key storage backed
// by an HSM/KMS or a local filesystem-based fallback. This is a scaffold;
// real providers (AWS KMS, Google KMS, PKCS#11, yubihsm, etc.) should implement
// `KeyStore` and be selectable at runtime via configuration.

pub trait KeyStore: Send + Sync {
    /// Sign bytes using the provider-managed private key. Implementations
    /// that do not have an on-device signing key may return an error.
    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// Store an encrypted/wrapped private key (short-term helper for
    /// KMS-wrapped key storage).
    fn store_wrapped_key(&self, _wrapped: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Simple filesystem-backed KeyStore used as the default implementation for
/// development and testing. It reads/writes `keys/signing.key.enc` directly.
pub struct FileKeyStore {
    root: std::path::PathBuf,
}

impl FileKeyStore {
    pub fn new(root: &Path) -> Self {
        FileKeyStore { root: root.to_path_buf() }
    }
}

impl KeyStore for FileKeyStore {
    fn sign(&self, _data: &[u8]) -> anyhow::Result<Vec<u8>> {
        Err(anyhow::anyhow!("FileKeyStore: signing via raw key not implemented; implement a KMS/HSM provider for signing"))
    }
}

/// Return the default KeyStore for the dataset root. In future this can be
/// made configurable to return an HSM-backed provider.
pub fn default_keystore(_dataset_root: &Path) -> Box<dyn KeyStore> {
    // If an AWS KMS Key ID is provided via env, attempt to return an AWS-backed
    // keystore (feature-gated). Otherwise return the filesystem fallback.
    if std::env::var("SPENFS_USE_ENCLAVE").is_ok() {
        #[cfg(feature = "enclave-se")]
        {
            if let Ok(ks) = crate::enclave_se::default_provider("spenfs-signing") {
                return ks;
            }
        }
    }
    if std::env::var("SPENFS_USE_PKCS11").is_ok() {
        #[cfg(feature = "pkcs11")]
        {
            if let Ok(ks) = crate::pkcs11::Provider::new("spenfs-signing") {
                return Box::new(ks);
            }
        }
    }
    if let Ok(kid) = std::env::var("AWS_KMS_KEY_ID") {
        #[cfg(feature = "aws-kms")]
        {
            if let Ok(ks) = AwsKmsKeyStore::new(&kid) {
                return Box::new(ks);
            }
        }
        // If feature not enabled or init failed, fall back to file keystore.
    }
    // Require explicit operator opt-in for falling back to the local filesystem
    // keystore to avoid silent software fallback when a hardware provider was
    // expected. Operators may set `SPENFS_ALLOW_FALLBACK=1` to permit the
    // filesystem fallback for debugging or single-host deployments.
    let allow_fallback = std::env::var("SPENFS_ALLOW_FALLBACK").map(|v| v == "1").unwrap_or(false);
    if allow_fallback {
        Box::new(FileKeyStore::new(_dataset_root))
    } else {
        panic!("No hardware KMS provider selected or available; fallback to local FileKeyStore is disabled. Set SPENFS_ALLOW_FALLBACK=1 to allow the filesystem fallback, or configure a provider via SPENFS_USE_ENCLAVE, SPENFS_USE_PKCS11, or AWS_KMS_KEY_ID.");
    }
}

// Feature-gated AWS KMS provider scaffold. To enable, build with `--features aws-kms`
#[cfg(feature = "aws-kms")]
mod aws_kms_impl {
    use super::*;
    use aws_config::meta::region::RegionProviderChain;
    use aws_sdk_kms::types::{SigningAlgorithmSpec, MessageType};
    use aws_sdk_kms::Client;
    use aws_smithy_types::Blob;

    pub struct AwsKmsKeyStore {
        client: Client,
        key_id: String,
    }

    impl AwsKmsKeyStore {
        pub fn new(key_id: &str) -> anyhow::Result<Self> {
            let rt = tokio::runtime::Runtime::new().context("create tokio runtime")?;
            let key = key_id.to_string();
            let config = rt.block_on(async {
                let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
                let conf = aws_config::from_env().region(region_provider).load().await;
                Ok::<_, anyhow::Error>(conf)
            })?;
            let client = Client::new(&config);
            Ok(AwsKmsKeyStore { client, key_id: key })
        }
    }

    impl KeyStore for AwsKmsKeyStore {
        fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
            let client = self.client.clone();
            let key_id = self.key_id.clone();
            let rt = tokio::runtime::Runtime::new().context("create tokio runtime")?;
            let res = rt.block_on(async move {
                let resp = client
                    .sign()
                    .key_id(key_id)
                    .message(Blob::from(data))
                    .message_type(MessageType::Raw)
                    .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512)
                    .send()
                    .await
                    .map_err(|e| anyhow::anyhow!("kms sign failed: {}", e))?;
                let sig = resp.signature().ok_or_else(|| anyhow::anyhow!("no signature returned"))?;
                Ok::<Vec<u8>, anyhow::Error>(sig.as_ref().to_vec())
            })?;
            Ok(res)
        }
    }
}

#[cfg(feature = "aws-kms")]
use aws_kms_impl::AwsKmsKeyStore;

/// Local-development KMS helpers: store a dataset-local KMS master key in the
/// user's home directory (`~/.spenfs_kms_master`) with mode 0600 and use it to
/// wrap/unwrap data. This is a short-term scaffold; production should use a
/// real KMS/HSM provider.
fn local_master_path() -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("no HOME env var for local master path"))?;
    Ok(std::path::PathBuf::from(home).join(".spenfs_kms_master"))
}

pub fn ensure_local_master() -> anyhow::Result<()> {
    let p = local_master_path()?;
    if p.exists() { return Ok(()); }
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).context("generate master key")?;
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true).mode(0o600);
    let mut f = opts.open(&p)?;
    f.write_all(&key)?;
    Ok(())
}

fn read_local_master() -> anyhow::Result<[u8;32]> {
    let p = local_master_path()?;
    let b = fs::read(&p).context("read local master key")?;
    if b.len() != 32 { return Err(anyhow::anyhow!("invalid master key length")); }
    let mut key = [0u8;32];
    key.copy_from_slice(&b);
    Ok(key)
}

/// Wrap input bytes using XChaCha20Poly1305 with the local master key.
pub fn wrap_bytes_with_local_master(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = read_local_master()?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let xnonce = XNonce::from_slice(&nonce);
    let ct = cipher.encrypt(xnonce, plaintext).map_err(|e| anyhow::anyhow!("wrap encrypt: {}", e))?;
    // store as nonce || ciphertext
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap bytes produced by `wrap_bytes_with_local_master`.
pub fn unwrap_bytes_with_local_master(wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
    if wrapped.len() < 24 { return Err(anyhow::anyhow!("wrapped too short")); }
    let key = read_local_master()?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let (nonce, ct) = wrapped.split_at(24);
    let xnonce = XNonce::from_slice(nonce);
    let pt = cipher.decrypt(xnonce, ct).map_err(|e| anyhow::anyhow!("unwrap decrypt: {}", e))?;
    Ok(pt)
}

use std::io::Write;

/// Wrap a file's contents and write to `out_path` with mode 0600.
pub fn wrap_file_to_file(in_path: &Path, out_path: &Path) -> anyhow::Result<()> {
    let data = fs::read(in_path)?;
    let wrapped = wrap_bytes_with_local_master(&data)?;
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true).mode(0o600);
    let mut f = opts.open(out_path)?;
    f.write_all(&wrapped)?;
    f.sync_all()?;
    Ok(())
}

/// Read a wrapped file and return the unwrapped bytes.
pub fn unwrap_file_to_vec(in_path: &Path) -> anyhow::Result<Vec<u8>> {
    let wrapped = fs::read(in_path)?;
    let pt = unwrap_bytes_with_local_master(&wrapped)?;
    Ok(pt)
}
