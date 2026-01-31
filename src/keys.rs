use std::path::Path;
use std::io::Write;
use anyhow::Context;
use crate::ed25519_compat::Keypair;
use zeroize::Zeroize;

/// Load the encrypted signing key from `keys/signing.key.enc`, prompt for passphrase
/// (or use `SPENFS_PW`), decrypt and return an `ed25519_dalek::Keypair`.
pub fn load_signing_key(dataset_root: &Path) -> anyhow::Result<Keypair> {
    let keys_dir = dataset_root.join("keys");
    let enc_path = keys_dir.join("signing.key.enc");
    let enc_kms = keys_dir.join("signing.key.kms");
    let enc = if enc_kms.exists() {
        // unwrap via local KMS scaffold
        crate::kms::unwrap_file_to_vec(&enc_kms).with_context(|| format!("unwrap kms signing key: {}", enc_kms.display()))?
    } else {
        std::fs::read(&enc_path).with_context(|| format!("read encrypted signing key: {}", enc_path.display()))?
    };

    // derive passphrase using secure retrieval helper (keyring or passphrase file).
    let pass = crate::passphrase::retrieve_passphrase(dataset_root)?;

    // read header to get salt and dataset_id for AAD
    let hdr = crate::on_disk::read_header(dataset_root).context("read header for key decrypt")?;
    let aead_key = crate::crypto::derive_key(pass.as_bytes(), &hdr.salt)?;
    let mut sb = crate::crypto::aead_decrypt(&aead_key, &enc, &hdr.dataset_id).context("decrypt signing key")?;

    // secret key bytes expected 32
    let sbytes = sb.as_slice();
    if sbytes.len() != 32 {
        return Err(anyhow::anyhow!("unexpected signing key length: {}", sbytes.len()));
    }
    let mut skb = [0u8; 32];
    skb.copy_from_slice(&sbytes[..32]);
    let kp = Keypair::from_secret_bytes(&skb).context("secret key from bytes")?;
    // clear secure memory and stack copy
    // clear inner secure memory
    sb.0.clear();
    skb.zeroize();
    Ok(kp)
}

/// Re-encrypt an existing signing key with a new passphrase. Loads current key,
/// prompts for new passphrase (confirm), and writes `keys/signing.key.enc`.
pub fn change_signing_key_passphrase(dataset_root: &Path) -> anyhow::Result<()> {
    let kp = load_signing_key(dataset_root)?;

    // prompt new passphrase twice
    let np1 = rpassword::prompt_password("Enter new passphrase: ")?;
    let np2 = rpassword::prompt_password("Confirm new passphrase: ")?;
    if np1 != np2 {
        return Err(anyhow::anyhow!("passphrases do not match"));
    }

    // derive aead key and encrypt secret
    let hdr = crate::on_disk::read_header(dataset_root)?;
    let aead_key = crate::crypto::derive_key(np1.as_bytes(), &hdr.salt)?;
    let sk_bytes = kp.secret_to_bytes();
    let enc = crate::crypto::aead_encrypt(&aead_key, &sk_bytes, &hdr.dataset_id)?;

    let keys_dir = dataset_root.join("keys");
    std::fs::create_dir_all(&keys_dir)?;
    let enc_path = keys_dir.join("signing.key.enc");
    // write via secure tmp file then rename
    let tmp = enc_path.with_extension("tmp");
    let mut f = crate::hardening::create_tmp_file_secure(&tmp)?;
    f.write_all(&enc)?;
    f.sync_all()?;
    std::fs::rename(&tmp, &enc_path)?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&enc_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&enc_path, perms)?;
    }

    // Optionally produce a KMS-wrapped copy for short-term KMS integration.
    let _ = maybe_wrap_with_local_kms(dataset_root, &enc_path);

    Ok(())
}

/// Optionally produce a KMS-wrapped copy of the encrypted signing key using
/// the local KMS scaffold when `SPENFS_USE_LOCAL_KMS=1` is set. This writes
/// `keys/signing.key.kms` next to `signing.key.enc`.
fn maybe_wrap_with_local_kms(dataset_root: &std::path::Path, enc_path: &std::path::Path) -> anyhow::Result<()> {
    if std::env::var("SPENFS_USE_LOCAL_KMS").ok().as_deref() == Some("1") {
        // ensure master exists
        crate::kms::ensure_local_master()?;
        let wrapped_path = enc_path.with_extension("kms");
        crate::kms::wrap_file_to_file(enc_path, &wrapped_path)?;
    }
    Ok(())
}

/// Public helper to wrap existing `keys/signing.key.enc` into a KMS-wrapped
/// file `keys/signing.key.kms` using the local KMS scaffold.
pub fn kms_wrap(dataset_root: &Path) -> anyhow::Result<()> {
    let keys_dir = dataset_root.join("keys");
    let enc_path = keys_dir.join("signing.key.enc");
    if !enc_path.exists() {
        return Err(anyhow::anyhow!("encrypted signing key not found"));
    }
    crate::kms::ensure_local_master()?;
    let wrapped_path = enc_path.with_extension("kms");
    crate::kms::wrap_file_to_file(&enc_path, &wrapped_path)?;
    Ok(())
}
