use serde::{Serialize, Deserialize};
use base64::{engine::general_purpose, Engine as _};
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::Aead, KeyInit};
use rand::rngs::OsRng;
use std::path::Path;
use std::fs;
use anyhow::Context;

#[derive(Serialize, Deserialize)]
pub struct RecipientEntry {
    pub id: String,
    pub alg: String,
    pub ephemeral_pk_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Envelope {
    pub version: u8,
    pub recipients: Vec<RecipientEntry>,
    pub recipients_sig_b64: Option<String>,
}

pub fn add_recipient(master_path: &Path, wrapped_path: &Path, recipient_pk: &[u8], id: &str) -> anyhow::Result<()> {
    let master = fs::read(master_path).context("read master key")?;
    let mut env = if wrapped_path.exists() {
        let s = fs::read_to_string(wrapped_path).context("read wrapped file")?;
        serde_json::from_str::<Envelope>(&s).context("parse envelope")?
    } else { Envelope { version: 1, recipients: vec![], recipients_sig_b64: None } };

    // generate ephemeral x25519 key (use getrandom to avoid rand_core version conflicts)
    let mut esk_bytes = [0u8; 32];
    getrandom::getrandom(&mut esk_bytes).context("ephemeral key gen")?;
    let ephemeral_sk = StaticSecret::from(esk_bytes);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);

    // compute shared secret
    let recipient_pk = PublicKey::from(<[u8;32]>::try_from(recipient_pk).map_err(|_| anyhow::anyhow!("recipient pk must be 32 bytes"))?);
    let shared = ephemeral_sk.diffie_hellman(&recipient_pk);

    // derive symmetric key
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"spenfs-envelope", &mut okm).map_err(|_| anyhow::anyhow!("hkdf expand failed"))?;

    let cipher = XChaCha20Poly1305::new(&okm.into());
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).context("nonce gen")?;
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), master.as_ref()).map_err(|e| anyhow::anyhow!("encrypt failed: {}", e))?;

    // store as nonce || ct
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);

    let entry = RecipientEntry {
        id: id.to_string(),
        alg: "X25519_XChaCha20Poly1305".to_string(),
        ephemeral_pk_b64: general_purpose::URL_SAFE_NO_PAD.encode(ephemeral_pk.as_bytes()),
        ciphertext_b64: general_purpose::URL_SAFE_NO_PAD.encode(&out),
    };

    env.recipients.push(entry);
    let s = serde_json::to_string_pretty(&env).context("serialize envelope")?;
    fs::write(wrapped_path, s).context("write wrapped file")?;
    Ok(())
}

// Sign the envelope's recipients array using an Ed25519 seed file (32 bytes).
pub fn sign_recipient_list(wrapped_path: &Path, operator_seed_path: &Path) -> anyhow::Result<()> {
    let s = fs::read_to_string(wrapped_path).context("read wrapped file")?;
    let mut env: Envelope = serde_json::from_str(&s).context("parse envelope")?;
    // load operator seed
    let b = fs::read(operator_seed_path).context("read operator seed")?;
    if b.len() != 32 { return Err(anyhow::anyhow!("operator seed must be 32 bytes")); }
    let mut arr = [0u8;32]; arr.copy_from_slice(&b[..32]);
    let kpair = crate::ed25519_compat::Keypair::from_seed_bytes(&arr)?;

    // canonicalize the data to sign: (version, recipients)
    let to_sign = serde_json::to_vec(&(&env.version, &env.recipients)).context("serialize recipients for signing")?;
    let sig = crate::crypto::ed25519_sign_bytes(&kpair, &to_sign);
    env.recipients_sig_b64 = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sig));
    let s2 = serde_json::to_string_pretty(&env).context("serialize signed envelope")?;
    fs::write(wrapped_path, s2).context("write signed envelope")?;
    Ok(())
}

pub fn verify_recipient_list(wrapped_path: &Path, operator_pubkey: &[u8]) -> anyhow::Result<()> {
    let s = fs::read_to_string(wrapped_path).context("read wrapped file")?;
    let env: Envelope = serde_json::from_str(&s).context("parse envelope")?;
    let sig_b64 = env.recipients_sig_b64.ok_or_else(|| anyhow::anyhow!("no recipients_sig present"))?;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig_b64).map_err(|e| anyhow::anyhow!("sig decode: {}", e))?;
    let to_verify = serde_json::to_vec(&(&env.version, &env.recipients)).context("serialize recipients for verify")?;
    crate::crypto::ed25519_verify_bytes(operator_pubkey, &to_verify, &sig)
}

pub fn try_unlock_with_x25519_private(wrapped_path: &Path, privkey: &[u8], operator_pubkey: Option<&[u8]>) -> anyhow::Result<Vec<u8>> {
    let s = fs::read_to_string(wrapped_path).context("read wrapped file")?;
    let env: Envelope = serde_json::from_str(&s).context("parse envelope")?;
    if let Some(opk) = operator_pubkey {
        verify_recipient_list(wrapped_path, opk)?;
    }
    let sk = StaticSecret::from(<[u8;32]>::try_from(privkey).map_err(|_| anyhow::anyhow!("privkey must be 32 bytes"))?);
    for e in env.recipients.iter() {
        if e.alg != "X25519_XChaCha20Poly1305" { continue; }
        let eph = general_purpose::URL_SAFE_NO_PAD.decode(&e.ephemeral_pk_b64).ok();
        let ct = general_purpose::URL_SAFE_NO_PAD.decode(&e.ciphertext_b64).ok();
        if eph.is_none() || ct.is_none() { continue; }
        let eph = eph.unwrap();
        let ct = ct.unwrap();
        if eph.len() != 32 || ct.len() < 24 { continue; }
        let eph_pk = PublicKey::from(<[u8;32]>::try_from(eph.as_slice()).unwrap());
        let shared = sk.diffie_hellman(&eph_pk);
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut okm = [0u8;32];
        if hk.expand(b"spenfs-envelope", &mut okm).is_err() { continue; }
        let cipher = XChaCha20Poly1305::new(&okm.into());
        let nonce = &ct[0..24];
        let ctdata = &ct[24..];
        if let Ok(pt) = cipher.decrypt(XNonce::from_slice(nonce), ctdata) {
            return Ok(pt);
        }
    }
    Err(anyhow::anyhow!("no recipient could decrypt"))
}
