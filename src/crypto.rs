use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use crate::ed25519_compat::{Keypair, PublicKey};
use ed25519_dalek::{Signature, Verifier};
use getrandom::getrandom;
use zeroize::Zeroize;
use crate::hardening::SecureMemory;
// rand::rngs::OsRng previously used; not required after switching to getrandom seed

pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let params = argon2::Params::new(65536, 3, 1, None).map_err(|e| anyhow::anyhow!("argon2 params: {}", e))?;
    let mut out = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2 failed: {}", e))?;
    Ok(out)
}

pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("getrandom failed: {}", e))?;
    let nonce_obj = XNonce::from_slice(&nonce);
    let ct = cipher
        .encrypt(nonce_obj, Payload { msg: plaintext, aad })
        .map_err(|e| anyhow::anyhow!("aead encrypt failed: {}", e))?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    // zeroize nonce
    nonce.zeroize();
    Ok(out)
}

pub fn aead_decrypt(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> anyhow::Result<crate::hardening::SecretBytes> {
    if payload.len() < 24 {
        return Err(anyhow::anyhow!("payload too short"));
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&payload[..24]);
    let ct = &payload[24..];
    let pt = cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|e| anyhow::anyhow!("aead decrypt failed: {}", e))?;
    // Move plaintext into secure memory wrapper
    let sb = crate::hardening::SecretBytes::from_vec(pt)?;
    Ok(sb)
}

pub fn ed25519_generate() -> anyhow::Result<Keypair> {
    let sm = SecureMemory::random(32).map_err(|e| anyhow::anyhow!("secure alloc failed: {}", e))?;
    let seed_slice = sm.as_slice();
    if seed_slice.len() < 32 {
        return Err(anyhow::anyhow!("seed length too small"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed_slice[..32]);
    let kp = Keypair::from_seed_bytes(&arr).map_err(|e| anyhow::anyhow!("create keypair: {}", e))?;
    drop(sm);
    Ok(kp)
}

pub fn ed25519_sign(kp: &Keypair, msg: &[u8]) -> Signature {
    kp.sign(msg)
}

pub fn ed25519_verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> anyhow::Result<()> {
    pk.verify(msg, sig).map_err(|e| anyhow::anyhow!("signature verify failed: {}", e))
}

pub fn ed25519_sign_bytes(kp: &Keypair, msg: &[u8]) -> Vec<u8> {
    let sig = kp.sign(msg);
    sig.to_bytes().to_vec()
}

pub fn ed25519_verify_bytes(pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> anyhow::Result<()> {
    let pk = crate::ed25519_compat::public_from_bytes(<&[u8;32]>::try_from(pubkey_bytes).map_err(|_| anyhow::anyhow!("pubkey must be 32 bytes"))?)?;
    let sig = crate::ed25519_compat::signature_from_slice(sig_bytes)?;
    ed25519_verify(&pk, msg, &sig)
}
