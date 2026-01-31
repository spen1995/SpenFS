use tempfile::tempdir;
use spenfs::hardening::SecretBytes;

#[test]
fn secretbytes_clear_zeroizes() -> anyhow::Result<()> {
    let td = tempdir()?;
    // create SecretBytes from a non-zero vector
    let v = vec![0xAAu8; 64];
    let mut sb = SecretBytes::from_vec(v)?;
    // verify non-zero
    assert!(sb.as_slice().iter().any(|&b| b != 0));
    // clear inner buffer
    sb.0.clear();
    // all zeros
    assert!(sb.as_slice().iter().all(|&b| b == 0));
    Ok(())
}

#[test]
fn aead_decrypt_returns_secretbytes_and_can_clear() -> anyhow::Result<()> {
    // setup dataset-like parameters
    let td = tempdir()?;
    let salt = vec![1u8; 32];
    // derive a key using the library's function (ensure it builds)
    let aead_key = spenfs::crypto::derive_key(b"pw-test", &salt)?;
    // plaintext
    let pt = b"sensitive plaintext data".to_vec();
    // encrypt -> ciphertext (Vec<u8>)
    let ct = spenfs::crypto::aead_encrypt(&aead_key, &pt, b"aad")?;
    // decrypt -> SecretBytes
    let mut sb = spenfs::crypto::aead_decrypt(&aead_key, &ct, b"aad")?;
    // verify content matches original
    assert_eq!(sb.as_slice(), pt.as_slice());
    // clear and verify zeroized
    sb.0.clear();
    assert!(sb.as_slice().iter().all(|&b| b == 0));
    Ok(())
}
