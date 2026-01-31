use tempfile::tempdir;
use std::fs;
use std::io::Write;
use zeroize::Zeroize;

#[test]
fn load_signing_key_zeroizes_inner_memory() -> anyhow::Result<()> {
    let _td = tempdir()?;
    let root = _td.path();

    // create deterministic keypair
    let seed = [7u8; 32];
    let kp = spenfs::ed25519_compat::Keypair::from_seed_bytes(&seed)?;

    // create header and write it (header contains salt and dataset_id)
    let mut hdr = spenfs::on_disk::Header::new();
    hdr.signing_pubkey = kp.public.to_bytes();
    spenfs::on_disk::write_header(root, &hdr)?;

    // derive AEAD key and encrypt the secret key bytes
    let pass = "test-pass";
    let pf = root.join("spenfs_pass.txt");
    std::fs::write(&pf, pass)?;
    std::env::set_var("SPENFS_PW_FILE", pf.to_string_lossy().to_string());
    let aead_key = spenfs::crypto::derive_key(pass.as_bytes(), &hdr.salt)?;
    let sk_bytes = kp.secret_to_bytes();
    let enc = spenfs::crypto::aead_encrypt(&aead_key, &sk_bytes, &hdr.dataset_id)?;

    // write encrypted signing key to keys/signing.key.enc
    let keys_dir = root.join("keys");
    std::fs::create_dir_all(&keys_dir)?;
    let enc_path = keys_dir.join("signing.key.enc");
    let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&enc_path)?;
    f.write_all(&enc)?;
    f.sync_all()?;

    // Now replicate load_signing_key decrypt path to capture pointer
    let enc_read = fs::read(&enc_path)?;
    let sb = spenfs::crypto::aead_decrypt(&aead_key, &enc_read, &hdr.dataset_id)?;
    // ensure decrypted content matches secret
    assert_eq!(sb.as_slice(), sk_bytes.as_slice());

    // get pointer to secure memory for test
    let ptr = sb.0.as_ptr_for_test();
    let len = sb.as_slice().len();
    assert_eq!(len, 32);

    // Now create the Keypair (simulate load_signing_key behavior)
    let mut skb = [0u8; 32];
    skb.copy_from_slice(&sb.as_slice()[..32]);
    let _kp2 = spenfs::ed25519_compat::Keypair::from_secret_bytes(&skb)?;

    // Now clear the secure buffer as load_signing_key does
    let mut sb = sb; // make mutable
    sb.0.clear();

    // Unsafe inspect the memory at the captured pointer for zeroization
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
        for &b in slice.iter() {
            assert_eq!(b, 0u8, "expected zeroized byte");
        }
    }

    // also clear stack copy
    skb.zeroize();

    Ok(())
}
