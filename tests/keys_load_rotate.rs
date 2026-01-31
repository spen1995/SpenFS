use tempfile::tempdir;
use std::path::Path;

#[test]
fn keys_load_and_rotate_simulation() {
    let td = tempdir().unwrap();
    let root = td.path();

    // create header with signing key and write header.bin and header.sig
    let mut hdr = spenfs::on_disk::Header::new();
    let kp = spenfs::crypto::ed25519_generate().expect("generate kp");
    hdr.signing_pubkey = kp.public.to_bytes();
    hdr.kdf_params = 65536;
    // write header and signature
    spenfs::on_disk::write_header(root, &hdr).expect("write header");
    let bytes = hdr.to_fixed_bytes().expect("to bytes");
    let sig = spenfs::crypto::ed25519_sign(&kp, &bytes);
    let sig_path = root.join("header.sig");
    std::fs::write(&sig_path, sig.to_bytes().as_ref()).expect("write sig");

    // write encrypted signing key under keys/signing.key.enc with passphrase "oldpass"
    let pass_old = "oldpass";
    let aead_old = spenfs::crypto::derive_key(pass_old.as_bytes(), &hdr.salt).expect("derive old");
    let sk_bytes = kp.secret.to_bytes();
    let enc = spenfs::crypto::aead_encrypt(&aead_old, &sk_bytes, &hdr.dataset_id).expect("encrypt sk");
    let keys_dir = root.join("keys");
    std::fs::create_dir_all(&keys_dir).unwrap();
    let enc_path = keys_dir.join("signing.key.enc");
    std::fs::write(&enc_path, &enc).expect("write enc");

    // set passphrase file so load_signing_key uses it
    let pf_old = root.join("spenfs_pass_old.txt");
    std::fs::write(&pf_old, pass_old).expect("write pass file");
    std::env::set_var("SPENFS_PW_FILE", pf_old.to_string_lossy().to_string());
    let loaded = spenfs::keys::load_signing_key(root).expect("load signing key");
    assert_eq!(loaded.public.to_bytes(), kp.public.to_bytes());

    // simulate rotation: generate new keypair, encrypt under new passphrase and overwrite file
    let kp2 = spenfs::crypto::ed25519_generate().expect("generate kp2");
    let pass_new = "newpass";
    let aead_new = spenfs::crypto::derive_key(pass_new.as_bytes(), &hdr.salt).expect("derive new");
    let enc2 = spenfs::crypto::aead_encrypt(&aead_new, &kp2.secret.to_bytes(), &hdr.dataset_id).expect("encrypt sk2");
    std::fs::write(&enc_path, &enc2).expect("write enc2");
    let pf_new = root.join("spenfs_pass_new.txt");
    std::fs::write(&pf_new, pass_new).expect("write pass file new");
    std::env::set_var("SPENFS_PW_FILE", pf_new.to_string_lossy().to_string());
    let loaded2 = spenfs::keys::load_signing_key(root).expect("load signing key 2");
    assert_eq!(loaded2.public.to_bytes(), kp2.public.to_bytes());
}
