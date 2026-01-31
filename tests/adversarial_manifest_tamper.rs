use tempfile::tempdir;
use std::fs;
use spenfs::manifest::create_snapshot_manifest;
use spenfs::ed25519_compat::Keypair;

#[test]
fn tampered_manifest_gets_quarantined() -> anyhow::Result<()> {
    let td = tempdir()?;
    let root = td.path();

    // create deterministic keypair
    let seed = [9u8; 32];
    let kp = Keypair::from_seed_bytes(&seed)?;

    // create header with pubkey
    let mut hdr = spenfs::on_disk::Header::new();
    hdr.signing_pubkey = kp.public.to_bytes();
    spenfs::on_disk::write_header(root, &hdr)?;

    // prepare a valid tmp manifest (writes manifest-<seq>.bin.tmp)
    let aead_key = spenfs::crypto::derive_key(b"test-pass", &hdr.salt)?;
    // set passphrase file for retrieval
    let pf = root.join("spenfs_pass.txt");
    std::fs::write(&pf, "test-pass")?;
    std::env::set_var("SPENFS_PW_FILE", pf.to_string_lossy().to_string());

    create_snapshot_manifest(root, 42, &Vec::new(), &kp, &aead_key)?;

    // find the tmp manifest and corrupt it
    let tmp = root.join("manifests").join("manifest-42.bin.tmp");
    assert!(tmp.exists());
    let mut data = fs::read(&tmp)?;
    // flip a byte in the serialized manifest to break signature
    if !data.is_empty() { data[0] ^= 0xff; }
    fs::write(&tmp, &data)?;

    // apply journal -> should quarantine the corrupted tmp manifest
    spenfs::on_disk::apply_journal_entries(root)?;

    let qdir = root.join("manifests").join("quarantine");
    assert!(qdir.exists());
    let mut found = false;
    for e in fs::read_dir(&qdir)? {
        let p = e?.path();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if name.contains("manifest-42") { found = true; }
    }
    assert!(found, "expected corrupted manifest to be quarantined");
    Ok(())
}

#[test]
fn missing_tmp_manifest_is_handled_gracefully() -> anyhow::Result<()> {
    let td = tempdir()?;
    let root = td.path();

    let seed = [10u8; 32];
    let kp = Keypair::from_seed_bytes(&seed)?;
    let mut hdr = spenfs::on_disk::Header::new();
    hdr.signing_pubkey = kp.public.to_bytes();
    spenfs::on_disk::write_header(root, &hdr)?;

    let aead_key = spenfs::crypto::derive_key(b"test-pass", &hdr.salt)?;
    let pf = root.join("spenfs_pass.txt");
    std::fs::write(&pf, "test-pass")?;
    std::env::set_var("SPENFS_PW_FILE", pf.to_string_lossy().to_string());

    create_snapshot_manifest(root, 99, &Vec::new(), &kp, &aead_key)?;
    let tmp = root.join("manifests").join("manifest-99.bin.tmp");
    assert!(tmp.exists());
    // simulate crash: remove the tmp manifest before WAL apply
    fs::remove_file(&tmp)?;

    // apply journal; should not panic and should not create final manifest
    spenfs::on_disk::apply_journal_entries(root)?;
    assert!(!root.join("manifests").join("manifest-99.bin").exists());
    Ok(())
}
