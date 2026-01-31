use tempfile::tempdir;
use std::fs;
use spenfs::on_disk::write_header;
use spenfs::manifest::create_snapshot_manifest;
use spenfs::ed25519_compat::Keypair;

// If an existing anchor has a corrupted signature, promotion should quarantine the tmp manifest.
#[test]
fn anchor_signature_corruption_quarantines() -> anyhow::Result<()> {
    let td = tempdir()?;
    let root = td.path();

    let seed = [3u8; 32];
    let kp = Keypair::from_seed_bytes(&seed)?;

    // create header with signing pubkey
    let mut hdr = spenfs::on_disk::Header::new();
    hdr.signing_pubkey = kp.public.to_bytes();
    write_header(root, &hdr)?;

    // create an existing anchor with seq=5 and a corrupted signature (versioned)
    let stored_seq: u64 = 5;
    let mut anchor_bytes = Vec::with_capacity(9);
    anchor_bytes.push(0x01u8);
    anchor_bytes.extend_from_slice(&stored_seq.to_le_bytes());
    fs::write(root.join("anchor.bin"), &anchor_bytes)?;
    let mut sig = kp.sign(&anchor_bytes).to_bytes();
    // corrupt the signature
    sig[0] ^= 0xAA;
    fs::write(root.join("anchor.sig"), &sig)?;

    // ensure promote attempt will use same passphrase for AEAD
    std::env::set_var("SPENFS_PW", "test-pass");
    let aead_key = spenfs::crypto::derive_key(b"test-pass", &hdr.salt)?;

    // writer creates a tmp manifest (which writes anchor.tmp files)
    create_snapshot_manifest(root, 10, &Vec::new(), &kp, &aead_key)?;

    // apply journal -> should quarantine because anchor signature verification fails
    spenfs::on_disk::apply_journal_entries(root)?;

    let qdir = root.join("manifests").join("quarantine");
    assert!(qdir.exists(), "quarantine dir missing");
    // expect a .reason file containing 'anchor signature'
    let mut found = false;
    for e in fs::read_dir(&qdir)? {
        let p = e?.path();
        if let Some(n) = p.file_name().and_then(|s| s.to_str()) {
            if n.ends_with(".reason") {
                let txt = fs::read_to_string(p)?;
                if txt.contains("anchor signature") {
                    found = true;
                    break;
                }
            }
        }
    }
    assert!(found, "expected quarantine reason mentioning anchor signature");
    Ok(())
}

// If existing anchor seq >= new seq, promotion should be quarantined as rollback.
#[test]
fn anchor_with_higher_seq_quarantines_as_rollback() -> anyhow::Result<()> {
    let td = tempdir()?;
    let root = td.path();

    let seed = [4u8; 32];
    let kp = Keypair::from_seed_bytes(&seed)?;

    let mut hdr = spenfs::on_disk::Header::new();
    hdr.signing_pubkey = kp.public.to_bytes();
    write_header(root, &hdr)?;

    // create a valid existing anchor with stored_seq = 20 (versioned)
    let stored_seq: u64 = 20;
    let mut anchor_bytes = Vec::with_capacity(9);
    anchor_bytes.push(0x01u8);
    anchor_bytes.extend_from_slice(&stored_seq.to_le_bytes());
    fs::write(root.join("anchor.bin"), &anchor_bytes)?;
    let sig = kp.sign(&anchor_bytes);
    fs::write(root.join("anchor.sig"), &sig.to_bytes())?;

    // writer creates a tmp manifest with seq 10 (lower)
    std::env::set_var("SPENFS_PW", "test-pass");
    let aead_key = spenfs::crypto::derive_key(b"test-pass", &hdr.salt)?;
    create_snapshot_manifest(root, 10, &Vec::new(), &kp, &aead_key)?;

    // apply journal -> should quarantine because stored_seq >= seq
    spenfs::on_disk::apply_journal_entries(root)?;

    let qdir = root.join("manifests").join("quarantine");
    assert!(qdir.exists(), "quarantine dir missing");
    let mut found = false;
    for e in fs::read_dir(&qdir)? {
        let p = e?.path();
        if let Some(n) = p.file_name().and_then(|s| s.to_str()) {
            if n.ends_with(".reason") {
                let txt = fs::read_to_string(p)?;
                if txt.contains("rollback") {
                    found = true;
                    break;
                }
            }
        }
    }
    assert!(found, "expected quarantine reason mentioning rollback");
    Ok(())
}
