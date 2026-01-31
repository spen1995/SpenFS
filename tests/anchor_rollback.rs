use tempfile::tempdir;
use std::fs;
use spenfs::on_disk::{apply_journal_entries, write_header};
use spenfs::manifest::create_snapshot_manifest;
use spenfs::ed25519_compat::Keypair;
use spenfs::manifest::JournalEntry;
use spenfs::manifest::JournalOp;

// Test that when a writer produces anchor.tmp + manifest.tmp and the journal
// is applied, the anchor is atomically installed and the manifest promoted.
#[test]
fn anchor_install_and_promotion() -> anyhow::Result<()> {
    let td = tempdir()?;
    let root = td.path();

    // create deterministic keypair
    let seed = [1u8; 32];
    let kp = Keypair::from_seed_bytes(&seed)?;

    // create header with signing pubkey
    let mut hdr = spenfs::on_disk::Header::new();
    hdr.signing_pubkey = kp.public.to_bytes();
    write_header(root, &hdr)?;

    // derive AEAD key
    let aead_key = spenfs::crypto::derive_key(b"test-pass", &hdr.salt)?;

    // set passphrase file to match AEAD key used by writer
    let pf = root.join("spenfs_pass.txt");
    std::fs::write(&pf, "test-pass")?;
    std::env::set_var("SPENFS_PW_FILE", pf.to_string_lossy().to_string());
    // create snapshot manifest tmp (this writes anchor.tmp)
    create_snapshot_manifest(root, 10, &Vec::new(), &kp, &aead_key)?;

    // apply journal to promote and install anchor
    apply_journal_entries(root)?;

    // debug: list root contents
    println!("root entries: {:?}", std::fs::read_dir(root)?.map(|e| e.unwrap().file_name()).collect::<Vec<_>>());
    println!("anchor.tmp exists: {}", root.join("anchor.bin.tmp").exists());
    println!("anchor.tmp sig exists: {}", root.join("anchor.sig.tmp").exists());
    println!("anchor.final exists: {}", root.join("anchor.bin").exists());
    println!("anchor.final sig exists: {}", root.join("anchor.sig").exists());
    println!("manifests entries: {:?}", std::fs::read_dir(root.join("manifests"))?.map(|e| e.unwrap().file_name()).collect::<Vec<_>>());
    println!("manifest promoted exists: {}", root.join("manifests").join("manifest-10.bin").exists());
    println!("latest file exists: {}", root.join("manifests").join("latest").exists());
    // If quarantine exists, print its contents and reason
    let qdir = root.join("manifests").join("quarantine");
    if qdir.exists() {
        let mut entries = Vec::new();
        for e in std::fs::read_dir(&qdir)? {
            let p = e?.path();
            entries.push(p.file_name().unwrap().to_string_lossy().to_string());
        }
        println!("quarantine contents: {:?}", entries);
        for name in entries.iter() {
            if name.ends_with(".reason") {
                let txt = std::fs::read_to_string(qdir.join(name))?;
                println!("quarantine reason ({}): {}", name, txt);
            }
        }
    }

    // checks: anchor.bin and anchor.sig exist and manifest promoted
    assert!(root.join("anchor.bin").exists(), "anchor.bin missing");
    assert!(root.join("anchor.sig").exists(), "anchor.sig missing");
    assert!(root.join("manifests").join("manifest-10.bin").exists());
    let latest = fs::read_to_string(root.join("manifests").join("latest"))?;
    assert_eq!(latest, "manifest-10.bin");
    Ok(())
}

// Test that an existing anchor with seq >= new seq causes quarantine (rollback)
#[test]
fn anchor_detects_rollback() -> anyhow::Result<()> {
    let td = tempdir()?;
    let root = td.path();

    let seed = [2u8; 32];
    let kp = Keypair::from_seed_bytes(&seed)?;

    // header with pubkey
    let mut hdr = spenfs::on_disk::Header::new();
    hdr.signing_pubkey = kp.public.to_bytes();
    write_header(root, &hdr)?;

    // create an existing anchor with stored_seq = 50 (versioned anchor: 0x01 + seq)
    let stored_seq: u64 = 50;
    let mut anchor_bytes = Vec::with_capacity(9);
    anchor_bytes.push(0x01u8);
    anchor_bytes.extend_from_slice(&stored_seq.to_le_bytes());
    fs::write(root.join("anchor.bin"), &anchor_bytes)?;
    let sig = kp.sign(&anchor_bytes);
    fs::write(root.join("anchor.sig"), &sig.to_bytes())?;

    // set passphrase file to match AEAD key used by writer
    let pf = root.join("spenfs_pass.txt");
    std::fs::write(&pf, "test-pass")?;
    std::env::set_var("SPENFS_PW_FILE", pf.to_string_lossy().to_string());
    // create a tmp manifest with lower seq (10)
    let aead_key = spenfs::crypto::derive_key(b"test-pass", &hdr.salt)?;
    create_snapshot_manifest(root, 10, &Vec::new(), &kp, &aead_key)?;

    // apply journal -> should quarantine the tmp manifest
    apply_journal_entries(root)?;

    // expect manifests/quarantine to contain a .bad file and a .reason
    let qdir = root.join("manifests").join("quarantine");
    assert!(qdir.exists());
    let entries = std::fs::read_dir(&qdir)?.count();
    assert!(entries >= 1);
    Ok(())
}
