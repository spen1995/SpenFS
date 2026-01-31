use tempfile::tempdir;
use std::fs::{self, File};
use std::io::Write;

#[test]
fn quarantine_on_invalid_signature() -> anyhow::Result<()> {
    let td = tempdir()?;
    let root = td.path();

    // write header with a public key (so promotion will attempt verification)
    let mut hdr = spenfs::on_disk::Header::new();
    let kp = spenfs::crypto::ed25519_generate()?;
    hdr.signing_pubkey = kp.public.to_bytes();
    spenfs::on_disk::write_header(root, &hdr)?;

    // create a manifest with an invalid signature (short bytes)
    let manifests_dir = root.join("manifests");
    fs::create_dir_all(&manifests_dir)?;
    let seq = 9u64;
    let name = format!("manifest-{}.bin", seq);
    let tmp_name = format!("{}.tmp", name);
    let tmp_path = manifests_dir.join(&tmp_name);

    let sb = spenfs::hardening::SecretBytes::from_vec(vec![1,2,3])?;
    let mut m = spenfs::manifest::Manifest::new(hdr.dataset_id, seq, sb)?;
    // place an invalid signature
    m.signature = vec![1,2,3];
    let bytes = rmp_serde::to_vec(&m)?;
        let mut f = spenfs::hardening::create_tmp_file_secure(&tmp_path)?;
    f.write_all(&bytes)?;
    f.sync_all()?;

    // append journal entries to commit and end txn
    use spenfs::manifest::{JournalEntry, JournalOp};
    let mut buf = Vec::new();
    let e1 = JournalEntry { seq: 1, op: JournalOp::StartTxn { txid: 200 }, timestamp: 1, signature: Vec::new() };
    let e2 = JournalEntry { seq: 2, op: JournalOp::CommitManifest { seq }, timestamp: 2, signature: Vec::new() };
    let e3 = JournalEntry { seq: 3, op: JournalOp::EndTxn { txid: 200 }, timestamp: 3, signature: Vec::new() };
    for e in &[e1, e2, e3] {
        let v = rmp_serde::to_vec(e)?;
        let len = (v.len() as u32).to_le_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&v);
    }
    fs::create_dir_all(root.join("journal"))?;
    fs::write(root.join("journal").join("journal.log"), &buf)?;

    spenfs::on_disk::apply_journal_entries(root)?;

    // tmp should be moved to quarantine and reason file present
    let qdir = manifests_dir.join("quarantine");
    assert!(qdir.exists());
    let entries: Vec<_> = fs::read_dir(&qdir)?.collect();
    assert!(!entries.is_empty());

    Ok(())
}

#[test]
fn quarantine_on_aead_decrypt_failure() -> anyhow::Result<()> {
    let td = tempdir()?;
    let root = td.path();

    // write header with signing key and produce a valid signature
    let mut hdr = spenfs::on_disk::Header::new();
    let kp = spenfs::crypto::ed25519_generate()?;
    hdr.signing_pubkey = kp.public.to_bytes();
    spenfs::on_disk::write_header(root, &hdr)?;

    // create a manifest whose metadata_blob is not valid AEAD ciphertext
    let manifests_dir = root.join("manifests");
    fs::create_dir_all(&manifests_dir)?;
    let seq = 10u64;
    let name = format!("manifest-{}.bin", seq);
    let tmp_name = format!("{}.tmp", name);
    let tmp_path = manifests_dir.join(&tmp_name);

    let sb = spenfs::hardening::SecretBytes::from_vec(vec![9,9,9])?;
    let mut m = spenfs::manifest::Manifest::new(hdr.dataset_id, seq, sb)?;
    // sign the manifest (but metadata_blob is plaintext, not AEAD)
    let mut temp = m.clone();
    temp.signature = Vec::new();
        let ser = rmp_serde::to_vec(&temp)?;
    let sig = spenfs::crypto::ed25519_sign(&kp, &ser);
    m.signature = sig.to_bytes().to_vec();

    let bytes = rmp_serde::to_vec(&m)?;
        let mut f = spenfs::hardening::create_tmp_file_secure(&tmp_path)?;
    f.write_all(&bytes)?;
    f.sync_all()?;

    // append journal entries
    use spenfs::manifest::{JournalEntry, JournalOp};
    let mut buf = Vec::new();
    let e1 = JournalEntry { seq: 1, op: JournalOp::StartTxn { txid: 201 }, timestamp: 1, signature: Vec::new() };
    let e2 = JournalEntry { seq: 2, op: JournalOp::CommitManifest { seq }, timestamp: 2, signature: Vec::new() };
    let e3 = JournalEntry { seq: 3, op: JournalOp::EndTxn { txid: 201 }, timestamp: 3, signature: Vec::new() };
    for e in &[e1, e2, e3] {
        let v = rmp_serde::to_vec(e)?;
        let len = (v.len() as u32).to_le_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&v);
    }
    fs::create_dir_all(root.join("journal"))?;
    fs::write(root.join("journal").join("journal.log"), &buf)?;

    spenfs::on_disk::apply_journal_entries(root)?;

    // expect quarantine due to AEAD decrypt failure
    let qdir = manifests_dir.join("quarantine");
    assert!(qdir.exists());
    let entries: Vec<_> = fs::read_dir(&qdir)?.collect();
    assert!(!entries.is_empty());

    Ok(())
}
