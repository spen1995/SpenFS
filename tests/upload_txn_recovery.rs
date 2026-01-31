use tempfile::tempdir;
use std::fs;
use spenfs::on_disk::{write_header, Header};
use spenfs::manifest::{append_journal_entry, JournalEntry, JournalOp};

#[test]
fn txn_commit_recovery_promotes_only_after_endtxn() -> anyhow::Result<()> {
    let td = tempdir()?;
    let ds = td.path();

    // write header
    let hdr = Header::new();
    write_header(&ds, &hdr)?;

    // prepare manifests dir and write tmp manifest file
    let manifests = ds.join("manifests");
    fs::create_dir_all(&manifests)?;
    let seq = 1u64;
    let sb = spenfs::hardening::SecretBytes::from_vec(vec![])?;
    let m = spenfs::manifest::Manifest::new(hdr.dataset_id, seq, sb)?;
    let name = format!("manifest-{}.bin", seq);
    let tmp_name = format!("{}.tmp", name);
    let tmp_path = manifests.join(&tmp_name);
    let bytes = rmp_serde::to_vec(&m)?;
    fs::write(&tmp_path, &bytes)?;
    // fsync tmp
    let _ = std::fs::OpenOptions::new().read(true).open(&tmp_path).and_then(|f| f.sync_all());

    // append StartTxn and CommitManifest but no EndTxn (simulate crash)
    let txid = 42u64;
    let start = JournalEntry { seq: 0, op: JournalOp::StartTxn { txid }, timestamp: chrono::Utc::now().timestamp() as u64, signature: Vec::new() };
    append_journal_entry(&ds.join("journal"), &start)?;
    let commit = JournalEntry { seq: 0, op: JournalOp::CommitManifest { seq }, timestamp: chrono::Utc::now().timestamp() as u64, signature: Vec::new() };
    append_journal_entry(&ds.join("journal"), &commit)?;

    // apply journal: should skip the un-ended transaction -> tmp should remain, final should not exist
    spenfs::on_disk::apply_journal_entries(&ds)?;
    assert!(tmp_path.exists(), "tmp manifest should remain when txn not ended");
    assert!(!manifests.join(&name).exists(), "final manifest should not exist yet");

    // now append EndTxn and apply -> manifest should be promoted
    let end = JournalEntry { seq: 0, op: JournalOp::EndTxn { txid }, timestamp: chrono::Utc::now().timestamp() as u64, signature: Vec::new() };
    append_journal_entry(&ds.join("journal"), &end)?;
    spenfs::on_disk::apply_journal_entries(&ds)?;

    assert!(!tmp_path.exists(), "tmp should be moved after commit apply");
    assert!(manifests.join(&name).exists(), "final manifest should exist after commit and endtxn");

    Ok(())
}
