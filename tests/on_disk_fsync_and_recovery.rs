use std::fs;
use tempfile::tempdir;

use spenfs::on_disk::{commit_manifest, apply_journal_entries};
use spenfs::manifest::{JournalEntry, JournalOp, append_journal_entry};

// Simulate an interrupted commit where a tmp manifest exists and a journal CommitManifest
// instructs promotion. The `apply_journal_entries` call should cause promotion and
// update the `latest` pointer atomically.
#[test]
fn promote_tmp_and_update_latest_via_journal() -> anyhow::Result<()> {
    let td = tempdir()?;
    let ds = td.path();
    let manifests = ds.join("manifests");
    fs::create_dir_all(&manifests)?;

    // write a tmp manifest file (simulate writer that crashed before renaming)
    let seq = 9001u64;
    let name = format!("manifest-{}.bin", seq);
    let tmp_name = format!("{}.tmp", name);
    let tmp_path = manifests.join(&tmp_name);
    fs::write(&tmp_path, b"ciphertext")?;
    // fsync tmp (emulate writer)
    let _ = std::fs::OpenOptions::new().read(true).open(&tmp_path).and_then(|f| f.sync_all());

    // append a commit journal entry expecting promotion
    let je = JournalEntry { seq: 0, op: JournalOp::CommitManifest { seq }, timestamp: 0, signature: Vec::new() };
    append_journal_entry(&ds.join("journal"), &je)?;

    // now apply journal entries (recovery path)
    apply_journal_entries(ds)?;

    // final manifest should exist and latest should point to it
    assert!(manifests.join(&name).exists());
    let latest = fs::read_to_string(manifests.join("latest"))?;
    assert_eq!(latest, name);
    Ok(())
}

// Basic round-trip for commit_manifest to validate fsync/rename ordering doesn't error
#[test]
fn commit_manifest_roundtrip() -> anyhow::Result<()> {
    let td = tempdir()?;
    let manifests = td.path().join("manifests");
    fs::create_dir_all(&manifests)?;
    commit_manifest(&manifests, 7, b"cipher", b"sig")?;
    assert!(manifests.join("manifest.7.bin").exists());
    assert!(manifests.join("manifest.7.bin.sig").exists());
    let latest = fs::read_to_string(manifests.join("latest"))?;
    assert_eq!(latest, "manifest.7.bin");
    Ok(())
}
