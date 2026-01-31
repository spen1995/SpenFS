use tempfile::tempdir;
use std::fs::{self, File};
use std::io::Write;

#[test]
fn transactional_journal_replay_promotes_manifest() {
    let td = tempdir().unwrap();
    let root = td.path();
    let journal_dir = root.join("journal");
    fs::create_dir_all(&journal_dir).unwrap();

    // prepare manifests tmp file to be promoted by journal replay
    let manifests_dir = root.join("manifests");
    fs::create_dir_all(&manifests_dir).unwrap();
    let seq = 7u64;
    let name = format!("manifest-{}.bin", seq);
    let tmp_name = format!("{}.tmp", name);
    let tmp_path = manifests_dir.join(&tmp_name);
        let mut f = spenfs::hardening::create_tmp_file_secure(&tmp_path).unwrap();
    f.write_all(b"ciphertext").unwrap();
    f.sync_all().unwrap();

    // build journal entries: StartTxn, CommitManifest, EndTxn
    use spenfs::manifest::{JournalEntry, JournalOp};
    let mut buf = Vec::new();
    let e1 = JournalEntry { seq: 1, op: JournalOp::StartTxn { txid: 100 }, timestamp: 1, signature: Vec::new() };
    let e2 = JournalEntry { seq: 2, op: JournalOp::CommitManifest { seq }, timestamp: 2, signature: Vec::new() };
    let e3 = JournalEntry { seq: 3, op: JournalOp::EndTxn { txid: 100 }, timestamp: 3, signature: Vec::new() };
    for e in &[e1, e2, e3] {
        let v = rmp_serde::to_vec(e).unwrap();
        let len = (v.len() as u32).to_le_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&v);
    }
    fs::write(journal_dir.join("journal.log"), &buf).unwrap();

    // call apply
    spenfs::on_disk::apply_journal_entries(root).unwrap();

    // manifest should be promoted
    assert!(manifests_dir.join(&name).exists());
    // journal should be archived
    let entries: Vec<_> = fs::read_dir(journal_dir).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert!(entries.iter().any(|n| n.to_string_lossy().starts_with("applied-")));
}
