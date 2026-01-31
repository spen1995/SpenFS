use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use chrono;
use uuid::Uuid;
use anyhow::Context;
use crate::ed25519_compat::Keypair;
use crate::manifest::{JournalEntry, JournalOp, append_journal_entry};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UploadState {
    pub id: String,
    pub file_path: String,
    pub file_size: u64,
    pub offset: u64,
    pub chunks: Vec<String>,
}

impl UploadState {
    pub fn new(id: String, file_path: String, file_size: u64) -> Self {
        UploadState {
            id,
            file_path,
            file_size,
            offset: 0,
            chunks: Vec::new(),
        }
    }

    pub fn path_for(dataset_path: &Path, id: &str) -> std::path::PathBuf {
        dataset_path.join("uploads").join(format!("{}.json", id))
    }

    pub fn load(dataset_path: &Path, id: &str) -> anyhow::Result<Self> {
        let p = Self::path_for(dataset_path, id);
        let v = std::fs::read(&p)?;
        let s: UploadState = serde_json::from_slice(&v)?;
        Ok(s)
    }

    pub fn save(&self, dataset_path: &Path) -> anyhow::Result<()> {
        let p = Self::path_for(dataset_path, &self.id);
        std::fs::create_dir_all(p.parent().unwrap())?;
        let v = serde_json::to_vec_pretty(self)?;
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(p)?;
        f.write_all(&v)?;
        f.flush()?;
        Ok(())
    }
}

pub fn start_upload(dataset_path: &Path, file_path: &str) -> anyhow::Result<UploadState> {
    let file_meta = std::fs::metadata(file_path)?;
    let size = file_meta.len();
    let id = uuid::Uuid::new_v4().to_string();
    let state = UploadState::new(id.clone(), file_path.to_string(), size);
    state.save(dataset_path)?;
    Ok(state)
}

pub fn resume_upload(dataset_path: &Path, id: &str, aead_key: &[u8; 32]) -> anyhow::Result<UploadState> {
    let mut state = UploadState::load(dataset_path, id)?;
    let mut f = std::fs::File::open(&state.file_path)?;
    f.seek(SeekFrom::Start(state.offset))?;

    // Begin a transaction marker so interrupted uploads are visible in the WAL
    let txid = Uuid::new_v4().as_u128() as u64;
    let start = JournalEntry { seq: 0, op: JournalOp::StartTxn { txid }, timestamp: chrono::Utc::now().timestamp() as u64, signature: Vec::new() };
    let _ = append_journal_entry(&dataset_path.join("journal"), &start);

    // use chunker to process remaining bytes incrementally; persist state after each chunk
    let params = crate::chunker::ChunkerParams::default();
    let rs_k: usize = std::env::var("SPENFS_RS_K").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    let rs_m: usize = std::env::var("SPENFS_RS_M").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    let chunker = crate::chunker::GearChunker::new_with_redundancy(params, Some((rs_k, rs_m)));

    // progress callback updates and persists upload state per chunk
    let mut progress = |chunk_id: &str, bytes: usize| {
        state.chunks.push(chunk_id.to_string());
        state.offset = state.offset.saturating_add(bytes as u64);
        let _ = state.save(dataset_path); // ignore save errors but attempt to persist
    };

    let cb_opt: Option<&mut dyn FnMut(&str, usize)> = Some(&mut progress);
    let res = chunker.chunk_and_store_with_progress(&mut f, &dataset_path.join("chunks"), aead_key, cb_opt);

    match res {
        Ok(_new_chunks) => {
            // final save to ensure state is up-to-date
            state.save(dataset_path)?;
            // append EndTxn
            let end = JournalEntry { seq: 0, op: JournalOp::EndTxn { txid }, timestamp: chrono::Utc::now().timestamp() as u64, signature: Vec::new() };
            let _ = append_journal_entry(&dataset_path.join("journal"), &end);
            Ok(state)
        }
        Err(e) => {
            // append AbortTxn so recovery can reason about incomplete upload
            let abort = JournalEntry { seq: 0, op: JournalOp::AbortTxn { txid }, timestamp: chrono::Utc::now().timestamp() as u64, signature: Vec::new() };
            let _ = append_journal_entry(&dataset_path.join("journal"), &abort);
            Err(e)
        }
    }
}

pub fn commit_snapshot_transaction(
    dataset_path: &Path,
    seq: u64,
    file_manifests: &[crate::manifest::FileManifest],
    signer: &Keypair,
    aead_key: &[u8; 32],
) -> anyhow::Result<()> {
    // create a transaction id
    let txid = Uuid::new_v4().as_u128() as u64;

    // append StartTxn
    let start = JournalEntry {
        seq: 0,
        op: JournalOp::StartTxn { txid },
        timestamp: chrono::Utc::now().timestamp() as u64,
        signature: Vec::new(),
    };
    append_journal_entry(&dataset_path.join("journal"), &start).context("append StartTxn")?;

    // write the snapshot manifest tmp (does not append journal entry anymore)
    let res = crate::manifest::create_snapshot_manifest(dataset_path, seq, file_manifests, signer, aead_key);

    match res {
        Ok(()) => {
            // append CommitManifest
            let commit = JournalEntry {
                seq: 0,
                op: JournalOp::CommitManifest { seq },
                timestamp: chrono::Utc::now().timestamp() as u64,
                signature: Vec::new(),
            };
            append_journal_entry(&dataset_path.join("journal"), &commit).context("append CommitManifest")?;

            // append EndTxn
            let end = JournalEntry {
                seq: 0,
                op: JournalOp::EndTxn { txid },
                timestamp: chrono::Utc::now().timestamp() as u64,
                signature: Vec::new(),
            };
            append_journal_entry(&dataset_path.join("journal"), &end).context("append EndTxn")?;

            // trigger apply to promote committed manifests
            crate::on_disk::apply_journal_entries(dataset_path).context("apply journal after commit")?;
            Ok(())
        }
        Err(e) => {
            // append AbortTxn so recovery can skip
            let abort = JournalEntry {
                seq: 0,
                op: JournalOp::AbortTxn { txid },
                timestamp: chrono::Utc::now().timestamp() as u64,
                signature: Vec::new(),
            };
            let _ = append_journal_entry(&dataset_path.join("journal"), &abort);
            Err(e).context("create snapshot manifest failed")
        }
    }
}
