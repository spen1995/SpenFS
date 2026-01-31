use serde::{Deserialize, Serialize};
use std::path::Path;
use std::io::Write;
use hex;
use crate::hardening::SecretBytes;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Manifest {
    pub magic: [u8; 4],
    pub version: u32,
    pub dataset_id: [u8; 32],
    pub seq: u64,
    pub root_merkle: [u8; 32],
    pub timestamp: u64,
    pub metadata_blob: SecretBytes, // encrypted serialized namespace tree
    pub signature: Vec<u8>,     // placeholder for Ed25519 signature
}

impl Manifest {
    pub fn new(dataset_id: [u8; 32], seq: u64, metadata_blob: SecretBytes) -> anyhow::Result<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let root_merkle = *blake3::hash(metadata_blob.as_slice()).as_bytes();
        Ok(Manifest {
            magic: *b"MFV1",
            version: 1,
            dataset_id,
            seq,
            root_merkle,
            timestamp: now,
            metadata_blob,
            signature: Vec::new(),
        })
    }
}

pub fn write_manifest(path: &Path, m: &Manifest) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    let name = format!("manifest-{}.bin", m.seq);
    let f = path.join(name);
    let v = rmp_serde::to_vec(m).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("rmp_serde serialize: {}", e)))?;
    std::fs::write(f, v)
}

pub fn read_manifest(path: &Path, seq: u64) -> std::io::Result<Manifest> {
    let name = format!("manifest-{}.bin", seq);
    let f = path.join(name);
    let v = std::fs::read(f)?;
    let m: Manifest = rmp_serde::from_slice(&v).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("rmp_serde: {}", e)))?;
    Ok(m)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum JournalOp {
    StartTxn { txid: u64 },
    EndTxn { txid: u64 },
    AbortTxn { txid: u64 },
    CommitManifest { seq: u64 },
    Create { path: String },
    Unlink { path: String },
    Rename { old: String, new: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JournalEntry {
    pub seq: u64,
    pub op: JournalOp,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

pub fn append_journal_entry(path: &Path, entry: &JournalEntry) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    let f = path.join("journal.log");
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(f)?;
    let v = rmp_serde::to_vec(entry).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("rmp_serde serialize: {}", e)))?;
    // prefix with length for easy parsing
    let len = (v.len() as u32).to_le_bytes();
    use std::io::Write;
    file.write_all(&len)?;
    file.write_all(&v)?;
    file.flush()?;
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileManifest {
    pub path: String,
    pub size: u64,
    pub chunks: Vec<String>, // chunk ids (hex)
    pub merkle_root: [u8; 32],
}

impl FileManifest {
    pub fn new(path: String, size: u64, chunks: Vec<String>) -> anyhow::Result<Self> {
        let merkle_root = build_merkle_root(&chunks)?;
        Ok(FileManifest {
            path,
            size,
            chunks,
            merkle_root,
        })
    }
}

fn build_merkle_root(chunks: &[String]) -> anyhow::Result<[u8; 32]> {
    if chunks.is_empty() {
        return Ok(*blake3::hash(b"").as_bytes());
    }
    // convert chunk hex ids to raw bytes
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(chunks.len());
    for h in chunks {
        let raw = hex::decode(h).map_err(|e| anyhow::anyhow!("hex decode: {}", e))?;
        if raw.len() != 32 {
            return Err(anyhow::anyhow!("invalid chunk hash length"));
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&raw);
        leaves.push(*blake3::hash(&a).as_bytes());
    }

    // build binary Merkle tree
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        let mut i = 0;
        while i < leaves.len() {
            if i + 1 < leaves.len() {
                let mut concat = Vec::with_capacity(64);
                concat.extend_from_slice(&leaves[i]);
                concat.extend_from_slice(&leaves[i + 1]);
                next.push(*blake3::hash(&concat).as_bytes());
                i += 2;
            } else {
                // duplicate last
                let mut concat = Vec::with_capacity(64);
                concat.extend_from_slice(&leaves[i]);
                concat.extend_from_slice(&leaves[i]);
                next.push(*blake3::hash(&concat).as_bytes());
                i += 1;
            }
        }
        leaves = next;
    }
    Ok(leaves[0])
}

pub fn write_file_manifest(path: &Path, fm: &FileManifest) -> std::io::Result<String> {
    std::fs::create_dir_all(path)?;
    let id = uuid::Uuid::new_v4().to_string();
    let name = format!("filemanifest-{}.bin", id);
    let f = path.join(name);
    let v = rmp_serde::to_vec(fm).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("rmp_serde serialize: {}", e)))?;
    std::fs::write(&f, v)?;
    Ok(id)
}

pub fn create_snapshot_manifest(
    dataset_path: &Path,
    seq: u64,
    file_manifests: &[FileManifest],
    signer: &crate::ed25519_compat::Keypair,
    aead_key: &[u8; 32],
) -> anyhow::Result<()> {
    // metadata_blob is serialized list of file manifests
    let metadata_blob = rmp_serde::to_vec(&file_manifests).expect("serialize file manifests");
    let sb = SecretBytes::from_vec(metadata_blob)?;
    let mut manifest = Manifest::new(read_dataset_id(dataset_path)?, seq, sb)?;
    write_encrypted_signed_manifest(dataset_path, &dataset_path.join("manifests"), &mut manifest, aead_key, signer)?;
    Ok(())
}

fn read_dataset_id(dataset_path: &Path) -> anyhow::Result<[u8; 32]> {
    let hdr = crate::on_disk::read_header(dataset_path)?;
    Ok(hdr.dataset_id)
}

pub fn write_encrypted_signed_manifest(
    dataset_root: &Path,
    path: &Path,
    m: &mut Manifest,
    aead_key: &[u8; 32],
    signer: &crate::ed25519_compat::Keypair,
) -> anyhow::Result<()> {
    // Encrypt metadata_blob with AEAD using dataset_id as AAD
    let aad = &m.dataset_id;
    let encrypted = crate::crypto::aead_encrypt(aead_key, m.metadata_blob.as_slice(), aad)?;
    m.metadata_blob = SecretBytes::from_vec(encrypted)?;

    // Serialize manifest without signature to sign
    let mut temp = m.clone();
    temp.signature = Vec::new();
    let ser = rmp_serde::to_vec(&temp).expect("serialize manifest for signing");
    let sig = crate::crypto::ed25519_sign(signer, &ser);
    m.signature = sig.to_bytes().to_vec();

    // write the manifest tmp file first
    std::fs::create_dir_all(path)?;
    let name = format!("manifest-{}.bin", m.seq);
    let tmp_name = format!("{}.tmp", name);
    let tmp_path = path.join(&tmp_name);
    let bytes = rmp_serde::to_vec(&m).expect("serialize manifest");
    std::fs::write(&tmp_path, &bytes)?;
    // fsync tmp file
    let _ = std::fs::OpenOptions::new().read(true).open(&tmp_path).and_then(|f| f.sync_all());

    // Create a signed monotonic anchor (best-effort). Writer signs the sequence
    // and writes temporary anchor files `anchor.bin.tmp` and `anchor.sig.tmp` at
    // the dataset root so promotion can atomically install them during recovery.
    // Anchor serialization: prefix a version byte to allow future formats.
    // 0x01: seq-only -> [0x01 | seq(8)]
    // 0x02: seq + tpm -> [0x02 | seq(8) | tpm(8)]
    #[cfg(feature = "tpm")]
    let anchor_bytes = {
        let idx = std::env::var("SPENFS_TPM_NV_INDEX").ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
        match crate::tpm::increment_monotonic(idx) {
            Ok(cnt) => {
                let mut v = Vec::with_capacity(17);
                v.push(0x02u8);
                v.extend_from_slice(&m.seq.to_le_bytes());
                v.extend_from_slice(&cnt.to_le_bytes());
                v
            }
            Err(_) => {
                let mut v = Vec::with_capacity(9);
                v.push(0x01u8);
                v.extend_from_slice(&m.seq.to_le_bytes());
                v
            }
        }
    };
    #[cfg(not(feature = "tpm"))]
    let anchor_bytes = {
        let mut v = Vec::with_capacity(9);
        v.push(0x01u8);
        v.extend_from_slice(&m.seq.to_le_bytes());
        v
    };
    let anchor_sig = crate::crypto::ed25519_sign(signer, &anchor_bytes);
    let root = dataset_root;
    let anchor_tmp = root.join("anchor.bin.tmp");
    let anchor_sig_tmp = root.join("anchor.sig.tmp");
    if let Ok(mut af) = crate::hardening::create_tmp_file_secure(&anchor_tmp) {
        let _ = af.write_all(&anchor_bytes);
        let _ = af.sync_all();
    }
    if let Ok(mut sf) = crate::hardening::create_tmp_file_secure(&anchor_sig_tmp) {
        let _ = sf.write_all(&anchor_sig.to_bytes());
        let _ = sf.sync_all();
    }

    // append a CommitManifest journal entry (caller is responsible for applying the WAL)
    let je = JournalEntry {
        seq: 0,
        op: JournalOp::CommitManifest { seq: m.seq },
        timestamp: chrono::Utc::now().timestamp() as u64,
        signature: Vec::new(),
    };
    append_journal_entry(&dataset_root.join("journal"), &je).map_err(|e| anyhow::anyhow!("append journal: {}", e))?;

    Ok(())
}

pub fn read_and_verify_encrypted_manifest(
    path: &Path,
    seq: u64,
    aead_key: &[u8; 32],
    pubkey: &crate::ed25519_compat::PublicKey,
) -> anyhow::Result<Manifest> {
    let mut m = read_manifest(path, seq).map_err(|e| anyhow::anyhow!("read manifest: {}", e))?;
    // extract signature, verify
    let sig = crate::ed25519_compat::signature_from_slice(&m.signature)?;
    let mut temp = m.clone();
    temp.signature = Vec::new();
    let ser = rmp_serde::to_vec(&temp).expect("serialize manifest for verify");
    crate::crypto::ed25519_verify(pubkey, &ser, &sig)?;

    // decrypt metadata_blob
    let aad = &m.dataset_id;
    let decrypted = crate::crypto::aead_decrypt(aead_key, m.metadata_blob.as_slice(), aad)?;
    m.metadata_blob = decrypted;
    Ok(m)
}
