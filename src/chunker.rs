use crate::crypto;
use blake3;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroize;
use crate::hardening::SecureMemory;

pub struct ChunkerParams {
    pub min_size: usize,
    pub avg_size: usize,
    pub max_size: usize,
}

impl Default for ChunkerParams {
    fn default() -> Self {
        ChunkerParams {
            min_size: 64 * 1024,   // 64KiB
            avg_size: 1024 * 1024, // 1MiB
            max_size: 8 * 1024 * 1024, // 8MiB
        }
    }
}

// Simple Gear-based CDC chunker. Not cryptographic; used for boundary selection.
pub struct GearChunker {
    table: [u64; 256],
    mask: u64,
    params: ChunkerParams,
    redundancy: Option<(usize, usize)>,
}

impl GearChunker {
    pub fn new(params: ChunkerParams) -> Self {
        Self::new_with_redundancy(params, None)
    }

    pub fn new_with_redundancy(params: ChunkerParams, redundancy: Option<(usize, usize)>) -> Self {
        // init table with deterministic values from blake3 of indices
        let mut table = [0u64; 256];
        for i in 0..256 {
            let t = blake3::hash(&[i as u8]);
            let mut b = [0u8; 8];
            b.copy_from_slice(&t.as_bytes()[..8]);
            table[i] = u64::from_le_bytes(b);
        }
        // choose mask based on avg_size (power-of-two approximation)
        let mut bits = 0u32;
        let mut a = params.avg_size;
        while a > 1 {
            bits += 1;
            a >>= 1;
        }
        let mask = (1u64 << bits) - 1;
        GearChunker { table, mask, params, redundancy }
    }

    // Stream from reader and write chunks to chunk store path. Returns vector of chunk ids (hex).
    pub fn chunk_and_store<R: Read>(
        &self,
        mut reader: R,
        store_path: &Path,
        aead_key: &[u8; 32],
    ) -> anyhow::Result<Vec<String>> {
        // backward-compatible wrapper that does no progress callbacks
        self.chunk_and_store_with_progress(&mut reader, store_path, aead_key, None)
    }

    // New variant that accepts an optional progress callback invoked after each chunk is written.
    // The callback receives the chunk id (hex) and the plaintext chunk length in bytes.
    #[allow(unused_assignments)]
    pub fn chunk_and_store_with_progress<R: Read>(
        &self,
        reader: &mut R,
        store_path: &Path,
        aead_key: &[u8; 32],
        mut progress: Option<&mut dyn FnMut(&str, usize)>,
    ) -> anyhow::Result<Vec<String>> {
        std::fs::create_dir_all(store_path)?;
        let mut window_hash: u64 = 0;
        let mut buf_sm = SecureMemory::new(self.params.max_size + 64)?;
        let mut buf_len: usize = 0;
        let mut tmp = [0u8; 8192];
        let mut chunk_ids = Vec::new();

        loop {
            let n = reader.read(&mut tmp)?;
            if n == 0 {
                // flush remaining
                if buf_len != 0 {
                    let id = self.write_chunk(&buf_sm.as_slice()[..buf_len], store_path, aead_key)?;
                    if let Some(cb) = progress.as_mut() {
                        cb(&id, buf_len);
                    }
                    chunk_ids.push(id);
                    // zeroize used portion and reset
                    buf_sm.as_mut_slice()[..buf_len].zeroize();
                    buf_len = 0;
                }
                break;
            }
            for &b in &tmp[..n] {
                buf_sm.as_mut_slice()[buf_len] = b;
                buf_len += 1;
                // update gear hash
                window_hash = (window_hash << 1).wrapping_add(self.table[b as usize]);
                let cut = (buf_len >= self.params.min_size
                    && (window_hash & self.mask) == 0)
                    || buf_len >= self.params.max_size;
                if cut {
                    let id = self.write_chunk(&buf_sm.as_slice()[..buf_len], store_path, aead_key)?;
                    if let Some(cb) = progress.as_mut() {
                        cb(&id, buf_len);
                    }
                    chunk_ids.push(id);
                    // zeroize used region and reset
                    buf_sm.as_mut_slice()[..buf_len].zeroize();
                    buf_len = 0;
                    window_hash = 0;
                }
            }
        }

        Ok(chunk_ids)
    }

    fn write_chunk(&self, data: &[u8], store_path: &Path, aead_key: &[u8; 32]) -> anyhow::Result<String> {
        let hash = blake3::hash(data);
        let hex = hash.to_hex().to_string();
        let prefix = &hex[0..2];
        let dir = store_path.join(prefix);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.chunk", hex));
        if path.exists() {
            // already stored
            return Ok(hex);
        }

        // encrypt data with AEAD and write
        let encrypted = crypto::aead_encrypt(aead_key, data, hash.as_bytes())?;
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&path)?;
        f.write_all(&encrypted)?;
        f.flush()?;
        // If redundancy is configured, encode shards immediately for this chunk.
        if let Some((k, m)) = self.redundancy {
            // best-effort: log errors but don't fail chunk write
            if let Err(e) = crate::redundancy::encode_chunk_shards(&store_path.parent().unwrap_or(Path::new(".")), &hex, k, m) {
                eprintln!("redundancy encode failed for {}: {}", &hex, e);
            }
        }
        Ok(hex)
    }
}
