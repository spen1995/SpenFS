use reed_solomon_erasure::galois_8::ReedSolomon;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use crate::hardening::SecureMemory;

/// Encode a chunk into `k` data shards + `m` parity shards.
/// Chunk is looked up under `dataset_path/chunks/xx/<chunk>.chunk`.
pub fn encode_chunk_shards(dataset_path: &Path, chunk_hex: &str, k: usize, m: usize) -> anyhow::Result<()> {
    let prefix = &chunk_hex[0..2];
    let chunk_file = dataset_path.join("chunks").join(prefix).join(format!("{}.chunk", chunk_hex));
    if !chunk_file.exists() {
        return Err(anyhow::anyhow!("chunk file not found: {}", chunk_file.display()));
    }

    let mut data = Vec::new();
    let mut f = fs::File::open(&chunk_file)?;
    f.read_to_end(&mut data)?;

    let r = ReedSolomon::new(k, m).map_err(|e| anyhow::anyhow!("rs init: {}", e))?;

    // compute shard size: ceil(len / k)
    let shard_size = (data.len() + k - 1) / k;
    // allocate secure shard buffers (mlocked) and fill data shards
    let mut secure_shards: Vec<SecureMemory> = Vec::with_capacity(k + m);
    for _ in 0..(k + m) {
        secure_shards.push(SecureMemory::new(shard_size)?);
    }
    for i in 0..k {
        let start = i * shard_size;
        let end = std::cmp::min(start + shard_size, data.len());
        if start < end {
            let dst = secure_shards[i].as_mut_slice();
            dst[..(end - start)].copy_from_slice(&data[start..end]);
        }
    }

    // build mutable slice refs for RS encode
    let mut shard_refs: Vec<&mut [u8]> = secure_shards.iter_mut().map(|s| s.as_mut_slice()).collect();
    r.encode(&mut shard_refs).map_err(|e| anyhow::anyhow!("rs encode: {}", e))?;

    // write shards from secure buffers
    let dir = dataset_path.join("shards").join(chunk_hex);
    fs::create_dir_all(&dir)?;
    for (i, sm) in secure_shards.into_iter().enumerate() {
        let path = dir.join(format!("{}.shard", i));
        let mut sf = crate::hardening::create_tmp_file_secure(&path)?;
        sf.write_all(sm.as_slice())?;
        sf.flush()?;
        // SecureMemory zeros on drop
    }

    // write metadata for reconstruction
    let meta = serde_json::to_vec_pretty(&serde_json::json!({
        "original_len": data.len(),
        "k": k,
        "m": m,
        "shard_size": shard_size
    }))?;
    fs::write(dir.join("meta.json"), meta)?;

    Ok(())
}

/// Try to repair missing shards and reconstruct the original chunk if possible.
pub fn repair_chunk_shards(dataset_path: &Path, chunk_hex: &str, k: usize, m: usize) -> anyhow::Result<()> {
    let dir = dataset_path.join("shards").join(chunk_hex);
    if !dir.exists() {
        return Err(anyhow::anyhow!("shard directory not found"));
    }

    let r = ReedSolomon::new(k, m).map_err(|e| anyhow::anyhow!("rs init: {}", e))?;
    let shard_count = k + m;
    // read shards into SecureMemory wrappers (None for missing)
    let mut secure_shards: Vec<Option<SecureMemory>> = Vec::with_capacity(shard_count);
    for i in 0..shard_count {
        let path = dir.join(format!("{}.shard", i));
        if path.exists() {
            let raw = fs::read(&path)?;
            secure_shards.push(Some(SecureMemory::from_vec(raw)?));
        } else {
            secure_shards.push(None);
        }
    }

    // call reconstruct directly on Vec<Option<SecureMemory>> since SecureMemory implements
    // the required traits (AsRef, AsMut, FromIterator)
    r.reconstruct(&mut secure_shards).map_err(|e| anyhow::anyhow!("rs reconstruct: {}", e))?;

    // write back any reconstructed shards from secure_shards
    for (i, opt) in secure_shards.into_iter().enumerate() {
        if let Some(sm) = opt {
            let path = dir.join(format!("{}.shard", i));
            let mut f = crate::hardening::create_tmp_file_secure(&path)?;
            f.write_all(sm.as_slice())?;
            f.flush()?;
            // sm zeros on drop
        }
    }

    Ok(())
}

pub fn reconstruct_chunk_from_shards(dataset_path: &Path, chunk_hex: &str) -> anyhow::Result<()> {
    let dir = dataset_path.join("shards").join(chunk_hex);
    if !dir.exists() {
        return Err(anyhow::anyhow!("shard directory not found"));
    }
    let meta_path = dir.join("meta.json");
    let meta_raw = fs::read(&meta_path)?;
    let meta: serde_json::Value = serde_json::from_slice(&meta_raw)?;
    let original_len = meta["original_len"].as_u64().ok_or_else(|| anyhow::anyhow!("missing original_len"))? as usize;
    let k = meta["k"].as_u64().ok_or_else(|| anyhow::anyhow!("missing k"))? as usize;

    // read first k shards into SecretBytes and concatenate
    let mut data = Vec::with_capacity(original_len);
    for i in 0..k {
        let path = dir.join(format!("{}.shard", i));
        let raw = fs::read(&path)?;
        let sm = SecureMemory::from_vec(raw)?;
        data.extend_from_slice(sm.as_slice());
        // sm zeros on drop
    }
    data.truncate(original_len);

    // write reconstructed chunk file
    let chunk_file = dataset_path.join("chunks").join(&chunk_hex[0..2]).join(format!("{}.chunk", chunk_hex));
    fs::create_dir_all(chunk_file.parent().unwrap())?;
    let mut f = crate::hardening::create_tmp_file_secure(&chunk_file)?;
    f.write_all(&data)?;
    f.flush()?;
    Ok(())
}

