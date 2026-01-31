use std::path::Path;
use std::fs;

/// Scan chunks and attempt to verify/decrypt; if missing or corrupted, try to repair from shards.
pub fn scan_and_repair(dataset_path: &Path, k: usize, m: usize, aead_key: &[u8; 32], max_repairs: usize, repair_sleep_ms: u64) -> anyhow::Result<()> {
    let chunks_dir = dataset_path.join("chunks");
    if !chunks_dir.exists() {
        return Ok(());
    }

    let mut total = 0usize;
    let mut repaired = 0usize;
    // First, scan existing chunk files and attempt to repair corrupted ones.
    for entry in fs::read_dir(&chunks_dir)? {
        let sub = entry?;
        if !sub.path().is_dir() { continue; }
        for c in fs::read_dir(sub.path())? {
            let file = c?;
            let fname = file.file_name().into_string().unwrap_or_default();
            if !fname.ends_with(".chunk") { continue; }
            let chunk_hex = fname.trim_end_matches(".chunk");
            total += 1;
            let path = file.path();
            // try decrypt and validate
            let data = fs::read(&path);
            let need_repair = match data {
                Ok(payload) => {
                    match crate::crypto::aead_decrypt(aead_key, &payload, &hex::decode(&chunk_hex).unwrap_or_default()) {
                        Ok(pt) => {
                            // verify blake3 matches
                            let h = blake3::hash(pt.as_slice()).to_hex().to_string(); 
                            h != chunk_hex 
                        }
                        Err(_) => true,
                    }
                }
                Err(_) => true,
            };

            if need_repair {
                eprintln!("Repairing chunk {}", chunk_hex);
                let _ = crate::redundancy::repair_chunk_shards(dataset_path, chunk_hex, k, m);
                if crate::redundancy::reconstruct_chunk_from_shards(dataset_path, chunk_hex).is_ok() {
                    // after reconstruct, try decrypt/verify
                    let chunk_file = dataset_path.join("chunks").join(&chunk_hex[0..2]).join(format!("{}.chunk", chunk_hex));
                    if let Ok(payload) = fs::read(&chunk_file) {
                        if let Ok(pt) = crate::crypto::aead_decrypt(aead_key, &payload, &hex::decode(&chunk_hex).unwrap_or_default()) {
                            if blake3::hash(pt.as_slice()).to_hex().to_string() == chunk_hex {
                                repaired += 1;
                                if repaired >= max_repairs { println!("Scan complete: total={} repaired={} (limit reached)", total, repaired); return Ok(()); } 
                                if repair_sleep_ms > 0 { std::thread::sleep(std::time::Duration::from_millis(repair_sleep_ms)); }
                            }
                        }
                    }
                }
            }
        }
    }

    // Next, detect missing chunks by scanning the shards directory — if shards exist but chunk missing, reconstruct.
    let shards_dir = dataset_path.join("shards");
    if shards_dir.exists() {
        for entry in fs::read_dir(&shards_dir)? {
            let sub = entry?;
            if !sub.path().is_dir() { continue; }
            let chunk_hex = sub.file_name().into_string().unwrap_or_default();
            let chunk_file = dataset_path.join("chunks").join(&chunk_hex[0..2]).join(format!("{}.chunk", chunk_hex));
            if !chunk_file.exists() {
                eprintln!("Reconstructing missing chunk {} from shards", chunk_hex);
                if crate::redundancy::reconstruct_chunk_from_shards(dataset_path, &chunk_hex).is_ok() {
                    // verify and count
                    if let Ok(payload) = fs::read(&chunk_file) {
                        if let Ok(pt) = crate::crypto::aead_decrypt(aead_key, &payload, &hex::decode(&chunk_hex).unwrap_or_default()) {
                            if blake3::hash(pt.as_slice()).to_hex().to_string() == chunk_hex {
                                repaired += 1;
                                total += 1; 
                                if repaired >= max_repairs { println!("Scan complete: total={} repaired={} (limit reached)", total, repaired); return Ok(()); }
                                if repair_sleep_ms > 0 { std::thread::sleep(std::time::Duration::from_millis(repair_sleep_ms)); }
                            }
                        }
                    }
                }
            }
        }
    }

    println!("Scan complete: total={} repaired={}", total, repaired);
    Ok(())
}
