use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use crossbeam_channel::{bounded, Receiver, Sender};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::io;
use std::io::{Read, Write};
use crc32fast::Hasher;
use chrono::Utc;
use log::{warn, info};

pub struct Compressor {
    sender: Arc<Sender<(PathBuf, PathBuf)>>,
    handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Compressor {
    pub fn start(workers: usize, queue_size: usize) -> Self {
        let (tx, rx) = bounded::<(PathBuf, PathBuf)>(queue_size);
        let sender = Arc::new(tx);
        let handles = Arc::new(Mutex::new(Vec::new()));

        for i in 0..workers {
            let rx_clone: Receiver<(PathBuf, PathBuf)> = rx.clone();
            let handles_clone = handles.clone();
            let handle = thread::Builder::new()
                .name(format!("compressor-{}", i))
                .spawn(move || {
                    while let Ok((rotated, logs_dir)) = rx_clone.recv() {
                        if let Err(e) = compress_and_cleanup(&rotated, &logs_dir) {
                            warn!("compressor: failed to compress {}: {}", rotated.display(), e);
                        }
                    }
                })
                .expect("failed to spawn compressor worker");
            handles_clone.lock().unwrap().push(handle);
        }

        Compressor { sender, handles }
    }

    pub fn list_quarantine(logs_dir: &std::path::Path) -> io::Result<Vec<String>> {
        let quarantine = logs_dir.join("quarantine");
        let mut names = Vec::new();
        if quarantine.exists() {
            for e in fs::read_dir(&quarantine)? {
                let entry = e?;
                if let Ok(n) = entry.file_name().into_string() {
                    names.push(n);
                }
            }
        }
        Ok(names)
    }

    pub fn restore_quarantined(logs_dir: &std::path::Path, name: &str) -> io::Result<()> {
        let quarantine = logs_dir.join("quarantine");
        let src = quarantine.join(name);
        if !src.exists() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "quarantined file not found"));
        }
        let dest = logs_dir.join(name);
        fs::rename(&src, &dest)?;
        // if there's a .crc partner, move it too
        let crc_name = format!("{}.crc", name);
        let src_crc = quarantine.join(&crc_name);
        if src_crc.exists() {
            let dest_crc = logs_dir.join(&crc_name);
            let _ = fs::rename(&src_crc, &dest_crc);
        }
        Ok(())
    }

    pub fn prune_quarantine(logs_dir: &std::path::Path, max_age_days: i64, dry_run: bool) -> io::Result<()> {
        let quarantine = logs_dir.join("quarantine");
        if !quarantine.exists() {
            return Ok(());
        }
        let now = std::time::SystemTime::now();
        let cutoff = std::time::Duration::from_secs((max_age_days as u64).saturating_mul(24 * 3600));
        for e in fs::read_dir(&quarantine)? {
            let entry = e?;
            let path = entry.path();
            if let Ok(meta) = fs::metadata(&path) {
                if let Ok(modified) = meta.modified() {
                    if let Ok(elapsed) = now.duration_since(modified) {
                        if elapsed >= cutoff {
                            if dry_run {
                                info!("compressor: prune (dry-run) would remove {}", path.display());
                            } else {
                                let _ = fs::remove_file(&path);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn enqueue(&self, rotated: PathBuf, logs_dir: PathBuf) -> Result<(), crossbeam_channel::SendError<(PathBuf, PathBuf)>> {
        self.sender.send((rotated, logs_dir))
    }

    pub fn verify_existing(logs_dir: PathBuf) -> io::Result<()> {
        // scan for existing rotated .log.gz files and ensure .crc sidecars exist and match
        if let Ok(entries) = fs::read_dir(&logs_dir) {
            for e in entries.filter_map(|e| e.ok()) {
                let name = e.file_name().into_string().unwrap_or_default();
                if name.starts_with("repair.log.") && name.ends_with(".log.gz") {
                    let gz_path = logs_dir.join(&name);
                    let crc_path = PathBuf::from(format!("{}{}.crc", gz_path.display(), ""));
                    if crc_path.exists() {
                        // verify
                        if let Ok(existing) = fs::read_to_string(&crc_path) {
                            let s = existing.trim();
                            if let Ok(expected) = u32::from_str_radix(s, 16) {
                                // compute crc
                                if let Ok(mut f) = fs::File::open(&gz_path) {
                                    let mut reader = std::io::BufReader::new(&mut f);
                                    let mut hasher = Hasher::new();
                                    let mut buf = [0u8; 8192];
                                    loop {
                                        match reader.read(&mut buf) {
                                            Ok(0) => break,
                                            Ok(n) => hasher.update(&buf[..n]),
                                            Err(_) => break,
                                        }
                                    }
                                    let crc = hasher.finalize();
                                    if crc != expected {
                                        warn!("compressor: CRC mismatch for {}: expected {:08x} got {:08x}", gz_path.display(), expected, crc);
                                        // move mismatched files to quarantine for manual inspection
                                        let quarantine = logs_dir.join("quarantine");
                                        let _ = fs::create_dir_all(&quarantine);
                                        let dest_gz = quarantine.join(name.clone());
                                        let dest_crc = quarantine.join(format!("{}.crc", name));
                                        if let Err(e) = fs::rename(&gz_path, &dest_gz) {
                                            warn!("compressor: failed to move {} to quarantine: {}", gz_path.display(), e);
                                        }
                                        if let Err(e) = fs::rename(&crc_path, &dest_crc) {
                                            // if cannot move crc, still continue
                                            warn!("compressor: failed to move {} to quarantine: {}", crc_path.display(), e);
                                        }
                                    } else {
                                        info!("compressor: verified crc for {}", gz_path.display());
                                    }
                                }
                            }
                        }
                                } else {
                            // missing crc file: compute and write
                            if let Ok(mut f) = fs::File::open(&gz_path) {
                                let mut reader = std::io::BufReader::new(&mut f);
                                let mut hasher = Hasher::new();
                                let mut buf = [0u8; 8192];
                                loop {
                                    match reader.read(&mut buf) {
                                        Ok(0) => break,
                                        Ok(n) => hasher.update(&buf[..n]),
                                        Err(_) => break,
                                    }
                                }
                                let crc = hasher.finalize();
                                let crc_path = PathBuf::from(format!("{}.crc", gz_path.display()));
                                if let Ok(mut cf) = crate::hardening::create_tmp_file_secure(&crc_path) {
                                    let _ = write!(&mut cf, "{:08x}", crc);
                                }
                            }
                        }
                }
            }
        }
        Ok(())
    }
}

impl Drop for Compressor {
    fn drop(&mut self) {
        // Dropping sender will close channel and cause workers to exit; join handles.
        // First drop the Arc<SyncSender> by replacing with a new dummy sender inside a new Arc.
        // To drop we simply take the handles and join them.
        let mut handles = self.handles.lock().unwrap();
        while let Some(h) = handles.pop() {
            let _ = h.join();
        }
    }
}

fn compress_and_cleanup(rotated: &PathBuf, logs_dir: &PathBuf) -> io::Result<()> {
    let gz_path = rotated.with_extension("log.gz");
    let src = fs::File::open(rotated)?;
    let dst = crate::hardening::create_tmp_file_secure(&gz_path)?;
    let mut encoder = GzEncoder::new(dst, Compression::default());
    io::copy(&mut std::io::BufReader::new(src), &mut encoder)?;
    // finish and obtain inner writer to ensure all data flushed
    let _inner = encoder.finish()?;

    // compute CRC32 of resulting gzip file and write .crc file
    let mut f = fs::File::open(&gz_path)?;
    let mut reader = std::io::BufReader::new(&mut f);
    let mut hasher = Hasher::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    let crc = hasher.finalize();
    // write crc as hex to a .crc sidecar file
    let crc_path = PathBuf::from(format!("{}.crc", gz_path.display()));
    if let Ok(mut cf) = crate::hardening::create_tmp_file_secure(&crc_path) {
        use std::fmt::Write as FmtWrite;
        let mut s = String::new();
        let _ = write!(&mut s, "{:08x}", crc);
        let _ = cf.write_all(s.as_bytes());
    }

    // remove original rotated file only after crc written
    fs::remove_file(rotated)?;

    // enforce rotate-count
    let rotate_keep: usize = std::env::var("SPENFS_REPAIR_LOG_ROTATE_COUNT").ok().and_then(|v| v.parse().ok()).unwrap_or(7usize);
    if let Ok(entries) = fs::read_dir(logs_dir) {
        let mut names: Vec<String> = entries.filter_map(|e| e.ok()).map(|e| e.file_name().into_string().unwrap_or_default()).filter(|n| n.starts_with("repair.log.") && n.ends_with(".gz")).collect();
        names.sort_by(|a, b| b.cmp(a));
        if names.len() > rotate_keep {
            for old in names.iter().skip(rotate_keep) {
                let p = logs_dir.join(old);
                let _ = fs::remove_file(&p);
            }
        }
        // age-based retention
        let max_age_days: i64 = std::env::var("SPENFS_REPAIR_LOG_MAX_AGE_DAYS").ok().and_then(|v| v.parse().ok()).unwrap_or(30i64);
        if max_age_days > 0 {
            let now = Utc::now();
            for name in names.iter() {
                if name.ends_with(".gz") {
                    if let Some(ts_str) = name.strip_prefix("repair.log.") {
                        let ts_str = ts_str.strip_suffix(".log.gz").unwrap_or(ts_str);
                        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y%m%dT%H%M%SZ") {
                            let dt = chrono::DateTime::from_naive_utc_and_offset(naive, Utc);
                            if (now - dt).num_days() > max_age_days {
                                let p = logs_dir.join(name);
                                let _ = fs::remove_file(&p);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
