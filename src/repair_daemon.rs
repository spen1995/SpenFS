use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use crate::compressor::Compressor;

use log::{error, info, warn};
use chrono::Utc;
use serde_json::json;
use rand::Rng;

/// Run a background repair loop that periodically invokes `repair::scan_and_repair`.
/// Adds structured logging and a simple exponential backoff on repeated failures to avoid I/O storms.
pub fn run_daemon(dataset_path: &Path, k: usize, m: usize, interval_secs: u64) -> anyhow::Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        warn!("repair-daemon: received shutdown signal");
        r.store(false, Ordering::SeqCst);
    })
    .map_err(|e| anyhow::anyhow!("ctrlc handler failed: {}", e))?;

    info!("repair-daemon: starting (interval={}s) on {}", interval_secs, dataset_path.display());

    // prepare logs dir
    let logs_dir = dataset_path.join("logs");
    if let Err(e) = create_dir_all(&logs_dir) {
        warn!("repair-daemon: could not create logs dir {}: {}", logs_dir.display(), e);
    }
    let log_path = logs_dir.join("repair.log");

    // start compressor worker-pool for async compression of rotated logs
    let compress_workers: usize = std::env::var("SPENFS_COMPRESS_WORKERS").ok().and_then(|v| v.parse().ok()).unwrap_or(2usize);
    let compress_queue: usize = std::env::var("SPENFS_COMPRESS_QUEUE").ok().and_then(|v| v.parse().ok()).unwrap_or(8usize);
    let compressor = Compressor::start(compress_workers, compress_queue);
    // verify any existing rotated logs have crc sidecars (or create them)
    if let Err(e) = Compressor::verify_existing(logs_dir.clone()) {
        warn!("repair-daemon: compressor verify_existing failed: {}", e);
    }

    // Replay WAL / journal entries and inspect for incomplete operations
    // Attempt to apply in-flight journal entries (WAL replay)
    match crate::on_disk::apply_journal_entries(dataset_path) {
        Ok(_) => info!("repair-daemon: journal replay applied or empty"),
        Err(e) => warn!("repair-daemon: journal replay failed: {}", e),
    }

    // spawn a maintenance thread to periodically prune quarantine
    let prune_days: i64 = std::env::var("SPENFS_QUARANTINE_PRUNE_DAYS").ok().and_then(|v| v.parse().ok()).unwrap_or(30i64);
    let prune_interval: u64 = std::env::var("SPENFS_QUARANTINE_PRUNE_INTERVAL_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(86400u64);
    let prune_dry_run: bool = std::env::var("SPENFS_QUARANTINE_PRUNE_DRY_RUN").ok().and_then(|v| match v.as_str() { "1" | "true" | "yes" => Some(true), _ => Some(false) }).unwrap_or(false);
    {
        let running_clone = running.clone();
        let logs_clone = logs_dir.clone();
        thread::spawn(move || {
            while running_clone.load(Ordering::SeqCst) {
                if let Err(e) = Compressor::prune_quarantine(&logs_clone, prune_days, prune_dry_run) {
                    warn!("repair-daemon: quarantine prune failed: {}", e);
                }
                let mut slept = 0u64;
                while slept < prune_interval && running_clone.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_secs(1));
                    slept += 1;
                }
            }
        });
    }

    // helper to append JSON log lines with size-based rotation
    let write_log = move |level: &str, msg: &str, failures: u32| {
        // rotation threshold (bytes)
        let max_bytes: u64 = std::env::var("SPENFS_REPAIR_LOG_MAX_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(10_000_000u64);

        // rotate if file exists and exceeds threshold
        if let Ok(meta) = std::fs::metadata(&log_path) {
            if meta.len() >= max_bytes {
                // rename with timestamp suffix
                let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
                let rotated = logs_dir.join(format!("repair.log.{}", ts));
                if let Err(e) = std::fs::rename(&log_path, &rotated) {
                    warn!("repair-daemon: failed to rotate log {} -> {}: {}", log_path.display(), rotated.display(), e);
                } else {
                    // enqueue rotated file for async compression by worker-pool
                    let logs_dir_clone = logs_dir.clone();
                    if let Err(e) = compressor.enqueue(rotated, logs_dir_clone) {
                        warn!("repair-daemon: compressor enqueue failed: {}", e);
                    }
                }
            }
        }
        // open and append
        match OpenOptions::new().create(true).append(true).open(&log_path) {
            Ok(mut f) => {
                let record = json!({
                    "ts": Utc::now().to_rfc3339(),
                    "level": level,
                    "msg": msg,
                    "consecutive_failures": failures,
                });
                if let Err(e) = writeln!(f, "{}", record.to_string()) {
                    warn!("repair-daemon: failed to write log file: {}", e);
                }
            }
            Err(e) => {
                warn!("repair-daemon: failed to open log file {}: {}", log_path.display(), e);
            }
        }
    };

    // Rate-limiting/backoff parameters
    let mut consecutive_failures: u32 = 0;
    let max_backoff = std::env::var("SPENFS_REPAIR_MAX_BACKOFF_SEC").ok().and_then(|s| s.parse().ok()).unwrap_or(300u64);

    while running.load(Ordering::SeqCst) {
        let start = Instant::now();
        match derive_key_for_dataset(dataset_path) {
            Ok(key) => {
                // configurable limits per run
                let max_repairs: usize = std::env::var("SPENFS_REPAIR_MAX_PER_RUN").ok().and_then(|v| v.parse().ok()).unwrap_or(5);
                let repair_sleep_ms: u64 = std::env::var("SPENFS_REPAIR_SLEEP_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(200);
                match crate::repair::scan_and_repair(dataset_path, k, m, &key, max_repairs, repair_sleep_ms) {
                    Ok(_) => {
                        if consecutive_failures > 0 {
                            info!("repair-daemon: scan succeeded, resetting failure counter (was={})", consecutive_failures);
                            write_log("info", "scan succeeded, resetting failure counter", consecutive_failures);
                        }
                        consecutive_failures = 0;
                    }
                    Err(e) => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        let msg = format!("scan failed: {}", e);
                        error!("repair-daemon: {} (consecutive_failures={})", msg, consecutive_failures);
                        write_log("error", &msg, consecutive_failures);
                    }
                }
            }
            Err(e) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                let msg = format!("unable to derive key for dataset: {}", e);
                error!("repair-daemon: {} (consecutive_failures={})", msg, consecutive_failures);
                write_log("error", &msg, consecutive_failures);
            }
        }

        // Compute backoff: exponential based on consecutive_failures, capped to max_backoff.
        let mut backoff = if consecutive_failures == 0 { 0u64 } else { 2u64.saturating_pow(std::cmp::min(consecutive_failures, 10)) };
        if backoff > max_backoff { backoff = max_backoff; }

        // Add randomized jitter to backoff to avoid synchronized retries across nodes/processes.
        let jittered_backoff = if backoff == 0 {
            0u64
        } else {
            let mut rng = rand::thread_rng();
            // choose a jitter in [0, backoff] and add it (result capped by max_backoff)
            let jitter = rng.gen_range(0..=backoff);
            let candidate = backoff.saturating_add(jitter);
            std::cmp::min(candidate, max_backoff)
        };

        // Ensure we respect the configured interval; subtract elapsed time from interval and add jittered backoff on failures.
        let elapsed = start.elapsed().as_secs();
        let wait = if interval_secs > elapsed { interval_secs - elapsed } else { 0 };
        let total_sleep = wait.saturating_add(jittered_backoff);

        if total_sleep > 0 {
            let sleep_msg = format!("sleeping {}s (interval_wait={} backoff={} jittered={})", total_sleep, wait, backoff, jittered_backoff);
            info!("repair-daemon: {}", sleep_msg);
            write_log("info", &sleep_msg, consecutive_failures);
            let mut slept = 0u64;
            while slept < total_sleep && running.load(Ordering::SeqCst) {
                let to_sleep = std::cmp::min(1, (total_sleep - slept) as i64) as u64;
                thread::sleep(Duration::from_secs(to_sleep));
                slept += to_sleep;
            }
        }
    }

    info!("repair-daemon: exiting");
    Ok(())
}

fn derive_key_for_dataset(dataset_path: &Path) -> anyhow::Result<[u8; 32]> {
    // derive AEAD key from env passphrase and dataset header salt
    let hdr = crate::on_disk::read_header(dataset_path)?;
        let pass = crate::passphrase::retrieve_passphrase(dataset_path).unwrap_or_else(|_| "example-passphrase".to_string());
    crate::crypto::derive_key(pass.as_bytes(), &hdr.salt)
}
