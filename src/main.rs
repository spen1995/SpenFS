use std::path::Path;
use std::fs::File;
use std::io::Write;

use spenfs::on_disk::{write_header, Header};
use rpassword;

fn prompt_passphrase_with_env(dataset_path: &str, _prompt: &str) -> anyhow::Result<String> {
    // Use secure retrieval helper: keyring, passphrase file, or interactive prompt.
    let p = spenfs::passphrase::retrieve_passphrase(std::path::Path::new(dataset_path))?;
    Ok(p)
}

fn usage() {
    eprintln!("Usage: spenfs init <path>");
}

fn cmd_init(path: &str) -> anyhow::Result<()> {
    let p = Path::new(path);

    let mut hdr = Header::new();
    // generate signing keypair for dataset
    let kp = spenfs::crypto::ed25519_generate()?;
    hdr.signing_pubkey = kp.public.to_bytes();

    // Prompt for dataset passphrase (required): this enables AEAD encryption by default.
    let prompt = format!("Enter new passphrase for dataset {}: ", path);
    let pass1 = prompt_passphrase_with_env(path, &prompt)?;
    let pass2 = prompt_passphrase_with_env(path, "Confirm passphrase: ")?;
    if pass1 != pass2 {
        return Err(anyhow::anyhow!("passphrases do not match"));
    }

    // mark header as encryption-enabled (flag bit 0)
    hdr.flags |= 0x01;
    // store a KDF param (e.g., memory_kib) for future derives
    hdr.kdf_params = 65536u32;

    // write private key encrypted under the dataset passphrase to keys/signing.key.enc
    let keys_dir = p.join("keys");
    std::fs::create_dir_all(&keys_dir)?;
    let sk_path = keys_dir.join("signing.key.enc");
    let sk_vec = kp.secret.to_bytes().to_vec();
    let sk_sm = spenfs::hardening::SecureMemory::from_vec(sk_vec)?;
    // derive AEAD key from passphrase and header salt
    let aead_key = spenfs::crypto::derive_key(pass1.as_bytes(), &hdr.salt)?;
    let encrypted = spenfs::crypto::aead_encrypt(&aead_key, sk_sm.as_slice(), &hdr.dataset_id)?;
    // zeroize secret material (SecureMemory will clear on drop)
    drop(sk_sm);
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(&sk_path, &encrypted)?;
    let mut perms = std::fs::metadata(&sk_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&sk_path, perms)?;

    // write header.bin (fixed-size) and header.sig (signature over header bytes)
    write_header(p, &hdr)?;
    let _header_path = p.join("header.bin");
    let bytes = hdr.to_fixed_bytes()?;
    let sig = spenfs::crypto::ed25519_sign(&kp, &bytes);
    // write signature atomically using secure tmp file
    let sig_tmp = p.join("header.sig.tmp");
    let sig_path = p.join("header.sig");
    let mut sf = spenfs::hardening::create_tmp_file_secure(&sig_tmp)?;
    sf.write_all(sig.to_bytes().as_ref())?;
    sf.sync_all()?;
    std::fs::rename(&sig_tmp, &sig_path)?;
    let _ = File::open(&sig_path)?.sync_all();

    println!("Wrote header to {}/header.bin", path);
    println!("Wrote signing key to {}/keys/signing.key.enc", path);
    println!("Wrote header signature to {}/header.sig", path);
    println!("Encryption: enabled (dataset will require a passphrase via keyring or passphrase-file)");
    println!("salt (hex): {}", hex::encode(&hdr.salt));

    Ok(())
}

fn cmd_put(dataset_path: &str, file: &str) -> anyhow::Result<()> {
    let p = std::path::Path::new(dataset_path);
    let hdr = spenfs::on_disk::read_header(p)?;
    // derive key from environment/passphrase-file or prompt interactively
    let pass = prompt_passphrase_with_env(dataset_path, &format!("Enter passphrase for dataset {}: ", dataset_path))?;
    let aead_key = spenfs::crypto::derive_key(pass.as_bytes(), &hdr.salt)?;

    let params = spenfs::chunker::ChunkerParams::default();
    let rs_k: usize = std::env::var("SPENFS_RS_K").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    let rs_m: usize = std::env::var("SPENFS_RS_M").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    let chunker = spenfs::chunker::GearChunker::new_with_redundancy(params, Some((rs_k, rs_m)));
    let mut file_h = std::fs::File::open(file)?;
    let chunks = chunker.chunk_and_store(&mut file_h, &p.join("chunks"), &aead_key)?;
    println!("Stored {} chunks", chunks.len());
    for c in chunks.iter().take(10) {
        println!("chunk {}", c);
    }
    
        // create file manifest and write it
        let metadata_dir = p.join("manifests");
        std::fs::create_dir_all(&metadata_dir)?;
        let size = std::fs::metadata(file)?.len();
        let fname = std::path::Path::new(file)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed".to_string());
        let fm = spenfs::manifest::FileManifest::new(fname, size, chunks.clone())?;
        let fm_id = spenfs::manifest::write_file_manifest(&metadata_dir, &fm)?;
        println!("Wrote file manifest {}", fm_id);

        // After writing a file manifest, create an atomic snapshot manifest that includes it.
        // This wraps snapshot creation in a StartTxn/CommitManifest/EndTxn flow.
        let mut file_manifests = Vec::new();
        for entry in std::fs::read_dir(&metadata_dir)? {
            let entry = entry?;
            let name = entry.file_name().into_string().unwrap_or_default();
            if name.starts_with("filemanifest-") && name.ends_with(".bin") {
                let v = std::fs::read(entry.path())?;
                let fm: spenfs::manifest::FileManifest = rmp_serde::from_slice(&v)?;
                file_manifests.push(fm);
            }
        }
        let seq = next_manifest_seq(p)?;
        let kp = match spenfs::keys::load_signing_key(p) {
            Ok(k) => k,
            Err(_) => spenfs::crypto::ed25519_generate()?,
        };
        spenfs::upload::commit_snapshot_transaction(p, seq, &file_manifests, &kp, &aead_key)?;
        println!("Created snapshot manifest seq={}", seq);

        Ok(())
}

    #[allow(dead_code)]
    fn cmd_snapshot(dataset_path: &str) -> anyhow::Result<()> {
        let p = std::path::Path::new(dataset_path);
        let manifests_dir = p.join("manifests");
        let mut file_manifests = Vec::new();
        for entry in std::fs::read_dir(&manifests_dir)? {
            let entry = entry?;
            let name = entry.file_name().into_string().unwrap_or_default();
            if name.starts_with("filemanifest-") && name.ends_with(".bin") {
                let v = std::fs::read(entry.path())?;
                let fm: spenfs::manifest::FileManifest = rmp_serde::from_slice(&v)?;
                file_manifests.push(fm);
            }
        }

        // pick next manifest seq
        let seq = next_manifest_seq(p)?;

        // try to load persistent signer from keys/, fall back to ephemeral
        let kp = match spenfs::keys::load_signing_key(p) {
            Ok(k) => k,
            Err(_) => spenfs::crypto::ed25519_generate()?,
        };
        let hdr = spenfs::on_disk::read_header(p)?;
        let pass = prompt_passphrase_with_env(dataset_path, &format!("Enter passphrase for dataset {}: ", dataset_path))?;
        let aead_key = spenfs::crypto::derive_key(pass.as_bytes(), &hdr.salt)?;

        spenfs::upload::commit_snapshot_transaction(p, seq, &file_manifests, &kp, &aead_key)?;
        println!("Wrote snapshot manifest seq={}", seq);
        Ok(())
    }

    fn next_manifest_seq(dataset_path: &std::path::Path) -> anyhow::Result<u64> {
        let mut max = 0u64;
        let dir = dataset_path.join("manifests");
        if dir.exists() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let name = entry.file_name().into_string().unwrap_or_default();
                if name.starts_with("manifest-") && name.ends_with(".bin") {
                    if let Some(mid) = name.strip_prefix("manifest-").and_then(|s| s.strip_suffix(".bin")) {
                        if let Ok(n) = mid.parse::<u64>() {
                            if n > max { max = n }
                        }
                    }
                }
            }
        }
        Ok(max + 1)
    }

fn main() -> anyhow::Result<()> {
    // initialize logging (configurable via RUST_LOG)
    env_logger::init();
    // Enforce/check RLIMIT_MEMLOCK early to surface configuration problems.
    match spenfs::hardening::check_mlock_limit() {
        Ok((cur, rec)) => {
            if cur < rec {
                if std::env::var("SPENFS_FAIL_ON_MLOCK").ok().as_deref() == Some("1") {
                    return Err(anyhow::anyhow!(format!("RLIMIT_MEMLOCK too low: {} bytes < recommended {} bytes", cur, rec)));
                } else {
                    log::warn!("RLIMIT_MEMLOCK is low: {} bytes < recommended {} bytes; secrets may be unprotected. Set SPENFS_FAIL_ON_MLOCK=1 to fail startup.", cur, rec);
                }
            } else {
                log::debug!("RLIMIT_MEMLOCK OK: {} bytes", cur);
            }
        }
        Err(e) => {
            log::warn!("Could not check RLIMIT_MEMLOCK: {}", e);
        }
    }
    // allow a global flag `--passphrase-file <path>` or `--passphrase-file=<path>`
    let mut args_vec: Vec<String> = std::env::args().skip(1).collect();
    if let Some(pos) = args_vec.iter().position(|a| a == "--passphrase-file") {
        if pos + 1 < args_vec.len() {
            let pf = args_vec.remove(pos + 1);
            args_vec.remove(pos);
            std::env::set_var("SPENFS_PW_FILE", pf);
        }
    } else if let Some(idx) = args_vec.iter().position(|a| a.starts_with("--passphrase-file=")) {
        let kv = args_vec.remove(idx);
        if let Some(eq) = kv.find('=') {
            let pf = kv[eq+1..].to_string();
            std::env::set_var("SPENFS_PW_FILE", pf);
        }
    }
    let mut args = args_vec.into_iter();
    match args.next().as_deref() {
        Some("init") => {
            if let Some(p) = args.next() {
                cmd_init(&p)?;
            } else {
                usage();
            }
        }
        Some("put") => {
            if let (Some(ds), Some(file)) = (args.next(), args.next()) {
                cmd_put(&ds, &file)?;
            } else {
                usage();
            }
        }
        Some("upload-start") => {
            if let (Some(ds), Some(file)) = (args.next(), args.next()) {
                let p = std::path::Path::new(&ds);
                let state = spenfs::upload::start_upload(p, &file)?;
                println!("Upload started: {}", state.id);
            } else { usage(); }
        }
        Some("upload-resume") => {
            if let (Some(ds), Some(id)) = (args.next(), args.next()) {
                let p = std::path::Path::new(&ds);
                let hdr = spenfs::on_disk::read_header(p)?;
                let pass = prompt_passphrase_with_env(&ds, &format!("Enter passphrase for dataset {}: ", ds))?;
                let aead_key = spenfs::crypto::derive_key(pass.as_bytes(), &hdr.salt)?;
                let state = spenfs::upload::resume_upload(p, &id, &aead_key)?;
                println!("Upload resumed: {} offset={} chunks={}", state.id, state.offset, state.chunks.len());
            } else { usage(); }
        }
        Some("encode-chunk") => {
            if let (Some(ds), Some(chunk), Some(k), Some(m)) = (args.next(), args.next(), args.next(), args.next()) {
                let p = std::path::Path::new(&ds);
                let k: usize = k.parse().unwrap_or(10);
                let m: usize = m.parse().unwrap_or(4);
                spenfs::redundancy::encode_chunk_shards(p, &chunk, k, m)?;
                println!("Encoded chunk {} -> {}+{} shards", chunk, k, m);
            } else { usage(); }
        }
        Some("repair-chunk") => {
            if let (Some(ds), Some(chunk), Some(k), Some(m)) = (args.next(), args.next(), args.next(), args.next()) {
                let p = std::path::Path::new(&ds);
                let k: usize = k.parse().unwrap_or(10);
                let m: usize = m.parse().unwrap_or(4);
                spenfs::redundancy::repair_chunk_shards(p, &chunk, k, m)?;
                println!("Repaired chunk {} shards", chunk);
            } else { usage(); }
        }
        Some("repair-scan") => {
            if let (Some(ds), Some(k), Some(m)) = (args.next(), args.next(), args.next()) {
                let p = std::path::Path::new(&ds);
                let k: usize = k.parse().unwrap_or(10);
                let m: usize = m.parse().unwrap_or(4);
                let hdr = spenfs::on_disk::read_header(p)?;
                let pass = prompt_passphrase_with_env(&ds, "Enter passphrase for dataset: ")?;
                let aead_key = spenfs::crypto::derive_key(pass.as_bytes(), &hdr.salt)?;
                let max_repairs: usize = std::env::var("SPENFS_REPAIR_MAX_PER_RUN").ok().and_then(|v| v.parse().ok()).unwrap_or(5);
                let repair_sleep_ms: u64 = std::env::var("SPENFS_REPAIR_SLEEP_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(200);
                spenfs::repair::scan_and_repair(p, k, m, &aead_key, max_repairs, repair_sleep_ms)?;
            } else { usage(); }
        }
        Some("repair-daemon") => {
            if let (Some(ds), Some(k), Some(m), Some(interval)) = (args.next(), args.next(), args.next(), args.next()) {
                let p = std::path::Path::new(&ds);
                let k: usize = k.parse().unwrap_or(10);
                let m: usize = m.parse().unwrap_or(4);
                let interval: u64 = interval.parse().unwrap_or(300);
                spenfs::repair_daemon::run_daemon(p, k, m, interval)?;
            } else { usage(); }
        }
        Some("quarantine-list") => {
            if let Some(ds) = args.next() {
                let p = std::path::Path::new(&ds);
                let logs = p.join("logs");
                let items = spenfs::compressor::Compressor::list_quarantine(&logs)?;
                for i in items { println!("{}", i); }
            } else { usage(); }
        }
        Some("quarantine-restore") => {
            if let (Some(ds), Some(name)) = (args.next(), args.next()) {
                let p = std::path::Path::new(&ds);
                let logs = p.join("logs");
                spenfs::compressor::Compressor::restore_quarantined(&logs, &name)?;
                println!("restored {}", name);
            } else { usage(); }
        }
        Some("quarantine-prune") => {
            if let Some(ds) = args.next() {
                // parse optional arguments: [days] and optional --dry-run token
                let mut days: i64 = 30;
                let mut dry_run = false;
                if let Some(next1) = args.next() {
                    if next1 == "--dry-run" {
                        dry_run = true;
                        if let Some(next2) = args.next() {
                            days = next2.parse().unwrap_or(30);
                        }
                    } else {
                        days = next1.parse().unwrap_or(30);
                        if let Some(next2) = args.next() {
                            if next2 == "--dry-run" { dry_run = true; }
                        }
                    }
                }
                let p = std::path::Path::new(&ds);
                let logs = p.join("logs");
                spenfs::compressor::Compressor::prune_quarantine(&logs, days, dry_run)?;
                println!("pruned quarantine older than {} days{}", days, if dry_run { " (dry-run)" } else { "" });
            } else { usage(); }
        }
        Some("kms-wrap") => {
            if let Some(ds) = args.next() {
                let p = std::path::Path::new(&ds);
                spenfs::keys::kms_wrap(p)?;
                println!("Wrapped keys/signing.key.enc -> keys/signing.key.kms for {}", ds);
            } else { usage(); }
        }
        Some("keys") => {
            if let Some(sub) = args.next() {
                if sub == "change-passphrase" {
                    if let Some(ds) = args.next() {
                        let p = std::path::Path::new(&ds);
                        spenfs::keys::change_signing_key_passphrase(p)?;
                        println!("changed passphrase for dataset {}", ds);
                    } else { usage(); }
                } else {
                    usage();
                }
            } else { usage(); }
        }
        _ => usage(),
    }
    Ok(())
}
