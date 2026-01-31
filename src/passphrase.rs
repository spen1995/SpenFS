use std::path::Path;
use std::fs;
use anyhow::Context;

// Retrieve passphrase for a dataset.
// Order of retrieval:
// 1. Deprecated env `SPENFS_PW` (kept for backwards compatibility; logs a warning)
// 2. Env `SPENFS_PW_FILE` -> read file contents
// 3. OS keyring entry under service `spenfs:<dataset_id_hex>`, username `passphrase`
// 4. Interactive prompt via rpassword

pub fn retrieve_passphrase(dataset_root: &Path) -> anyhow::Result<String> {
    // Prefer keyring (if configured) then a passphrase file. Do NOT fall back to the
    // deprecated `SPENFS_PW` env var nor interactive prompts — callers should provide
    // `SPENFS_PW_FILE` or configure the OS keyring. This makes non-interactive runs
    // (CI, daemons) deterministic and avoids env-secret proliferation.

    // 1. attempt keyring lookup using dataset id from header
    if let Ok(hdr) = crate::on_disk::read_header(dataset_root) {
        let svc = format!("spenfs:{}", hex::encode(&hdr.dataset_id));
        let entry = keyring::Entry::new(&svc, "passphrase");
        if let Ok(pw) = entry.get_password() {
            return Ok(pw);
        }
    }

    // 2. passphrase file (explicit override useful for CI/automation)
    if let Ok(pf) = std::env::var("SPENFS_PW_FILE") {
        let s = fs::read_to_string(&pf).context("read passphrase file")?;
        return Ok(s.trim_end().to_string());
    }

    Err(anyhow::anyhow!("passphrase unavailable: configure keyring entry or set SPENFS_PW_FILE"))
}

pub fn store_passphrase_in_keyring(dataset_root: &Path, passphrase: &str) -> anyhow::Result<()> {
    let hdr = crate::on_disk::read_header(dataset_root).context("read header for keyring id")?;
    let svc = format!("spenfs:{}", hex::encode(&hdr.dataset_id));
    let entry = keyring::Entry::new(&svc, "passphrase");
    entry.set_password(passphrase).map_err(|e| anyhow::anyhow!("keyring set_password: {}", e))?;
    Ok(())
}
