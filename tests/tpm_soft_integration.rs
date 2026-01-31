#![cfg(any(feature = "tpm", feature = "tpm-mock"))]

use anyhow::Context;
use tempfile::tempdir;
use spenfs::tpm;

#[test]
fn softtpm_nv_counter_roundtrip() -> anyhow::Result<()> {
    // Skip early if TPM not available in the environment
    if let Err(e) = tpm::ensure_tpm_available() {
        eprintln!("TPM not available: {} -- skipping SoftTPM integration test", e);
        return Ok(());
    }

    // Choose an index (operator may override via env)
    let idx = std::env::var("SPENFS_TPM_NV_INDEX").ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0x01500000u32);

    // Attempt to provision NV index; ignore "already defined" errors.
    match tpm::provision_nv_index(idx, 8, None) {
        Ok(_) => {}
        Err(e) => eprintln!("provision_nv_index returned warning: {}", e),
    }

    // Read current (may be zero)
    let v1 = tpm::read_monotonic(idx).context("read_monotonic failed")?;
    let v2 = tpm::increment_monotonic(idx).context("increment_monotonic failed")?;
    assert_eq!(v2, v1 + 1);

    // Read back
    let v3 = tpm::read_monotonic(idx).context("read_monotonic 2 failed")?;
    assert_eq!(v3, v2);

    Ok(())
}
