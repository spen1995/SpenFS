#![cfg(feature = "tpm")]

use tempfile::tempdir;
use std::time::Duration;
use std::thread::sleep;

#[test]
fn swtpm_provision_and_counter_roundtrip() -> anyhow::Result<()> {
    // This test assumes a running TPM emulator (swtpm) and an RM (tpm2-abrmd)
    // are available on the test host. CI job will start them before running tests.
    // The test will provision an NV index, set an auth policy, write an initial
    // counter value via the API, increment, and read back.

    // quick availability probe
    crate::tpm::ensure_tpm_available().context("tpm not available")?;

    // choose an index in the reserved range for testing (operator may choose differently)
    let idx: u32 = 0x1500016;

    // Provision NV index of 16 bytes
    crate::tpm::provision_nv_index(idx, 16, None).context("provision failed")?;

    // Set a simple auth policy (auth:<hex>) to a random value
    let auth = hex::encode(&[0xA5u8; 8]);
    let blob = format!("auth:{}", auth);
    crate::tpm::set_nv_policy(idx, Some(blob.as_bytes())).context("set policy failed")?;

    // Write initial counter by directly invoking increment (which writes the value)
    let v1 = crate::tpm::increment_monotonic(idx).context("increment failed")?;
    // small sleep to ensure persistence
    sleep(Duration::from_millis(200));
    let v2 = crate::tpm::read_monotonic(idx).context("read failed")?;
    assert!(v2 >= v1);

    Ok(())
}
