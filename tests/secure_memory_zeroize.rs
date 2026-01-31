use spenfs::hardening::SecureMemory;

#[test]
fn secure_memory_random_and_drop() -> anyhow::Result<()> {
    let sm = SecureMemory::random(16)?;
    assert_eq!(sm.as_slice().len(), 16);
    // rely on Drop to zeroize; explicitly drop now
    drop(sm);
    Ok(())
}
