#![cfg(all(test, target_os = "linux"))]

use spenfs::hardening::SecureMemory;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};

#[test]
fn secure_memory_drop_zeroizes_via_proc_mem() -> anyhow::Result<()> {
    // best-effort test for Linux: allocate SecureMemory, write pattern, capture pointer,
    // drop it, then read /proc/self/mem at the pointer to ensure zeros.
    let mut sm = SecureMemory::new(64)?;
    sm.as_mut_slice().fill(0xAA);
    let ptr = sm.as_ptr_for_test();
    let len = sm.as_slice().len();
    // obtain raw address
    let addr = ptr as usize;
    // drop the SecureMemory to trigger zeroize & munlock
    drop(sm);

    // Try to read /proc/self/mem at addr. Best-effort: skip the test if procfs access
    // is restricted (common on CI or unprivileged runners) rather than failing.
    let mut f = match OpenOptions::new().read(true).open("/proc/self/mem") {
        Ok(f) => f,
        Err(e) => {
            eprintln!("skipping procfs read: {}", e);
            return Ok(());
        }
    };

    // Seek to the address and read len bytes; if any step fails, skip the assertion.
    if let Err(e) = f.seek(SeekFrom::Start(addr as u64)) {
        eprintln!("skipping procfs seek: {}", e);
        return Ok(());
    }

    let mut buf = vec![0u8; len];
    if let Err(e) = f.read_exact(&mut buf) {
        eprintln!("skipping procfs read_exact: {}", e);
        return Ok(());
    }

    // expect zeros
    for b in buf.iter() {
        assert_eq!(*b, 0u8, "expected zeroized memory after drop");
    }
    Ok(())
}
