#[cfg(unix)]
#[test]
fn tmp_file_created_with_0600() -> anyhow::Result<()> {
    use tempfile::tempdir;
    use std::os::unix::fs::PermissionsExt;
    use std::io::Write;
    let td = tempdir()?;
    let p = td.path().join("secret.tmp");
    let mut f = spenfs::hardening::create_tmp_file_secure(&p)?;
    f.write_all(b"hello")?;
    f.sync_all()?;
    let meta = std::fs::metadata(&p)?;
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    Ok(())
}

#[cfg(not(unix))]
#[test]
fn tmp_file_created_best_effort() -> anyhow::Result<()> {
    // On non-unix, just ensure file is created and writable
    let td = tempfile::tempdir()?;
    let p = td.path().join("secret.tmp");
    let mut f = spenfs::hardening::create_tmp_file_secure(&p)?;
    f.write_all(b"hello")?;
    f.sync_all()?;
    assert!(p.exists());
    Ok(())
}
