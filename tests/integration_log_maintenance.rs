use std::fs;
use std::io::{Read, Write};

use flate2::write::GzEncoder;
use flate2::Compression;
use crc32fast::Hasher;

use tempfile::tempdir;

use spenfs::compressor::Compressor;

#[test]
fn log_rotation_compression_quarantine_prune_flow() -> anyhow::Result<()> {
    let td = tempdir()?;
    let ds = td.path();
    let logs = ds.join("logs");
    fs::create_dir_all(&logs)?;

    // create a gzip file named like a rotated log
    let name = "repair.log.20260101T000000Z.log.gz";
    let gz_path = logs.join(name);
    {
        let dst = spenfs::hardening::create_tmp_file_secure(&gz_path)?;
        let mut encoder = GzEncoder::new(dst, Compression::default());
        encoder.write_all(b"this is a test log line\n")?;
        encoder.finish()?;
    }

    // compute correct crc then write an incorrect .crc to force quarantine
    let mut f = fs::File::open(&gz_path)?;
    let mut reader = std::io::BufReader::new(&mut f);
    let mut hasher = Hasher::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    let _correct_crc = hasher.finalize();

    // write a wrong crc to force mismatch
    let crc_path = logs.join(format!("{}.crc", gz_path.display()));
    fs::write(&crc_path, b"deadbeef")?;

    // run verification: should detect mismatch and move both files to quarantine
    Compressor::verify_existing(logs.clone())?;

    let quarantine = logs.join("quarantine");
    assert!(quarantine.exists());
    let quarantined_gz = quarantine.join(name);
    let quarantined_crc = quarantine.join(format!("{}.crc", name));
    assert!(quarantined_gz.exists(), "gz file should be moved to quarantine");
    assert!(quarantined_crc.exists(), "crc file should be moved to quarantine");

    // dry-run prune: nothing deleted
    Compressor::prune_quarantine(&logs, 0, true)?;
    assert!(quarantined_gz.exists());

    // actual prune: remove quarantined items older than 0 days
    Compressor::prune_quarantine(&logs, 0, false)?;
    // after prune, quarantine dir may be removed or empty
    if quarantine.exists() {
        let entries: Vec<_> = fs::read_dir(&quarantine)?.collect();
        assert!(entries.is_empty(), "quarantine should be empty after prune");
    }

    Ok(())
}
