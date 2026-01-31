pub mod on_disk;
pub mod manifest;
pub mod crypto;
pub mod keys;
pub mod envelope;
pub mod chunker;
pub mod upload;
pub mod redundancy;
pub mod repair;
pub mod repair_daemon;
pub mod compressor;
pub mod hardening;
pub mod ed25519_compat;
pub mod passphrase;
pub mod kms;
#[cfg(any(feature = "tpm", feature = "tpm-mock"))]
pub mod tpm;
#[cfg(feature = "enclave-se")]
pub mod enclave_se;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;

#[cfg(test)]
mod tests {
    use super::on_disk::Header;

    #[test]
    fn header_roundtrip() {
        let h = Header::new();
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("header.bin");
        h.write_atomic_fixed(&p).unwrap();
        let back = Header::read_from_fixed(&p).unwrap();
        assert_eq!(h.version, back.version);
        assert_eq!(h.magic, back.magic);
        assert_eq!(h.salt.len(), back.salt.len());
    }
}
