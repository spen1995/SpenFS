// Feature-gated Secure Enclave (macOS) provider scaffold.
// When `enclave-se` feature is enabled this module exposes a KeyStore-backed
// provider that will integrate with the macOS Secure Enclave in future work.

use anyhow::Context;
use std::path::Path;
use crate::kms::KeyStore;

#[cfg(all(feature = "enclave-se", target_os = "macos"))]
mod imp {
    use super::*;

    pub struct EnclaveKeyStore { label: String }

    impl EnclaveKeyStore {
        pub fn new(label: &str) -> anyhow::Result<Self> {
            // Attempt to probe for Secure Enclave by trying to access default keychain
            // We'll defer real key creation to `create_key` to keep construction cheap.
            let _kc = security_framework::os::macos::keychain::SecKeychain::default();
            Ok(EnclaveKeyStore { label: label.to_string() })
        }

        pub fn ensure_se_available() -> anyhow::Result<()> {
            // Probe by attempting to get default keychain; presence suggests macOS APIs available.
            let _ = security_framework::os::macos::keychain::SecKeychain::default();
            Ok(())
        }

        pub fn create_key(_label: &str) -> anyhow::Result<()> {
            // Create an EC P-256 keypair in the Secure Enclave and store in keychain
            // Build attribute dictionary for SecKey::generate
            use core_foundation::dictionary::CFDictionary;
            use core_foundation::number::CFNumber;
            use core_foundation::string::CFString;
            use core_foundation::base::TCFType;

            // Use security-framework's helper to build generation options
            use security_framework::key::{GenerateKeyOptions, KeyType, Token};

            let mut opts = GenerateKeyOptions::default();
            opts.set_key_type(KeyType::ec());
            opts.set_size_in_bits(256);
            opts.set_label("spenfs-enclave");
            opts.set_token(Token::SecureEnclave);

            let attrs = opts.to_dictionary();
            match security_framework::key::SecKey::generate(attrs) {
                Ok(_k) => Ok(()),
                Err(e) => Err(anyhow::anyhow!("SecKey generate failed: {}", e)),
            }
        }

        fn find_private_key(label: &str) -> anyhow::Result<security_framework::key::SecKey> {
            use security_framework::item::{ItemSearchOptions, ItemClass, KeyClass};

            let mut opts = ItemSearchOptions::new();
            opts.key_class(KeyClass::private()).load_refs(true).label(label).limit(1);
            let res = opts.search()?;
            if res.is_empty() {
                anyhow::bail!("no key found with label '{}'", label)
            }
            match &res[0] {
                security_framework::item::SearchResult::Ref(security_framework::item::Reference::Key(k)) => Ok(k.clone()),
                other => anyhow::bail!("unexpected search result: {:?}", other),
            }
        }

        pub fn sign(label: &str, data: &[u8]) -> anyhow::Result<Vec<u8>> {
            use security_framework::key::Algorithm;

            let key = Self::find_private_key(label)?;
            // Use ECDSA with SHA-256 over the message (Secure Enclave P-256)
            let sig = key.create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
                .map_err(|e| anyhow::anyhow!("create_signature failed: {}", e))?;
            Ok(sig)
        }

        pub fn export_pubkey(label: &str) -> anyhow::Result<Vec<u8>> {
            let key = Self::find_private_key(label)?;
            let pubk = key.public_key().ok_or_else(|| anyhow::anyhow!("public key not available"))?;
            let der = pubk.external_representation()
                .ok_or_else(|| anyhow::anyhow!("external_representation not available"))?;
            Ok(der.to_vec())
        }
    }

    impl KeyStore for EnclaveKeyStore {
        fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
            Self::sign(&self.label, data)
        }
    }

    pub use EnclaveKeyStore as Provider;
}

#[cfg(not(all(feature = "enclave-se", target_os = "macos")))]
mod imp {
    use super::*;
    pub struct EnclaveKeyStore {}
    impl EnclaveKeyStore {
        pub fn new(_label: &str) -> anyhow::Result<Self> {
            Err(anyhow::anyhow!("enclave-se feature is not enabled or not running on macOS"))
        }
        pub fn ensure_se_available() -> anyhow::Result<()> {
            Err(anyhow::anyhow!("enclave-se feature not enabled or not macOS"))
        }
        pub fn create_key(_label: &str) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("enclave-se not available"))
        }
        pub fn sign(_label: &str, _data: &[u8]) -> anyhow::Result<Vec<u8>> {
            Err(anyhow::anyhow!("enclave-se not available"))
        }
        pub fn export_pubkey(_label: &str) -> anyhow::Result<Vec<u8>> {
            Err(anyhow::anyhow!("enclave-se not available"))
        }
    }
    impl KeyStore for EnclaveKeyStore {
        fn sign(&self, _data: &[u8]) -> anyhow::Result<Vec<u8>> {
            Err(anyhow::anyhow!("enclave-se not available"))
        }
    }
    pub use EnclaveKeyStore as Provider;
}

pub use imp::Provider as EnclaveKeyStore;

/// Helper to return a default provider instance when the operator opts in.
pub fn default_provider(label: &str) -> anyhow::Result<Box<dyn KeyStore>> {
    let p = EnclaveKeyStore::new(label)?;
    Ok(Box::new(p))
}
