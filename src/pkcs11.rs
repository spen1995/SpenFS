// Feature-gated PKCS#11 provider scaffold (YubiKey / SoftHSM)
// Builds only when feature `pkcs11` is enabled.

#[cfg(feature = "pkcs11")]
use crate::kms::KeyStore;

#[cfg(feature = "pkcs11")]
pub struct Pkcs11KeyStore { label: String }

#[cfg(feature = "pkcs11")]
impl Pkcs11KeyStore {
    pub fn new(label: &str) -> anyhow::Result<Self> {
        // Minimal scaffold: validate environment presence and return provider.
        if std::env::var("PKCS11_MODULE").is_err() {
            anyhow::bail!("PKCS11_MODULE must be set to the PKCS#11 library path (e.g. /usr/local/lib/softhsm/libsofthsm2.so or /usr/local/lib/libykcs11.dylib)");
        }
        Ok(Pkcs11KeyStore { label: label.to_string() })
    }
}

#[cfg(feature = "pkcs11")]
impl KeyStore for Pkcs11KeyStore {
    fn sign(&self, _data: &[u8]) -> anyhow::Result<Vec<u8>> {
        Err(anyhow::anyhow!("PKCS#11 signing not implemented in scaffold. Provision a key on your token (ykman/ykcs11/pkcs11-tool) and implement signing via `cryptoki` or call external tooling."))
    }
}

#[cfg(feature = "pkcs11")]
pub use Pkcs11KeyStore as Provider;

#[cfg(feature = "pkcs11")]
pub fn try_unlock_with_pkcs11(_wrapped_path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    // Placeholder: full PKCS#11 ECDH/derive implementation depends on token capabilities.
    Err(anyhow::anyhow!("PKCS#11 unlock not implemented in scaffold. Implement token ECDH (C_Derive) using `cryptoki` crate."))
}
