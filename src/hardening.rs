use std::fs::OpenOptions;
use std::fs::File;
use std::path::Path;
use std::io;

use zeroize::Zeroize;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de::Error as SerdeError;

/// SecureMemory allocates a heap buffer, locks it into memory (mlock) when possible,
/// and zeroizes on drop.
pub struct SecureMemory {
    buf: Vec<u8>,
}

impl SecureMemory {
    pub fn new(len: usize) -> io::Result<Self> {
        let v = vec![0u8; len];
        // attempt to mlock the pages backing this vector
        let p = v.as_ptr();
        let l = v.len();
        #[cfg(unix)]
        unsafe {
            // ignore errors from mlock; best-effort
            let _ = libc::mlock(p as *const libc::c_void, l);
        }
        Ok(SecureMemory { buf: v })
    }

    pub fn from_vec(v: Vec<u8>) -> io::Result<Self> {
        // Copy into a fresh buffer to ensure we control the backing memory
        let mut buf = Vec::with_capacity(v.len());
        buf.extend_from_slice(&v);
        let p = buf.as_ptr();
        let l = buf.len();
        #[cfg(unix)]
        unsafe {
            let _ = libc::mlock(p as *const libc::c_void, l);
        }
        Ok(SecureMemory { buf })
    }

    pub fn random(len: usize) -> io::Result<Self> {
        let mut v = vec![0u8; len];
        getrandom::getrandom(&mut v).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Self::from_vec(v)
    }

    pub fn as_slice(&self) -> &[u8] { &self.buf }

    pub fn as_mut_slice(&mut self) -> &mut [u8] { &mut self.buf }

    /// Return raw pointer for test/inspection purposes.
    pub fn as_ptr_for_test(&self) -> *const u8 { self.buf.as_ptr() }

    /// Simple wrapper type for secret bytes providing ZeroizeOnDrop semantics.
    pub fn into_secret_bytes(self) -> SecretBytes { SecretBytes(self) }

    pub fn clear(&mut self) {
        self.buf.zeroize();
    }
}

/// Newtype wrapper around `SecureMemory` which makes intent explicit.
pub struct SecretBytes(pub SecureMemory);

impl SecretBytes {
    pub fn as_slice(&self) -> &[u8] { self.0.as_slice() }
    pub fn from_vec(v: Vec<u8>) -> io::Result<Self> {
        Ok(SecretBytes(SecureMemory::from_vec(v)?))
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(len={})", self.as_slice().len())
    }
}

impl Serialize for SecretBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_bytes(self.as_slice())
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer).map_err(D::Error::custom)?;
        SecretBytes::from_vec(bytes).map_err(|e| D::Error::custom(format!("secure memory alloc: {}", e)))
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        let v = self.as_slice().to_vec();
        SecretBytes::from_vec(v).expect("clone SecretBytes: allocation failed")
    }
}

/// Check the current RLIMIT_MEMLOCK value (best-effort) and return (current, recommended_min).
pub fn check_mlock_limit() -> io::Result<(u64, u64)> {
    #[cfg(unix)]
    unsafe {
        let mut rl = std::mem::zeroed::<libc::rlimit>();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) != 0 {
            return Err(io::Error::last_os_error());
        }
        let cur = if rl.rlim_cur == libc::RLIM_INFINITY { u64::MAX } else { rl.rlim_cur as u64 };
        // recommend at least 64KiB per key (heuristic)
        let rec = 64 * 1024u64;
        Ok((cur, rec))
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::new(io::ErrorKind::Other, "mlock limits not available on this platform"))
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        // zeroize then munlock
        self.buf.zeroize();
        #[cfg(unix)]
        unsafe {
            let _ = libc::munlock(self.buf.as_ptr() as *const libc::c_void, self.buf.len());
        }
    }
}

impl AsRef<[u8]> for SecureMemory {
    fn as_ref(&self) -> &[u8] { self.as_slice() }
}

impl AsMut<[u8]> for SecureMemory {
    fn as_mut(&mut self) -> &mut [u8] { self.as_mut_slice() }
}

impl FromIterator<u8> for SecureMemory {
    fn from_iter<I: IntoIterator<Item = u8>>(iter: I) -> Self {
        let v: Vec<u8> = iter.into_iter().collect();
        match SecureMemory::from_vec(v) {
            Ok(sm) => sm,
            Err(_) => {
                // Allocation failed; return an empty SecureMemory instead of panicking.
                // Note: the external RS crate expects FromIterator to succeed; if allocation
                // consistently fails, reconstruction will likely not succeed. Returning an
                // empty buffer avoids unwinding across FFI boundaries.
                SecureMemory::new(0).unwrap_or(SecureMemory { buf: Vec::new() })
            }
        }
    }
}

/// Create a temporary file with secure permissions (0600) where supported.
pub fn create_tmp_file_secure(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        // Best-effort: create and then set permissions if possible.
        let f = OpenOptions::new().write(true).create(true).truncate(true).open(path)?;
        Ok(f)
    }
}
