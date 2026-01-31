// Feature-gated TPM monotonic counter helpers.
// When compiled with `--features tpm` this module exposes a small safe wrapper
// around a monotonic counter using the `tss-esapi` crate. When the feature is
// disabled the functions are no-ops or return an appropriate error.

use anyhow::Context;
use std::path::Path;

#[cfg(feature = "tpm")]
mod imp {
    use super::*;
    use tss_esapi::Context as TpmContext;
    use tss_esapi::constants::tss::TPM2_SE_POLICY;
    use tss_esapi::structures::Auth;
    use tss_esapi::structures::Attest;
    use tss_esapi::utils::TpmsContext;
    use tss_esapi::handles::AuthHandle;
    use tss_esapi::interface_types::resource_handles::Hierarchy;
    use tss_esapi::structures::CreationData;
    use tss_esapi::structures::PublicBuilder;
    use tss_esapi::structures::Public;
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::structures::SymmetricDefinitionObject;
    use tss_esapi::structures::SymmetricDefinition;
    use tss_esapi::structures::TPM2B_DIGEST;
    use tss_esapi::abstraction::transient::TransientKeyContext;
    use tss_esapi::handles::NvIndexTpmHandle;
    use tss_esapi::structures::TpmsContext as _TpmsContext;
    use tss_esapi::structures::NvPublicBuilder;
    use tss_esapi::tss2_esys::TPM2B_MAX_NV_BUFFER;

    // This is a minimal prototype: we use NV index as a monotonic counter.
    // Production-grade code needs careful NV index management and auth policies.

    pub fn ensure_tpm_available() -> anyhow::Result<()> {
        // Try opening a TCTI context
        let mut ctx = TpmContext::new(TpmContext::default()).context("open tpm context")?;
        // simple command to ensure TPM responds
        let _ = ctx.get_random(8).context("tpm get_random")?;
        Ok(())
    }

    pub fn read_monotonic(index: u32) -> anyhow::Result<u64> {
        let mut ctx = TpmContext::new(TpmContext::default()).context("open tpm context")?;
        let handle = NvIndexTpmHandle::from(index);
        let nv_pub = ctx.nv_read_public(handle).context("nv_read_public")?;
        let size = nv_pub.nv_public().data_area_size();
        let data = ctx.nv_read(handle, handle.into(), size.into(), 0).context("nv_read")?;
        if data.len() < 8 {
            return Err(anyhow::anyhow!("nv data too small"));
        }
        let mut arr = [0u8;8];
        arr.copy_from_slice(&data.as_bytes()[..8]);
        Ok(u64::from_le_bytes(arr))
    }

    pub fn increment_monotonic(index: u32) -> anyhow::Result<u64> {
        let mut ctx = TpmContext::new(TpmContext::default()).context("open tpm context")?;
        let handle = NvIndexTpmHandle::from(index);
        // read current
        let cur = read_monotonic(index)?;
        let next = cur.checked_add(1).ok_or_else(|| anyhow::anyhow!("counter overflow"))?;
        let b = next.to_le_bytes();
        // write back by NV write; in real TPM use NV increment if supported.
        ctx.nv_write(handle, handle.into(), &TPM2B_MAX_NV_BUFFER { size: b.len() as u16, buffer: { let mut buf = [0u8; 512]; buf[..b.len()].copy_from_slice(&b); buf }}, 0).context("nv_write")?;
        Ok(next)
    }
}

#[cfg(all(not(feature = "tpm"), not(feature = "tpm-mock")))]
mod imp {
    use super::*;
    pub fn ensure_tpm_available() -> anyhow::Result<()> {
        Err(anyhow::anyhow!("tpm feature not enabled"))
    }
    pub fn read_monotonic(_index: u32) -> anyhow::Result<u64> {
        Err(anyhow::anyhow!("tpm feature not enabled"))
    }
    pub fn increment_monotonic(_index: u32) -> anyhow::Result<u64> {
        Err(anyhow::anyhow!("tpm feature not enabled"))
    }
}

#[cfg(feature = "tpm-mock")]
mod imp {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    static STORE: OnceLock<Mutex<HashMap<u32,u64>>> = OnceLock::new();

    fn store_dir() -> PathBuf {
        std::env::var("SPENFS_TPM_MOCK_DIR").map(PathBuf::from).unwrap_or_else(|_| {
            let mut p = std::env::temp_dir();
            p.push("spenfs-tpm-mock");
            p
        })
    }

    fn load_store() -> anyhow::Result<()> {
        let dir = store_dir();
        let file = dir.join("nv.json");
        let mut map = HashMap::new();
        if file.exists() {
            let s = fs::read_to_string(&file)?;
            let parsed: HashMap<String,u64> = serde_json::from_str(&s)?;
            for (k,v) in parsed.into_iter() { if let Ok(idx) = u32::from_str_radix(&k, 16) { map.insert(idx, v); } }
        }
        STORE.get_or_init(|| Mutex::new(map));
        Ok(())
    }

    fn persist_store() -> anyhow::Result<()> {
        let dir = store_dir();
        fs::create_dir_all(&dir)?;
        let file = dir.join("nv.json");
        let lock = STORE.get().ok_or_else(|| anyhow::anyhow!("store not initialized"))?;
        let map = lock.lock().unwrap();
        let mut out: HashMap<String,u64> = HashMap::new();
        for (k,v) in map.iter() { out.insert(format!("{:08X}", k), *v); }
        let s = serde_json::to_string_pretty(&out)?;
        fs::write(file, s)?;
        Ok(())
    }

    pub fn ensure_tpm_available() -> anyhow::Result<()> {
        load_store()?;
        Ok(())
    }

    pub fn read_monotonic(index: u32) -> anyhow::Result<u64> {
        load_store()?;
        let lock = STORE.get().unwrap();
        let map = lock.lock().unwrap();
        Ok(*map.get(&index).unwrap_or(&0u64))
    }

    pub fn increment_monotonic(index: u32) -> anyhow::Result<u64> {
        load_store()?;
        let lock = STORE.get().unwrap();
        let next = {
            let mut map = lock.lock().unwrap();
            let cur = *map.get(&index).unwrap_or(&0u64);
            let next = cur.checked_add(1).ok_or_else(|| anyhow::anyhow!("counter overflow"))?;
            map.insert(index, next);
            next
        };
        persist_store()?;
        Ok(next)
    }

    pub fn provision_nv_index(_index: u32, _size: u16, _auth: Option<&[u8]>) -> anyhow::Result<()> {
        // no-op for mock
        load_store()?;
        Ok(())
    }
}

pub use imp::ensure_tpm_available;
pub use imp::read_monotonic;
pub use imp::increment_monotonic;

/// Provision an NV index for use as a monotonic counter using system tpm2-tools.
/// This is a best-effort operator helper: it shells out to `tpm2_nvdefine`
/// and `tpm2_nvwrite` if available. Returns an error when the tools are missing.
pub fn provision_nv_index(index: u32, size: u16, auth: Option<&[u8]>) -> anyhow::Result<()> {
    #[cfg(feature = "tpm")]
    {
        use tss_esapi::interface_types::resource_handles::Hierarchy;
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::structures::{Auth, NvPublicBuilder, NvPublic, MaxNvBuffer};
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::handles::NvIndexTpmHandle;

        let mut ctx = TpmContext::new(TpmContext::default()).context("open tpm context")?;
        let handle = NvIndexTpmHandle::from(index);

        let authval = if let Some(a) = auth { Auth::try_from(a.to_vec()).unwrap_or(Auth::default()) } else { Auth::default() };

        let attrs = ObjectAttributesBuilder::new()
            .with_auth_read(true)
            .with_auth_write(true)
            .with_no_da(true)
            .build()
            .context("build nv attributes")?;

        let nvpub = NvPublicBuilder::new()
            .with_nv_index(handle.into())
            .with_name_algorithm(HashingAlgorithm::Sha256)
            .with_attributes(attrs)
            .with_data_size(size.into())
            .build()
            .context("build nv public")?;

        // Define space under owner hierarchy
        ctx.nv_define_space(Hierarchy::Owner.into(), Some(&authval), &nvpub)
            .context("nv_define_space")?;
        Ok(())
    }
    #[cfg(not(feature = "tpm"))]
    {
        // Fallback to tpm2-tools if tss-esapi not enabled
        let idx_str = format!("0x{:X}", index);
        let res = std::process::Command::new("tpm2_nvdefine").args(&[idx_str.as_str(), "-s", &size.to_string(), "-a", "0x2000A"]).status();
        match res {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => Err(anyhow::anyhow!("tpm2_nvdefine failed with status: {}", s)),
            Err(e) => Err(anyhow::anyhow!("failed to execute tpm2_nvdefine: {}", e)),
        }
    }
}

pub fn set_nv_policy(index: u32, policy_blob: Option<&[u8]>) -> anyhow::Result<()> {
    #[cfg(feature = "tpm")]
    {
        use tss_esapi::structures::Auth;
        use tss_esapi::handles::NvIndexTpmHandle;

        let mut ctx = TpmContext::new(TpmContext::default()).context("open tpm context")?;
        let handle = NvIndexTpmHandle::from(index);

        // Common operator policies supported:
        // - If `policy_blob` is Some and begins with b"auth:", the remainder is treated
        //   as the auth value (hex) to set as the NV auth using NV_ChangeAuth.
        // - If `policy_blob` is Some and begins with b"pcr:", we compute a policy
        //   digest that corresponds to the PCR selection and set that digest as
        //   the NV auth (convenience: operator should prefer defining authPolicy
        //   at nv define time for stronger guarantees).

        if let Some(blob) = policy_blob {
            if blob.starts_with(b"auth:") {
                let hex = &blob[5..];
                let auth_bytes = hex::decode(hex).context("invalid hex in auth policy")?;
                let auth = Auth::try_from(auth_bytes).context("invalid auth bytes")?;
                // Use NV_ChangeAuth to change the auth value of the NV index (requires owner or index auth)
                ctx.nv_change_auth(handle.into(), &auth).context("nv_change_auth failed")?;
                return Ok(());
            } else if blob.starts_with(b"pcr:") {
                // Parse PCR list e.g. b"pcr:0,1,7" -> build a policyDigest via policy session
                let txt = std::str::from_utf8(&blob[4..]).context("pcr spec not utf8")?;
                let mut pcrs: Vec<u32> = Vec::new();
                for part in txt.split(',') {
                    if part.trim().is_empty() { continue; }
                    pcrs.push(part.trim().parse::<u32>().context("invalid pcr number")?);
                }

                // Start a trial policy session to compute the policy digest
                use tss_esapi::session::Session;
                use tss_esapi::interface_types::session_handles::SessionType;
                use tss_esapi::structures::{PcrSelectionListBuilder, Digest};
                use tss_esapi::utils::TpmsContext;

                let session = ctx.start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Policy,
                    None,
                    None,
                ).context("start policy session")?;

                // Build PCR selection
                let mut pcr_sel_builder = PcrSelectionListBuilder::new();
                for p in &pcrs {
                    pcr_sel_builder = pcr_sel_builder.with_selection(tss_esapi::interface_types::resource_handles::PcrSlot::from(*p), tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256);
                }
                let pcr_sel = pcr_sel_builder.build();

                // Apply policyPCR to the session
                ctx.policy_pcr(session.handle().into(), None, pcr_sel.clone()).context("policy_pcr failed")?;

                // Get resulting digest
                let pd: Digest = ctx.policy_get_digest(session.handle().into()).context("policy_get_digest failed")?;

                // Use the policy digest bytes as the new auth value for NV index via NV_ChangeAuth
                let auth = Auth::try_from(pd.value().to_vec()).context("invalid digest->auth")?;
                ctx.nv_change_auth(handle.into(), &auth).context("nv_change_auth failed")?;
                return Ok(());
            } else {
                return Err(anyhow::anyhow!("unknown policy_blob format; use 'auth:<hex>' or 'pcr:0,1,7'"));
            }
        }
        Err(anyhow::anyhow!("policy_blob required for set_nv_policy"))
    }
    #[cfg(not(feature = "tpm"))]
    {
        Err(anyhow::anyhow!("set_nv_policy not available without tpm feature; use tpm2-tools"))
    }
}
