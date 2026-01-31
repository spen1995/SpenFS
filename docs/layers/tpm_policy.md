TPM Policy & Isolation

Goal
- Isolate TPM policy logic (NV index management, auth, PCR/Policy sessions) behind a clear `tpm::policy` API so other components do not depend on low-level TPM details.

API surface (suggested)
- provision_nv_index(index: u32, size: u16, auth: Option<&[u8]>) -> Result<()>
- read_nv(index: u32) -> Result<Vec<u8>>
- extend_monotonic(index: u32, delta: u64) -> Result<u64>
- get_monotonic(index: u32) -> Result<u64>
- set_nv_policy(index: u32, policy_spec: PolicySpec) -> Result<()>

Security goals
- Enforce minimal privileges for caller; sensitive ops require operator confirmation (CLI flag) or a signed policy blob.
- Use emulator/SoftTPM in CI for deterministic tests.

Tests
- SoftTPM integration: provision NV index, increment counter, persist state across runs, simulate rollbacks.

Mapping to code
- Move TPM-specific policy code out of `src/tpm.rs` callers into `src/tpm/policy.rs` and provide mockable trait for tests.
- Callsites: anchors verification, provisioning CLI, and enforcement in `default_keystore()` if using TPM-bound keys.