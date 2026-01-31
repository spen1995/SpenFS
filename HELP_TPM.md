TPM Monotonic Counter Integration (prototype)

Overview

- Purpose: provide a hardware-backed monotonic counter to strengthen anchor sequencing and make local rollbacks harder to perform undetected when combined with other protections.
- Scope: prototype wrapper using the TPM NV index as a counter; feature-gated behind `--features tpm`.

Design notes

- We use an NV index to store an 8-byte little-endian counter. Production systems should prefer TPM monotonic counter objects where available and manage NV index allocation and auth policy carefully.
- The module exposes:
  - `ensure_tpm_available()` — basic availability check
  - `read_monotonic(index: u32) -> Result<u64>` — read counter at NV index
  - `increment_monotonic(index: u32) -> Result<u64>` — increment and return new value

Security considerations

- NV indices require careful auth and policy management; leaving indices writable by an attacker is unsafe.
- TPM-based counters raise the bar but do not replace remote anchoring (publish anchors to an external log) for full rollback protection.
- Provisioning: operators must allocate and protect a specific NV index for SpenFS and ensure secrets/policies are stored out-of-band.

How to build

- Add the `tpm` feature when building to enable the TPM module:

```bash
cargo build --features tpm
```

- The code uses `tss-esapi` which requires system TPM libraries and development headers on the host.

Next steps for production

- Implement robust NV index provisioning and policy enforcement.
- Prefer TPM monotonic counters (TPM2) or secure enclave monotonic storage where available.
- Integrate TPM checks into `promote_manifest` flow: increment TPM counter and include TPM-backed counter value in anchor; verify on open that TPM value matches/monotonic.
- Combine TPM counters with remote anchor publishing for maximum assurance.
