Sealed Objects (Enclaves / Secure Enclave / Tokens)

Principles
- Sealed objects (keys) are opaque: no codepath should export raw private key bytes from a HW-backed provider.
- Trust in sealed objects is established via attestation (if available) or explicit operator policy.

Provider contract
- Expose a minimal service interface:
  - sign(data: &[u8]) -> Result<Vec<u8>>
  - public_key() -> Result<Vec<u8>>
  - attest() -> Option<AttestationBlob>
- The host must perform attestation validation (based on policy) before accepting signatures as authoritative.

Attestation
- Where supported (SE/enclave/Nitro), require that the attestation includes:
  - provider id + key label
  - measurement or certificate chain identifying firmware/image
  - nonce-based challenge response to prevent replay

Failure modes
- If attestation cannot be obtained/validated, operator must be prompted to allow or deny using that provider. No silent allow.

Mapping to code
- `src/enclave_se.rs` should implement the provider contract above and export `attest()` where possible.
- `src/kms.rs::default_keystore()` must require explicit opt-in for using non-attested providers or present attestation to the operator.