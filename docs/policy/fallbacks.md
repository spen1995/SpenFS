Fallback Policy

SpenFS default policy:

- Silent fallback from a hardware-backed KeyStore (TPM, Secure Enclave, PKCS#11 token, or remote KMS) to the local filesystem-based KeyStore is disallowed by default.
- Operators wishing to allow the local filesystem fallback must explicitly opt in by setting the environment variable `SPENFS_ALLOW_FALLBACK=1`.

Rationale
- Prevents accidental loss of hardware-backed guarantees (non-exportability, attestation, monotonic anchors) when software fallback would weaken security.
- Forces an explicit operator decision with audit traces or deployment notes.

Operator guidance
- Production deployments: configure a hardware provider (set `SPENFS_USE_ENCLAVE`, `SPENFS_USE_PKCS11`, or `AWS_KMS_KEY_ID`) and avoid setting `SPENFS_ALLOW_FALLBACK`.
- Development or single-host deployments: set `SPENFS_ALLOW_FALLBACK=1` to allow the filesystem keystore for convenience.

Implementation
- `src/kms.rs::default_keystore()` will panic if no provider is selected or available and `SPENFS_ALLOW_FALLBACK` is not set to `1`.
