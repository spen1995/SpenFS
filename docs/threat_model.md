# SpenFS — Threat Model (draft)

Scope
- Components: keystore providers (`src/kms.rs`), `enclave-se` (`src/enclave_se.rs`), `pkcs11` scaffold (`src/pkcs11.rs`), TPM helpers, envelope logic (`src/envelope.rs`), anchors/manifesting.
- Goal: define attacker capabilities, trust assumptions, security goals (secrecy, integrity, anti-rollback), and concrete failure modes and tests.

Assets
- Dataset master key (wrapped on-disk blob).
- Operator signing/anchor keys and monotonic anchors.
- Hardware-protected private keys (SE/TPM/token).
- On-disk manifests, anchors, and metadata.

Adversary classes & capabilities
- Local adversary with physical access: read/modify disk, snapshot/restore, attach USB devices.
- Remote adversary: tamper CI/release, replace binaries, or intercept network provisioning.
- Hardware compromise: stolen token (YubiKey), compromised TPM/SE (firmware/OS-level attacker), or malicious OS with access to KeyStore APIs.
- Rollback attacker: can revert disk to older snapshot but cannot modify hardware counters or make a token produce signatures outside its policy.

Trust assumptions
- Hardware-protected keys (TPM/SE/token) cannot be extracted (by design). Attestation/attributes must be validated before trust.
- Operator controls fallback policies explicitly; silent fallback is not trusted.
- CI and build artifacts are assumed honest unless additional supply-chain controls are added.

Security goals
- Secrecy: master key must remain confidential except to authorized provable unwrapping operations.
- Integrity: manifests and anchors must detect unauthorized modification.
- Anti-rollback: detect/mitigate snapshot restores via monotonic counters/anchors.
- Portability: allow authorized hardware tokens to unwrap without exporting private keys.

Failure modes and mitigations
- Token loss: require recovery policy (e.g., multiple recipients, offline backup), document and test recovery steps.
- Token compromise: allow revocation of recipient entries and require recipient-list signing to prevent silent addition/removal.
- Silent fallback (software key used when hardware fails): forbid by default; require operator opt-in and explicit audit logs.
- Rollback that bypasses monotonic anchors: require monotonic counters stored in TPM/anchor verification tied to manifest sequence numbers.

Tests and mappings to code
- Envelope unwrap tests: `src/envelope.rs` — unit tests for multi-recipient unwrap success/failure and ciphertext tampering.
- PKCS#11 tests: SoftHSM-based integration tests exercising on-token ECDH/unwrap (planned in `tests/` when `pkcs11` implemented).
- Enclave tests: feature-gated provisioning/run tests on macOS for `enclave-se` (already manual; add CI gating policy).
- Anchor/rollback tests: extend `tests/` to simulate snapshot restore and verify anchor monotonic checks.

Immediate decisions required
- No silent fallback: `default_keystore()` must require explicit operator opt-in for fallback.
- Require recipient-list signing: prevent tampering with envelope recipients.
- Define clear attestation verification requirements for SE/enclave/remote-KMS before accepting signatures.

Next steps
- Produce per-layer design docs (`docs/layers/`) deriving concrete APIs and tests.
- Implement CI gating to block merges touching keystore/enclave/pkcs11/envelope until doc + tests exist.
- Add integration tests: SoftHSM for PKCS#11, emulator for TPM monotonic behavior, and adversarial rollback simulations.

— end of draft —
