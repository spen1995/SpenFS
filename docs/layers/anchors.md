Anchors & Rollback Detection

Purpose
- Define the on-disk anchor format, verification API, and how monotonic hardware anchors (TPM NV / counters) tie into anti-rollback checks.

Format
- Anchor blob: 1-byte version || payload.
  - Version 0x01: sequence-only anchor (seq number, metadata)
  - Version 0x02: sequence + monotonic token anchor (seq, token_id, monotonic_value)
- Anchors MUST be canonical-serialized (e.g., CBOR or RMP) and signed by the operator key.

Verification API
- verify_anchor(anchor_blob, expected_seq, optional_token_state) -> Result<AnchorClaims>
  - Verifies signature, checks sequence monotonicity, and when present validates monotonic_value against the token (TPM NV or other HW counter).
- anchor_claims contains: seq, token_id (optional), monotonic_value (optional), signing_pubkey

Hardware binding
- TPM-backed anchors: store monotonic value in TPM NV index; include NV index identifier in anchor payload.
- On verification, query the TPM to ensure NV value >= monotonic_value in anchor and that the NV index has the expected auth policy.

Failure semantics
- On signature failure: treat as integrity failure and refuse mount/promotion.
- On monotonic check failure (anchor monotonic_value > token value): treat as possible rollback; refuse to accept unless operator-approved recovery procedure applied.

Tests
- Simulate snapshot restore by lowering the local anchor and ensure verification rejects (unit/integration tests).
- SoftTPM emulator tests to exercise NV monotonic operations and anchor verification.

Mapping to code
- `src/on_disk.rs`, `src/manifest.rs` — implement the `verify_anchor` helper and anchor parsing per the format above.
- Add tests in `tests/anchor_rollback.rs` that exercise both sequence-only and TPM-anchor cases.