Key Hierarchy & Envelopes

Design goals
- Separate dataset master key lifecycle from provider Keystore semantics.
- Envelope schema must be explicit, signed (recipient-list signing), and support revocation.

Components
- Root operator key (Ed25519): signs anchors and recipient-list changes.
- Dataset master key: small symmetric key encrypted under one or more recipient entries.
- Recipient entry: { id, alg, ephemeral_pk, ciphertext }

Envelope rules
- The envelope JSON must include `recipients`, `version`, and a `recipients_sig` field which is an Ed25519 signature over the canonical recipients array and version.
- Recipient-list changes MUST be signed by the operator key; untrusted recipients array is rejected.

Revocation
- Revocation is performed by creating a new envelope with recipients removed and the new recipients array signed by the operator key; old envelopes remain valid until operator advances anchors.

Mapping to code
- `src/envelope.rs`: add recipient-list signing/verification helpers and require signature verification in `try_unlock_*` flows.
- `src/crypto.rs`: add helpers to sign/verify recipient arrays with operator key stored in `KeyStore` or local operator key (subject to policy).

Tests
- Tamper recipient array and ensure unwrap fails.
- Rotate recipient list and ensure only signed updates are accepted.