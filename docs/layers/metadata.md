Filesystem Metadata & Separation of Concerns

Guiding rule
- Filesystem metadata and manifest formats are consumer-facing data models and must be separated from cryptographic primitives and anchor logic.

Invariants
- Metadata layout (manifests, journal, anchors) must be versioned and documented separately from crypto algorithms.
- Migration rules must be explicit and tested (backwards-compatibility checks).

Responsibilities
- `src/on_disk.rs` and `src/manifest.rs` implement metadata parsing/validation.
- Crypto checks (AEAD decrypt, signature verification) are performed by `crypto` helpers and called from the promotion/verification layer — do not mix parsing + crypto in one function.

Tests
- Schema evolution tests for manifest versions.
- Quarantine path exercised when signatures fail; reason files must be human-readable and include the failing check.

Mapping to code
- Extract any ad-hoc parsing/crypto mixing into two-step verify flows: parse -> verify signatures & AEAD -> accept or quarantine. Add tests in `tests/` accordingly.