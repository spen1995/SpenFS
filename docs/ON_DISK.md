SpenFS — On-disk Format & Metadata Specification

Purpose
- Define precise, implementable on-disk formats and atomic commit rules for SpenFS.
- Provide a canonical reference for implementations, testing, and recovery/repair logic.

Goals and invariants
- Atomic visibility: metadata changes (manifests) must become visible atomically.
- Durability: committed metadata must survive crashes after fsync semantics.
- Idempotent recovery: WAL replays are idempotent and can be re-run safely.
- Verifiable promotion: manifests are promoted only after cryptographic checks (Ed25519 signature + AEAD metadata decrypt) or quarantined with reason.
- Compatible archiving: successful journal applications are archived (unless uncommitted txns exist).

Top-level layout (dataset root)
- header.bin               — fixed-size serialized `Header` used to bootstrap dataset
- keys/                    — local private key storage for prototype (`signing.key`, mode 0600)
 - keys/                    — local private key storage for prototype (`signing.key.enc`, encrypted, mode 0600)
- journal/journal.log      — append-only, length-prefixed bincode `JournalEntry` stream
- journal/applied-<ts>.log — rotated/archived journals after apply
- manifests/               — manifest tmp/final files and `latest` pointer
  - manifest-<seq>.bin
  - manifest-<seq>.bin.tmp
  - quarantine/            — failed tmp manifests and `.reason` files
  - latest                 — textual pointer to last manifest file name
- chunks/                  — chunk blobs and shard files
- uploads/                 — persistent upload state (JSON)
- logs/                    — repair logs, rotated/compressed, crc and quarantine

Header (on-disk: `header.bin`)
- Fixed-size serialized struct (recommend exact 256 bytes pad for forward compatibility)
- Fields (example):
  - magic: 8 bytes (e.g., "SPENFS\0\0")
  - version: u8
  - flags: u8
  - kdf_id: u8
  - reserved: u8
  - kdf_params: u32
  - created_ts: u64
  - salt: Vec<u8> (512 bytes) — per-dataset 512-byte salt for KDF
  - fingerprint: [u8; 32]
  - dataset_id: [u8; 32]    — dataset identifier
  - signing_pubkey: [u8; 32]

Notes:
- `signing_pubkey` is empty (all zeros) until `spenfs init` populates it.
- The header must be written atomically (tmp -> fsync -> rename -> parent fsync).

Journal (WAL) format
- Storage: `journal/journal.log` is append-only.
- Each entry is length-prefixed with a 4-byte little-endian length, followed by bincode(serialized JournalEntry).
- `JournalEntry` shape:
  - seq: u64 (reserved; can be 0 for now)
  - op: JournalOp enum (StartTxn{txid}, EndTxn{txid}, AbortTxn{txid}, CommitManifest{seq}, Create{path}, Unlink{path}, Rename{old,new})
  - timestamp: u64 (UTC seconds)
  - signature: Vec<u8> (optional; future ledger signing)

Transaction semantics
- Transactions are optionally explicit using `StartTxn(txid)` and `EndTxn(txid)` around multiple ops.
- If a `StartTxn` is present, ops between Start and End are considered a transaction identified by `txid`.
- `AbortTxn(txid)` marks a transaction as aborted; on replay aborted and incomplete txns are skipped.
- `CommitManifest(seq)` is the journal op indicating a manifest tmp exists and should be promoted when the transaction is complete.

Apply/recovery rules (`apply_journal_entries`)
1. Read the journal fully and parse entries in order (preserve order inside transactions).
2. Group entries into transactions by `txid` where StartTxn..EndTxn exist. Entries outside StartTxn..EndTxn are treated as single-entry implicit transactions.
3. Apply all non-transaction (outside) entries first; they are idempotent or safe to re-run.
4. For transactions: only apply those where `EndTxn` exists and `AbortTxn` does NOT exist.
5. If any transactions are incomplete (missing `EndTxn`) or aborted, do NOT archive the journal — leave it in place so future EndTxn/AbortTxn append will allow completion.
6. If all transactions were applied (none left uncommitted), archive the journal file by renaming to `applied-<ts>.log`.

Manifest write & promotion flow
- Writer flow (atomic commit):
  1. Serialize manifest, AEAD-encrypt `metadata_blob` using dataset-derived AEAD key (dataset_id as AAD).
  2. Sign the manifest (Ed25519) and embed signature.
  3. Write temp manifest to `manifests/manifest-<seq>.bin.tmp` and fsync.
  4. Append `CommitManifest{seq}` to the `journal/journal.log` (fsync journal).
  5. Caller appends EndTxn(txid) (if using transactions) and calls `apply_journal_entries()`.
  6. Promotion: `apply_journal_entries()` will call `promote_manifest_if_tmp_exists` which will:
     - Check `header.signing_pubkey` and verify Ed25519 signature; if invalid -> move tmp to `manifests/quarantine/` and write `<tmp>.reason`.
     - Attempt AEAD decrypt with dataset-derived key; if decrypt fails -> quarantine similarly.
     - If checks pass -> rename tmp -> final, fsync final, update `latest` pointer atomically, fsync manifests dir.

Quarantine semantics
- Any tmp manifest that fails verification or decryption is moved to `manifests/quarantine/<tmpname>.bad` with a reason file `*.reason` containing the failure cause.
- Quarantine is retained until manual inspection or periodic prune via `spenfs quarantine-prune`.

Idempotency and ordering guarantees
- Manifest promotion is idempotent: if final already exists, promotion step is a no-op.
- Create/Unlink/Rename ops are written against dataset paths and are designed to be safe on repeated replay.

Compatibility and forward-compat
- Reserve extra bytes in header for future fields; pad header to fixed size to allow additions.
- Journal entry `signature` field allows later addition of ledger signing without format break.

Testing & verification checklist
- Unit tests for header read/write roundtrip and padding.
- Integration tests for:
  - Journal replay in presence of incomplete transactions (behavior: leave journal; do not promote)
  - Successful transaction (StartTxn -> CommitManifest -> EndTxn) promotes manifest
  - Quarantine behaviors for invalid signatures and AEAD failures
  - Journal archival when all txns complete

Implementation plan (next actions)
1. Finalize this document and commit to `docs/ON_DISK.md` (done).
2. Implement/adjust `src/on_disk.rs` to match the spec exactly (add/verify padding, header size, explicit fsync points, `latest` pointer handling) — create unit tests.
3. Strengthen `promote_manifest_if_tmp_exists` to produce structured reason messages and verify all fsync/rename ordering.
4. Add more integration tests under `tests/` to simulate crashes (journal partials) and recovery.
5. Optional: create small tool `tools/inspect_journal.rs` to pretty-print `journal.log` for debugging.

Notes on atomic rename and fsync ordering
- Write tmp -> fsync(tmp)
- Rename tmp -> final
- fsync(final)
- Update `latest` via `latest.tmp` -> fsync -> rename `latest.tmp` -> `latest` -> fsync parent dir
- Rationale: ensures `latest` always points to a fully fsynced file and avoids torn writes across crashes.

Next steps for me
- I will start implementing the follow-up code updates in `src/on_disk.rs` (unit tests + tighten promotion/archival) unless you prefer adjustments to the spec first.

Generated: January 30, 2026
