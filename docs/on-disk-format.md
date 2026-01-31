# SpenFS On-disk Format (draft)

This document outlines the initial on-disk layout for SpenFS: header, manifests, journal, chunk store, and basic atomic commit rules.

Overview
- Superblock/header: `header.bin` (already implemented) contains dataset salt, dataset-id, version, created_at.
- Manifests: `manifest.bin` — authenticated, versioned metadata that contains the filesystem namespace root, snapshot pointers, Merkle root(s), and KDF salt reference.
- Journal: `journal.log` — append-only, small authenticated records describing metadata transactions; used for atomic commit and crash recovery.
- Chunk store: directory `chunks/` storing content-addressed chunks by hash (sharded layout e.g. first 2 hex chars as directory).
- Snapshots: stored as immutable manifests referenced by snapshot id; manifests are content-addressed and signed.

High-level rules
- All metadata files (manifests, journal entries) are considered sensitive and must be authenticated and optionally encrypted.
- Salt and non-secret parameters are stored in `header.bin` and authenticated by the header's integrity protection.
- Atomic commit: write new manifest to a temporary file, append a journal commit record referencing the manifest, then atomically update a `current` pointer (e.g., `current -> manifest-<id>.bin`) using atomic `rename`.
- Crash recovery: on mount, replay `journal.log` from the last manifest checkpoint to reach a consistent state; incomplete transactions are discarded.

Manifest format (logical)
- manifest:
  - magic (4 bytes)
  - version (u32)
  - dataset_id (32 bytes)
  - seq (u64) // monotonic manifest sequence
  - root_merkle (32 bytes) // root hash for top-level namespace tree
  - timestamp (u64)
  - metadata_blob (bytes) // serialized namespace tree; should be encrypted with AEAD
  - signature (variable) // Ed25519 signature over all previous fields

Journal entries (logical)
- Each entry is append-only, serialized and optionally signed:
  - seq (u64)
  - op (enum: Create, Unlink, Rename, CommitManifest, StartTxn, EndTxn)
  - payload (op-specific)
  - timestamp
  - signature (optional)

Chunk store
- Chunks stored under `chunks/xx/yy...` where `xx` = first byte hex, `yy` = second byte hex, to avoid large single directories.
- Each chunk file named by full hex digest, contents are AEAD ciphertext including AAD with chunk coordinates and version.

Recovery & repair
- Background repair verifies chunk AEAD integrity and Merkle hashes, repairs missing shards from erasure-coded redundancy or replication peers (future).

Versioning and upgrades
- All on-disk structures include a `version` and `dataset_id`; code must support forward-safe parsing and fail-closed on unsupported critical versions.

Next steps
- Define exact byte layout for serialized manifest and journal records.
- Implement manifest journal writer/reader and atomic commit helpers in Rust.
- Add AEAD envelope type for encrypted metadata.
