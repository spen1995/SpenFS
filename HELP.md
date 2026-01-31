SpenFS — Project Help

**Overview**
- **Purpose**: SpenFS is a Rust reference prototype for a secure, content-addressed storage system with KDF/AEAD encryption, Ed25519-signed manifests, content-defined chunking, Reed–Solomon redundancy, and a journaled WAL for atomic metadata commits and recovery.
- **Scope**: Not production-ready; intended as a security-minded research prototype and operational playground.

**What This Repo Implements**
- **On-disk header**: dataset `header.bin` (fixed-size, includes salt, dataset id, fingerprint, and `signing_pubkey`).
- **Journal / WAL**: `journal/journal.log` — length-prefixed bincode `JournalEntry` list with ops: `StartTxn`, `EndTxn`, `AbortTxn`, `CommitManifest`, `Create`, `Unlink`, `Rename`.
- **Atomic manifest commit**: write manifest tmp -> fsync -> append `CommitManifest` to journal -> caller triggers WAL apply -> manifest promotion (with signature + AEAD checks) -> fsync parent -> journal archived.
- **Manifest security**: manifests are serialized, AEAD-encrypted (XChaCha20-Poly1305), and signed (Ed25519). Promotion verifies signature and tries AEAD decrypt; failing tmp manifests are quarantined.
- **KeyStore & HSM/KMS providers**: a `KeyStore` abstraction was added to allow non-exportable signing/decryption keys. Current providers/scaffolds include TPM (native via `tss-esapi` when built with the `tpm` feature), a macOS Secure Enclave provider (`enclave-se` feature), and a PKCS#11 scaffold for on-token keys. A file-backed `tpm-mock` provider exists for local testing and CI.
- **Multi-recipient envelopes & recipient signing**: manifests support a multi-recipient envelope format and signed recipient lists to allow encrypting manifests to multiple recipients while protecting against recipient-swap attacks.
- **Anchor verification & anti-rollback**: anchors include optional monotonic/TPM NV commitments and `verify_anchor()` enforces monotonic promotion checks to detect rollback or anchor tampering.
- **Chunking & redundancy**: Gear CDC chunker, chunk encryption with AEAD, and RS redundancy helpers (encode/repair shards).
- **Repair daemon**: background scanner/repair process with structured JSONL repair logs, log rotation, gzip compression, CRC verification, quarantine/restore, and periodic prune.
- **Upload/resume**: upload state persisted under `uploads/` with `upload-start` and `upload-resume` CLI helpers.

**Repository Layout (key paths)**
 **Keys**: private signing key produced by `spenfs init` at `keys/signing.key.enc` (encrypted, mode 0600)
- **Logs**: `logs/repair.log`, rotated files `repair.log.*`, compressed `repair.log.*.gz`, CRC files alongside compressed blobs, and `logs/quarantine/`

**Important Files in Source**
- **Header & WAL apply**: `src/on_disk.rs` — header struct, journal reader, `apply_journal_entries`, `promote_manifest_if_tmp_exists` and quarantine
- **Manifest helpers & journal ops**: `src/manifest.rs` — Manifest struct, `write_encrypted_signed_manifest`, journal append helpers
- **Upload flow**: `src/upload.rs` — `start_upload`, `resume_upload`, and `commit_snapshot_transaction` (transactional wrapper)
- **Repair daemon**: `src/repair_daemon.rs` — startup replay of journal and background repair loop
- **Crypto**: `src/crypto.rs` — KDF (Argon2id), AEAD, Ed25519 helpers
- **Compressor**: `src/compressor.rs` — log rotation, gzip compression, CRC verification, quarantine + prune

**CLI Commands and Examples**
- **Initialize a dataset** — creates header, generates dataset signing key (private saved at `keys/signing.key`):

```bash
spenfs init /path/to/dataset
```

- **Store a file's chunks (one-shot put)** — chunk & store; writes file-level filemanifest (not the snapshot manifest):

```bash
spenfs put /path/to/dataset /path/to/file
```

- **Start a resumable upload** — creates upload state file under `uploads/`:

```bash
spenfs upload-start /path/to/dataset /path/to/file
# prints upload id
```

- **Resume a resumable upload** — continues chunking from stored offset and persists chunk IDs:

```bash
export SPENFS_PW=your-passphrase
spenfs upload-resume /path/to/dataset <upload-id>
```

- **Create a snapshot manifest (atomic)** — creates the snapshot manifest (transactionally):

```bash
export SPENFS_PW=your-passphrase
spenfs snapshot /path/to/dataset
```

- **KMS helper (dev scaffold)** — wrap existing encrypted signing key with local KMS master:

```bash
spenfs kms-wrap /path/to/dataset
```

- **Chunk shard encoding / repair helpers**:

```bash
spenfs encode-chunk /path/to/dataset <chunk-id> <k> <m>
spenfs repair-chunk /path/to/dataset <chunk-id> <k> <m>
```

- **Repair utilities**:

```bash
spenfs repair-scan /path/to/dataset <k> <m>
spenfs repair-daemon /path/to/dataset <k> <m> <interval-secs>
```

- **Quarantine & log maintenance**:

```bash
spenfs quarantine-list /path/to/dataset
spenfs quarantine-restore /path/to/dataset <name>
```bash
# Provide passphrase via `SPENFS_PW_FILE` or configure the OS keyring
# Example (passphrase file):
printf "your-passphrase\n" > /tmp/spenfs_pass.txt && export SPENFS_PW_FILE=/tmp/spenfs_pass.txt

**WAL / Transaction Semantics**
- **Markers**: Use `StartTxn(txid)`, write artifacts (tmp manifests/shards), append `CommitManifest(seq)`, and finish with `EndTxn(txid)`. On failure append `AbortTxn(txid)`.
- **Recovery handling**: `apply_journal_entries` groups journal entries by transaction id. It will only apply transactions that contain `EndTxn` and are not aborted. If uncommitted transactions are present, the journal is left in-place so subsequent `EndTxn`/`AbortTxn` entries can complete recovery.
- **Idempotency**: Apply logic is designed to be idempotent for Create/Unlink/Rename and manifest promotion.

```bash
# Provide passphrase via `SPENFS_PW_FILE` or keyring. Example using passphrase file:
printf "your-passphrase\n" > /tmp/spenfs_pass.txt && export SPENFS_PW_FILE=/tmp/spenfs_pass.txt
- **Signature verification**: `promote_manifest_if_tmp_exists` uses the `signing_pubkey` from the header to verify the Ed25519 signature embedded in the manifest. If absent or invalid, the tmp manifest is moved to `manifests/quarantine/` and a `.reason` file is written.
- **AEAD decrypt check**: promotion tries to AEAD-decrypt the manifest's metadata_blob using a key derived from `SPENFS_PW` + dataset salt. If decrypt fails, the tmp file is quarantined.
- **Quarantine**: Quarantined tmp manifest files are moved to `manifests/quarantine/<tmpname>.bad` with `*.reason` explaining the failure.

**Environment Variables & Config**
- **SPENFS_PW**: passphrase used by prototype to derive the AEAD key for manifest decrypt checks. Replace with secure key retrieval in production.
- **SPENFS_RS_K / SPENFS_RS_M**: Reed–Solomon parameters for encode/repair (defaults in code if unset).
- **Repair & compressor settings**: `SPENFS_REPAIR_LOG_MAX_BYTES`, `SPENFS_COMPRESS_WORKERS`, `SPENFS_COMPRESS_QUEUE`, `SPENFS_QUARANTINE_PRUNE_INTERVAL_SECS`, `SPENFS_QUARANTINE_PRUNE_DAYS`, `SPENFS_QUARANTINE_PRUNE_DRY_RUN` (see `src/compressor.rs` for defaults).

**Testing & Development**
- Run test suite:

```bash
cargo test
```

- Integration tests added:
  - `tests/integration_log_maintenance.rs` — exercises log rotation/compression/quarantine/prune flow.
  - `tests/upload_txn_recovery.rs` — simulates interrupted manifest commit and validates WAL replay behavior.

**Operational Notes & Next Steps**
- **Security**: The prototype currently stores the dataset Ed25519 private key under `keys/signing.key`. For production, integrate with an HSM/KMS and avoid storing plaintext private key on disk.
- **Security**: The prototype currently stores the dataset Ed25519 private key under `keys/signing.key`. For production, integrate with an HSM/KMS and avoid storing plaintext private key on disk.

**Tmp-file hardening & memory hygiene**
- The codebase now uses a secure tmp-file helper to create temporary files with restrictive permissions (mode 0600 on Unix) before atomically renaming them into place. This reduces the window where sensitive artifacts could be exposed with permissive default umasks.
- Sensitive in-memory buffers (PRNG seed, signing key plaintext, AEAD nonces where applicable) are protected using a `SecureMemory` helper which attempts to `mlock` the pages and zeroizes memory on drop. This is a best-effort measure; `mlock` failures are handled gracefully and logged.
- There are tests under `tests/` that verify secure tmp-file permissions and allocate/tear down `SecureMemory`. On Linux a best-effort test attempts to read `/proc/self/mem` to assert that zeroization occurred after `Drop` (this test may require elevated privileges or adjusted procfs permissions).
- SpenFS now performs a startup check via `check_mlock_limit()` to surface insufficient `RLIMIT_MEMLOCK` settings. If the current limit is below the repository's recommended minimum (heuristic: 64 KiB), SpenFS will log a warning. To make startup fail instead of warning, set the environment variable `SPENFS_FAIL_ON_MLOCK=1`. To raise the limit on Unix systems, adjust `ulimit -l` or set `LimitMEMLOCK` in systemd service files; for CI, ensure the runner provides an adequate memlock limit or run tests with a passphrase-file fallback.
- **Key handling**: Replace `SPENFS_PW`-based AEAD key derivation with secure secret retrieval and rotation support.
- **Uploads**: The next planned work is to integrate the transactional StartTxn/EndTxn/AbortTxn markers into normal upload/put flows (so multi-shard writes and manifest creation are atomic). A helper `commit_snapshot_transaction` already exists; extend other flows similarly.
- **Testing**: Add concurrent-writer tests and fuzzing for parsers and deserialization paths.

**Where to Look in Code**
- `src/on_disk.rs` — header format, journal reader and apply, promotion/quarantine logic
- `src/manifest.rs` — manifest creation, serialization, AEAD, signature helper, and journal helpers
- `src/compressor.rs` — log rotation, compression, CRC, quarantine, prune

**Keeping HELP.md Up-to-Date**
- I will update this file after each substantive change (new CLI commands, on-disk changes, security changes, or operational tooling changes).
- To request an update, ask: “Update HELP.md with <feature/change>”.

**Diagrams & Quick Reference**

WAL / Manifest promotion (ASCII diagram):

 START: client writes tmp manifest -> fsync tmp
     |
     v
  append CommitManifest(tx.seq) to `journal/journal.log` (length-prefixed bincode)
     |
     v
  caller appends EndTxn(txid) and optionally fsyncs journal
     |
     v
  `apply_journal_entries()` reads journal, groups transactions, verifies EndTxn and no AbortTxn, then promotes tmp -> final (signature + AEAD checks)
     |
     v
  archive journal to `journal/applied-<ts>.log` (unless uncommitted txns remain)

Promotion decision flow:
- If header has `signing_pubkey`: verify Ed25519 signature on manifest
- If signature fails: move tmp to `manifests/quarantine/<tmp>.bad` and write `<tmp>.bad.reason`
- If signature ok and `SPENFS_PW` key derives to aead key: attempt AEAD decrypt of `metadata_blob`
- If decrypt fails: quarantine tmp similarly
- On success: rename tmp -> final and fsync

**Troubleshooting Examples**

- "Manifest not promoting": check `journal/journal.log` for `CommitManifest` and `EndTxn` entries; check `manifests/quarantine/*.reason` for failure reasons.
- "Repair daemon not repairing": ensure `SPENFS_PW` is set (for prototype) and `repair-daemon` has read access to `keys/signing.key` if needed; check `logs/repair.log` and rotated archives.
- "Quarantined gz mismatch": `logs/quarantine/` contains `.gz` and `.crc`; restore with `spenfs quarantine-restore`.

**Automated HELP.md updates (suggested)**

- Add a small script `scripts/generate_help.rs` or a CI step that runs when `src/` changes to produce a digest of public CLI commands and modules. For now, manual updates are recorded in the repo via this file.
- Example GitHub Actions workflow snippet (suggested):

```yaml
name: Update HELP
on:
  push:
    paths:
      - 'src/**'
jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run help generator
        run: cargo run --package spenfs --bin tools-generate-help || true
      - name: Commit HELP.md
        run: |
          git config user.name ci-bot
          git config user.email ci@example.com
          git add HELP.md || true
          git commit -m "chore: regenerate HELP.md" || true
          git push || true
```

This repo currently updates `HELP.md` manually; I can scaffold a generator if you want.

---
Generated: January 30, 2026

Feedback welcome: tell me which sections you want expanded or formatted differently.

**CI / Runner Notes**

- A sample GitHub Actions workflow was added at `.github/workflows/ci.yml` which runs tests using a temporary passphrase file and includes an optional `memlock-check` job.
- To avoid interactive/passphrase-keyring issues in CI, set `SPENFS_PW_FILE` to a path containing the dataset passphrase (the CI workflow writes `spenfs_pass.txt` and exports it as `SPENFS_PW_FILE`).
- The workflow also demonstrates how to fail-fast on insufficient memlock limits by setting `SPENFS_FAIL_ON_MLOCK=1` in the `memlock-check` job. If your runners cannot increase `RLIMIT_MEMLOCK`, prefer using `SPENFS_PW_FILE` for CI tests to avoid reliance on `mlock`.
- For systemd-deployed services, set `LimitMEMLOCK` or adjust the service unit to grant the required locked memory. For ephemeral CI runners, ensure the runner image or job runner supports the memlock requirements or run the memlock-check job conditionally.
