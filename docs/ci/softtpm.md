# SoftTPM (swtpm) integration for CI

Purpose
- Run a SoftTPM instance in CI (or locally) and execute feature-gated tests that exercise TPM NV monotonic anchors.

## Ubuntu (local or CI runner)

- Install system deps (must run as root or via sudo):

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config swtpm swtpm-tools tpm2-tools libtss2-dev
```

- Start `swtpm` in the background (uses port 2321 for TPM socket):

```bash
mkdir -p /tmp/swtpm-state
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm-state --ctrl type=tcp,port=2322 --server type=tcp,port=2321 &>/tmp/swtpm.log &
sleep 1
```

- Export TCTI env vars and pick a safe NV index for the test:

```bash
export TPM2TOOLS_TCTI="socket:host=127.0.0.1,port=2321"
export TSS2_TCTI="mssim:port=2321"
export SPENFS_TPM_NV_INDEX=0x01500000
```

- Run the TPM feature tests (feature-gated tests):

```bash
cargo test --features tpm --test tpm_soft_integration -- --nocapture
```

- Cleanup (stop swtpm and remove state):

```bash
pkill swtpm || true
rm -rf /tmp/swtpm-state
```

## Docker (cross-platform / macOS-friendly)

- Run an Ubuntu container that installs deps, starts `swtpm`, and runs tests. Mounts your repo into `/work` and runs tests inside the container:

```bash
docker run --rm -it \
  -v "$PWD":/work -w /work \
  ubuntu:22.04 /bin/bash -lc "
    apt-get update && apt-get install -y build-essential pkg-config ca-certificates curl \
      swtpm swtpm-tools tpm2-tools libtss2-dev git && \
    curl https://sh.rustup.rs -sSf | sh -s -- -y && source \$HOME/.cargo/env && \
    mkdir -p /work/swtpm-state && \
    swtpm socket --tpm2 --tpmstate dir=/work/swtpm-state --ctrl type=tcp,port=2322 --server type=tcp,port=2321 &>/work/swtpm.log & \
    sleep 1 && \
    export TPM2TOOLS_TCTI='socket:host=127.0.0.1,port=2321' && \
    export TSS2_TCTI='mssim:port=2321' && \
    export SPENFS_TPM_NV_INDEX=0x01500000 && \
    cargo test --features tpm --test tpm_soft_integration -- --nocapture
  "
```

## Notes & troubleshooting

- The `tss-esapi`/`tss-esapi-sys` crates require system `libtss2` dev files (installed via `libtss2-dev` on Ubuntu). `pkg-config` must be able to find `tss2-sys.pc`.
- If an NV define fails because the index already exists from a prior run, either pick a different `SPENFS_TPM_NV_INDEX` per run or remove the `swtpm` state dir between runs.
- In CI: install the same packages, start `swtpm` before running tests, set `TSS2_TCTI`/`TPM2TOOLS_TCTI`, and use `SPENFS_TPM_NV_INDEX` per job to avoid collisions.

## Next steps

- I can add a GitHub Actions workflow that installs the packages, starts `swtpm`, and runs the feature-gated tests, or add a mockable TPM trait so unit tests do not need system libs. Which would you prefer?
SoftTPM (swtpm) integration for CI

Purpose
- Show how to run a SoftTPM instance in CI (or locally) and execute feature-gated tests that exercise TPM NV monotonic anchors.

High-level steps
1. Install `swtpm` and `tpm2-tools` on the runner (Ubuntu example):

```bash
sudo apt-get update
sudo apt-get install -y swtpm swtpm-tools tpm2-tools
```

2. Start a swtpm socket and point `TSS2_TCTI` / `TPM2TOOLS_TCTI` to it.
- Example (run in background):

```bash
mkdir -p /tmp/swtpm-state
swtpm socket --tpm2 --ctrl type=tcp,port=2321 --server type=tcp,port=2322 --tpmstate dir=/tmp/swtpm-state &
export TPM2TOOLS_TCTI="socket:host=127.0.0.1,port=2321"
export TSS2_TCTI="mssim:port=2321" # depending on tss stack in use
```

Note: exact TCTI strings depend on libraries used by `tss-esapi`. CI runners may require slight variation; test will skip gracefully if a usable TPM is not available.

3. Run tests with the `tpm` feature enabled:

```bash
cargo test --features tpm --tests
```

GitHub Actions snippet (example)

```yaml
- name: Install swtpm
  run: sudo apt-get update && sudo apt-get install -y swtpm swtpm-tools tpm2-tools

- name: Start swtpm
  run: |
    mkdir -p $GITHUB_WORKSPACE/swtpm-state
    swtpm socket --tpm2 --ctrl type=tcp,port=2321 --server type=tcp,port=2322 --tpmstate dir=$GITHUB_WORKSPACE/swtpm-state &
    sleep 1
  env:
    CI: true

- name: Run tests with TPM feature
  run: |
    export TPM2TOOLS_TCTI="socket:host=127.0.0.1,port=2321"
    cargo test --features tpm --tests
```

Guidance
- Tests are designed to be resilient: if `ensure_tpm_available()` fails, the test will skip with a printed message rather than failing the entire job. For CI, prefer enabling the `tpm` feature and ensuring swtpm is running to exercise coverage.
- Use `SPENFS_TPM_NV_INDEX` env var to pick a non-conflicting NV index in parallel CI jobs.

Troubleshooting
- If `tss-esapi` reports TCTI errors, verify the TCTI string expected by your `tss-esapi` version and set `TSS2_TCTI` / `TPM2TOOLS_TCTI` accordingly.
- If NV define fails due to existing index, either use a different index or run cleanup steps between jobs (remove state dir for swtpm).