# SpenFS (prototype)

Minimal prototype for SpenFS. This project demonstrates dataset initialization with a 512-byte salt and Argon2id key derivation parameters and provides a security-focused playground for HSM/KMS integrations and on-disk anchor protection.

Highlights
- KeyStore abstraction and provider scaffolds for hardware-backed keys: TPM (native), macOS Secure Enclave, and a PKCS#11 scaffold for on-token keys.
- Multi-recipient envelope format and signed recipient lists for encrypting manifests to multiple recipients.
- Anchor verification with monotonic checks (TPM NV/monotonic counters) to protect against rollback/anchor tampering.
- In-repo `tpm-mock` plus SoftTPM integration for CI and local testing without a system TPM.

Quick run:

```bash
cargo run -- init ./data
```

Testing with the TPM mock
- Unit and integration tests can be run with the `tpm-mock` feature enabled locally: `cargo test --features tpm-mock`.

CI notes
- The TPM integration workflow is configured to target a self-hosted privileged runner (label: `self-hosted, linux, x64, privileged`) because swtpm/tpm2-tools and certain procfs-based zeroization checks require elevated runner capabilities. If you don't have a matching self-hosted runner, adjust `.github/workflows/tpm-integration.yml` or run the tests locally with `--features tpm-mock`.

For more detailed help and CLI usage, see `HELP.md`.
