Title: Add fallible reconstruction support (TryFromIterator) to reed-solomon-erasure

Summary

This patch proposes adding a fallible construction trait (TryFromIterator) and a fallible reconstruction entrypoint to the `reed-solomon-erasure` crate so callers can propagate allocation or other construction errors instead of panicking.

Motivation

The current `reconstruct` API relies on `FromIterator` for reconstructed shards. `FromIterator::from_iter` cannot return errors, so callers must implement a `FromIterator` that panics on allocation failure or otherwise hide allocation failures. This is unsafe for applications that allocate mlocked secure memory or need to return clear errors upstream instead of unwinding/panicking across library boundaries.

Proposal

1. Add a new trait `TryFromIterator<Item>` that mirrors `FromIterator` but returns `Result<Self, E>`.
2. Add a new method on `ReedSolomon` such as `reconstruct_try<T, E>(&self, slices: &mut [Option<T>]) -> Result<(), Error>` where `T: TryFromIterator<F::Elem, Error = E>` (concrete trait bounds to be refined) so reconstruction can fail gracefully if constructing missing shards is impossible.
3. Keep existing `reconstruct` backward-compatible by implementing it on top of `reconstruct_try` using a `TryFromIterator` impl that panics on error (for backwards compatibility).

High-level patch sketch (to be adapted for upstream code layout)

- Add new trait in `src/lib.rs` or core module:

```rust
pub trait TryFromIterator<T>: Sized {
    type Error;
    fn try_from_iter<I: IntoIterator<Item = T>>(iter: I) -> Result<Self, Self::Error>;
}
```

- Add default impl for `Option<Vec<F::Elem>>` or leave to callers.

- Add new method in core implementation (example name `reconstruct_try`) that mirrors existing `reconstruct` but uses `TryFromIterator` when materializing shards.

- Provide tests that simulate allocation failure by implementing a test type whose `try_from_iter` returns Err() on demand and verify `reconstruct_try` returns the error instead of panicking.

Compatibility shim

To preserve API stability, `reconstruct` can be implemented in terms of `reconstruct_try` by using a thin wrapper type that panics on `Error` (existing behaviour). This keeps existing callers working while enabling new code paths that can propagate errors.

Benefits

- Enables secure-memory users to provide fallible constructors (e.g. allocate `SecureMemory`) that can return an error on insufficient RLIMIT_MEMLOCK or other allocation failures.
- Prevents panics/unwinding across crate boundaries and allows applications to handle low-memory or allocation failures gracefully.

Suggested next steps

- I can prepare a complete PR against the `reed-solomon-erasure` repo with the full code changes, tests, and changelog entry. If you want, I can also open a fork and submit the PR; otherwise, I can provide a patch file you can review and push.

Applying the patch locally (example)

```bash
git clone https://github.com/<your-fork>/reed-solomon-erasure.git
cd reed-solomon-erasure
git checkout -b tryfromiter-reconstruct
# apply patch file from this repo: patches/reed-solomon-tryfromiterator.diff
git apply ../SpenFS/patches/reed-solomon-tryfromiterator.diff
cargo test
# iterate until CI green, then push and open a PR
```

Contact/Notes

- If you'd like, I can open the fork & PR for you if you grant the target repo or tell me the GitHub handle to use. I can also prepare a minimal compatibility patch in this repo showing how `SecureMemory` would implement `TryFromIterator` and how to call the new `reconstruct_try` API.
