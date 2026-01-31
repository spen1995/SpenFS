Compatibility shim and integration notes

1. Implementing `TryFromIterator` for `SecureMemory` (SpenFS example)

```rust
impl TryFromIterator<u8> for SecureMemory {
    type Error = std::io::Error;
    fn try_from_iter<I: IntoIterator<Item = u8>>(iter: I) -> Result<Self, Self::Error> {
        let v: Vec<u8> = iter.into_iter().collect();
        SecureMemory::from_vec(v).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("secure alloc: {}", e)))
    }
}
```

2. Calling the new API:

```rust
let mut shards: Vec<Option<SecureMemory>> = ... // some present/None pattern
reconstructor.reconstruct_try(&mut shards)?; // returns Result
```

3. Backwards compatibility

Existing `reconstruct(&mut [Option<T>])` remains but will be reimplemented as a thin wrapper around `reconstruct_try` that maps `TryFromIterator::Error` into a panic to preserve current behavior.

4. CI and iteration

- Apply the patch locally to the upstream repo and run `cargo test`.
- Fix any compilation mismatches (module names, type alias differences) and iterate.
- Once tests pass locally, open a PR against upstream and let their CI run; fix any platform-specific issues reported by CI.
