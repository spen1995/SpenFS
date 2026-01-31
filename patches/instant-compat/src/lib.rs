//! Local compatibility shim for the `instant` crate (version 0.1.13)
//!
//! This re-exports `std::time::Instant` and `std::time::Duration` so downstream
//! crates that depend on the unmaintained `instant` crate can build using the
//! standard library implementation.

pub use std::time::{Duration, Instant};
