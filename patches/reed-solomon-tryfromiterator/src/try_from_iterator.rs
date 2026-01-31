//! TryFromIterator trait: a fallible counterpart to `FromIterator`.
//!
//! This file is intended to be added to the `reed-solomon-erasure` crate
//! to provide an API for fallible reconstruction.

pub trait TryFromIterator<T>: Sized {
    type Error;
    fn try_from_iter<I: IntoIterator<Item = T>>(iter: I) -> Result<Self, Self::Error>;
}
