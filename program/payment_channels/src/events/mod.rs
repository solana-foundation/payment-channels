//! On-chain events emitted via Anchor-compatible self-CPI.
//!
//! Events use Borsh, but only its stack-only subset: primitives and
//! fixed-size arrays of primitives. Heap-backed types (`Vec`, `String`,
//! `Option<T>`, `Box<T>`) panic under Pinocchio's `no_allocator!()`.

pub mod opened;
pub use opened::Opened;
