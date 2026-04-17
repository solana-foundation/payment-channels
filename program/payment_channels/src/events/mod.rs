//! On-chain events emitted via Anchor-compatible self-CPI.
//!
//! Event structs in this module must serialize only primitives and
//! fixed-size arrays of primitives; heap-backed Borsh types
//! (`Vec`, `String`, `Option<T>`) would cross Pinocchio's
//! `no_allocator!()` boundary and panic at runtime.

pub mod opened;
pub use opened::Opened;
