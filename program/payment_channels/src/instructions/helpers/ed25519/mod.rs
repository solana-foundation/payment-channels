//! Ed25519 precompile bindings — wire-layout constants plus the
//! canonical single-signature inline-ix parser.

mod consts;
pub(super) mod parse;

pub use consts::*;
